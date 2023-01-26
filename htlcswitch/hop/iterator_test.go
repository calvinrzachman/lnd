package hop

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/davecgh/go-spew/spew"
	sphinx "github.com/lightningnetwork/lightning-onion"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/record"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
)

var (
	//nolint:lll
	testPrivKeyBytes, _     = hex.DecodeString("e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734")
	testPrivKey, testPubKey = btcec.PrivKeyFromBytes(testPrivKeyBytes)
	testNextHop             = lnwire.NewShortChanIDFromInt(1)
)

// TestSphinxHopIteratorForwardingInstructions tests that we're able to
// properly decode an onion payload, no matter the payload type, into the
// original set of forwarding instructions.
func TestSphinxHopIteratorForwardingInstructions(t *testing.T) {
	t.Parallel()

	// First, we'll make the hop data that the sender would create to send
	// an HTLC through our imaginary route.
	hopData := sphinx.HopData{
		ForwardAmount: 100000,
		OutgoingCltv:  4343,
	}
	copy(hopData.NextAddress[:], bytes.Repeat([]byte("a"), 8))

	// Next, we'll make the hop forwarding information that we should
	// extract each type, no matter the payload type.
	nextAddrInt := binary.BigEndian.Uint64(hopData.NextAddress[:])
	expectedFwdInfo := ForwardingInfo{
		NextHop:         lnwire.NewShortChanIDFromInt(nextAddrInt),
		AmountToForward: lnwire.MilliSatoshi(hopData.ForwardAmount),
		OutgoingCTLV:    hopData.OutgoingCltv,
	}

	// For our TLV payload, we'll serialize the hop into into a TLV stream
	// as we would normally in the routing network.
	var b bytes.Buffer
	tlvRecords := []tlv.Record{
		record.NewAmtToFwdRecord(&hopData.ForwardAmount),
		record.NewLockTimeRecord(&hopData.OutgoingCltv),
		record.NewNextHopIDRecord(&nextAddrInt),
	}
	tlvStream, err := tlv.NewStream(tlvRecords...)
	require.NoError(t, err, "unable to create stream")
	if err := tlvStream.Encode(&b); err != nil {
		t.Fatalf("unable to encode stream: %v", err)
	}

	var testCases = []struct {
		sphinxPacket    *sphinx.ProcessedPacket
		expectedFwdInfo ForwardingInfo
	}{
		// A regular legacy payload that signals more hops.
		{
			sphinxPacket: &sphinx.ProcessedPacket{
				Payload: sphinx.HopPayload{
					Type: sphinx.PayloadLegacy,
				},
				Action:                 sphinx.MoreHops,
				ForwardingInstructions: &hopData,
			},
			expectedFwdInfo: expectedFwdInfo,
		},
		// A TLV payload, we can leave off the action as we'll always
		// read the cid encoded.
		{
			sphinxPacket: &sphinx.ProcessedPacket{
				Payload: sphinx.HopPayload{
					Type:    sphinx.PayloadTLV,
					Payload: b.Bytes(),
				},
			},
			expectedFwdInfo: expectedFwdInfo,
		},
	}

	// Finally, we'll test that we get the same set of
	// ForwardingInstructions for each payload type.
	iterator := sphinxHopIterator{}
	for i, testCase := range testCases {
		iterator.processedPacket = testCase.sphinxPacket

		pld, err := iterator.HopPayload()
		if err != nil {
			t.Fatalf("#%v: unable to extract forwarding "+
				"instructions: %v", i, err)
		}

		fwdInfo := pld.ForwardingInfo()
		if fwdInfo != testCase.expectedFwdInfo {
			t.Fatalf("#%v: wrong fwding info: expected %v, got %v",
				i, spew.Sdump(testCase.expectedFwdInfo),
				spew.Sdump(fwdInfo))
		}
	}
}

// TestForwardingAmountCalc tests calculation of forwarding amounts from the
// hop's forwarding parameters.
func TestForwardingAmountCalc(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		incomingAmount lnwire.MilliSatoshi
		baseFee        uint32
		proportional   uint32
		forwardAmount  lnwire.MilliSatoshi
		expectErr      bool
	}{
		{
			name:           "overflow",
			incomingAmount: 10,
			baseFee:        100,
			expectErr:      true,
		},
		{
			name:           "ok",
			incomingAmount: 100_000,
			baseFee:        1000,
			proportional:   10,
			forwardAmount:  99000,
		},
	}

	for _, testCase := range tests {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			actual, err := calculateForwardingAmount(
				testCase.incomingAmount, testCase.baseFee,
				testCase.proportional,
			)

			require.Equal(t, testCase.expectErr, err != nil)
			require.Equal(t, testCase.forwardAmount, actual)
		})
	}
}

// A simplified implementation of the BlindingProcessor interface.
type mockBlindHopProcessor struct{}

// For the sake of testing, we assume that the payload is already decrypted.
// From the perspective of the link, we expect this function implementation
// (sphinx, test, or otherwise) to deliver us a proper serialized route blinding
// payload, which we can then parse into a BlindHopPayload{}.
func (b *mockBlindHopProcessor) DecryptBlindedData(
	blindingPoint *btcec.PublicKey, payload []byte) ([]byte, error) {

	return payload, nil
}

// For simplicity's sake we just pass back the same blinding point.
func (b *mockBlindHopProcessor) NextEphemeral(
	blindingPoint *btcec.PublicKey) (*btcec.PublicKey, error) {

	return blindingPoint, nil
}

type crossPayloadValidationTest struct {
	name                   string
	onionPayload           *Payload
	routeBlindingPayload   *record.BlindedRouteData
	updateAddBlindingPoint *btcec.PublicKey
	incomingAmt            lnwire.MilliSatoshi
	incomingCltv           uint32
	isFinalHop             bool
	expectedErr            error
}

var defaultRouteBlindingPayload = &record.BlindedRouteData{
	ShortChannelID: &testNextHop,
	RelayInfo: &record.PaymentRelayInfo{
		BaseFee:         0,
		FeeRate:         10,
		CltvExpiryDelta: 10,
	},
}

var crossPayloadValidationTests = []crossPayloadValidationTest{
	{
		name: "introduction node blinded route",
		onionPayload: &Payload{
			blindingPoint: testPubKey, // intro nodes have blinding point in onion
		},
		routeBlindingPayload: &record.BlindedRouteData{
			ShortChannelID: &testNextHop,
			RelayInfo: &record.PaymentRelayInfo{
				BaseFee:         0,
				FeeRate:         10,
				CltvExpiryDelta: 10,
			},
			Constraints: &record.PaymentConstraints{},
		},
	},
	{
		name:                   "intermediate hop blinded route with next hop",
		onionPayload:           &Payload{},
		routeBlindingPayload:   defaultRouteBlindingPayload,
		updateAddBlindingPoint: testPubKey,
	},
	{
		name:         "blind hop blinded route with next_node_id",
		onionPayload: &Payload{},
		routeBlindingPayload: &record.BlindedRouteData{
			NextNodeID: testPubKey, // it's okay to specify the next node by ID rather than scid
			RelayInfo: &record.PaymentRelayInfo{
				BaseFee:         0,
				FeeRate:         10,
				CltvExpiryDelta: 10,
			},
		},
		updateAddBlindingPoint: testPubKey,
	},
	{
		name: "final hop blinded route",
		onionPayload: &Payload{
			FwdInfo: ForwardingInfo{
				NextHop:         Exit,
				AmountToForward: 100,
				OutgoingCTLV:    10,
			},
		},
		routeBlindingPayload: &record.BlindedRouteData{
			PathID: bytes.Repeat([]byte{1}, 32),
		},
		updateAddBlindingPoint: testPubKey,
		isFinalHop:             true,
	},
	{
		name: "blind hop with blinding point in both msg and tlv payload",
		onionPayload: &Payload{
			blindingPoint: testPubKey,
		},
		routeBlindingPayload:   defaultRouteBlindingPayload,
		updateAddBlindingPoint: testPubKey,
		expectedErr: ErrInvalidPayload{
			Type:      record.BlindingPointOnionType,
			Violation: OverloadedViolation,
		},
	},
	{
		name:                 "blind hop missing blinding point in msg and tlv payload",
		onionPayload:         &Payload{},
		routeBlindingPayload: &record.BlindedRouteData{},
		expectedErr: ErrInvalidPayload{
			Type:      record.BlindingPointOnionType,
			Violation: OmittedViolation,
		},
	},
	{
		name: "blind hop blinded route missing both next_hop " + // error case
			"and next_node_id",
		onionPayload: &Payload{},
		routeBlindingPayload: &record.BlindedRouteData{
			// - no next_hop
			// - no next_node_id
			RelayInfo: &record.PaymentRelayInfo{
				BaseFee:         0,
				FeeRate:         10,
				CltvExpiryDelta: 10,
			},
		},
		updateAddBlindingPoint: testPubKey,
		expectedErr: ErrInvalidPayload{
			Type:      record.ShortChannelIDType,
			Violation: OmittedViolation,
			BlindHop:  true,
		},
	},
	{
		name:         "blind hop missing payment_relay",
		onionPayload: &Payload{},
		routeBlindingPayload: &record.BlindedRouteData{
			ShortChannelID: &testNextHop,
			// - no payment_relay
		},
		updateAddBlindingPoint: testPubKey,
		expectedErr: ErrInvalidPayload{
			Type:      record.PaymentRelayType,
			Violation: OmittedViolation,
			BlindHop:  true,
		},
	},
	{
		name:         "blind hop payment_relay which fails to meet constraints",
		onionPayload: &Payload{},
		routeBlindingPayload: &record.BlindedRouteData{
			ShortChannelID: &testNextHop,
			RelayInfo: &record.PaymentRelayInfo{
				BaseFee:         0,
				FeeRate:         10,
				CltvExpiryDelta: 10,
			},
			Constraints: &record.PaymentConstraints{
				HtlcMinimumMsat: lnwire.MaxMilliSatoshi,
				// AllowedFeatures: []byte,
			},
		},
		// UpdateAddHTLC fields:
		updateAddBlindingPoint: testPubKey,
		incomingAmt:            lnwire.MaxMilliSatoshi - 1,
		expectedErr: ErrInvalidPayload{
			Type:      record.AmtOnionType,
			Violation: InsufficientViolation,
			BlindHop:  true,
		},
	},
	{
		name:         "blind hop payment_relay fails to meet constraints - expired",
		onionPayload: &Payload{},
		routeBlindingPayload: &record.BlindedRouteData{
			ShortChannelID: &testNextHop,
			RelayInfo: &record.PaymentRelayInfo{
				BaseFee:         0,
				FeeRate:         10,
				CltvExpiryDelta: 10,
			},
			Constraints: &record.PaymentConstraints{
				MaxCltvExpiry: 1,
			},
		},
		updateAddBlindingPoint: testPubKey,
		incomingCltv:           2,
		expectedErr: ErrInvalidPayload{
			Type:      record.LockTimeOnionType,
			Violation: InsufficientViolation,
			BlindHop:  true,
		},
	},
	{
		name: "blind hop with amt_to_forward improperly set in " +
			"top level TLV payload",
		onionPayload: &Payload{
			FwdInfo: ForwardingInfo{
				AmountToForward: lnwire.MilliSatoshi(100),
			},
			// RouteBlindingEncryptedData: []byte{},
		},
		routeBlindingPayload:   defaultRouteBlindingPayload,
		updateAddBlindingPoint: testPubKey,
		expectedErr: ErrInvalidPayload{
			Type:      record.AmtOnionType,
			Violation: IncludedViolation,
			// BlindHop:  true, // we expect this error to come from incorrectly included onion payload field
		},
	},
	{
		name: "blind hop with timelock improperly set in top level TLV payload",
		onionPayload: &Payload{
			FwdInfo: ForwardingInfo{
				OutgoingCTLV: 1000,
			},
		},
		routeBlindingPayload:   defaultRouteBlindingPayload,
		updateAddBlindingPoint: testPubKey,
		expectedErr: ErrInvalidPayload{
			Type:      record.LockTimeOnionType,
			Violation: IncludedViolation,
		},
	},
	{
		name: "blind hop with short_channel_id improperly set in top level TLV payload",
		onionPayload: &Payload{
			FwdInfo: ForwardingInfo{
				NextHop: lnwire.NewShortChanIDFromInt(1),
			},
		},
		routeBlindingPayload:   defaultRouteBlindingPayload,
		updateAddBlindingPoint: testPubKey,
		expectedErr: ErrInvalidPayload{
			Type:      record.NextHopOnionType,
			Violation: IncludedViolation,
		},
	},
	{
		name: "blind hop with MPP improperly set in top level TLV payload",
		onionPayload: &Payload{
			MPP: &record.MPP{},
		},
		routeBlindingPayload:   defaultRouteBlindingPayload,
		updateAddBlindingPoint: testPubKey,
		expectedErr: ErrInvalidPayload{
			Type:      record.MPPOnionType,
			Violation: IncludedViolation,
		},
	},
	// { NOTE(1/26/23): Redundant as AMP will not be put in TLV without MPP (PackHopPayload)
	// 	name: "blind hop with AMP improperly set in top level TLV payload",
	// 	onionPayload: &Payload{
	// 		MPP: &record.MPP{},
	// 		AMP: &record.AMP{},
	// 	},
	// 	routeBlindingPayload: &record.BlindedRouteData{
	// 		ShortChannelID: &testNextHop,
	// 		RelayInfo: &record.PaymentRelayInfo{
	// 			BaseFee:         0,
	// 			FeeRate:         10,
	// 			CltvExpiryDelta: 10,
	// 		},
	// 	},
	// 	updateAddBlindingPoint: testPubKey,
	// 	expectedErr: ErrInvalidPayload{
	// 		Type:      record.AMPOnionType,
	// 		Violation: IncludedViolation,
	// 	},
	// { TODO: Add TotalAmountMsat?
	// 	name: "blind hop with total_amount_msat improperly set in top level TLV payload",
	// 	onionPayload: &Payload{
	// 		TotalAmountMsat: lnwire.MilliSatoshi(100),
	// 	},
	// 	routeBlindingPayload: &record.BlindedRouteData{
	// 		ShortChannelID: &testNextHop,
	// 		RelayInfo: &record.PaymentRelayInfo{
	// 			BaseFee:         0,
	// 			FeeRate:         10,
	// 			CltvExpiryDelta: 10,
	// 		},
	// 	},
	// 	updateAddBlindingPoint: testPubKey,
	// 	expectedErr: ErrInvalidPayload{
	// 		Type:      record.TotalAmountMsatOnionType,
	// 		Violation: IncludedViolation,
	// 	},
	// },
	{
		name: "final hop blinded route missing amt in top level TLV payload",
		onionPayload: &Payload{
			FwdInfo: ForwardingInfo{
				AmountToForward: lnwire.MilliSatoshi(0), // 0 value is not written in TLV stream
			},
		},
		routeBlindingPayload: &record.BlindedRouteData{
			PathID: bytes.Repeat([]byte{1}, 32),
		},
		updateAddBlindingPoint: testPubKey,
		isFinalHop:             true,
		expectedErr: ErrInvalidPayload{
			Type:      record.AmtOnionType,
			Violation: OmittedViolation,
			FinalHop:  true,
		},
	},
	{
		name: "final hop blinded route missing outgoing_cltv_value " +
			"in top level TLV payload",
		onionPayload: &Payload{
			FwdInfo: ForwardingInfo{
				NextHop:         Exit,
				AmountToForward: 100,
				OutgoingCTLV:    0, // 0 value is not written in TLV stream
			},
		},
		routeBlindingPayload: &record.BlindedRouteData{
			PathID: bytes.Repeat([]byte{1}, 32),
		},
		updateAddBlindingPoint: testPubKey,
		isFinalHop:             true,
		expectedErr: ErrInvalidPayload{
			Type:      record.LockTimeOnionType,
			Violation: OmittedViolation,
			FinalHop:  true,
		},
	},
	{
		name: "final hop blinded route missing path_id ",
		onionPayload: &Payload{
			FwdInfo: ForwardingInfo{
				NextHop:         Exit,
				AmountToForward: 100,
				OutgoingCTLV:    10,
			},
		},
		routeBlindingPayload: &record.BlindedRouteData{
			// - no path_id
		},
		updateAddBlindingPoint: testPubKey,
		isFinalHop:             true,
		expectedErr: ErrInvalidPayload{
			Type:      record.PathIDType,
			Violation: OmittedViolation,
			FinalHop:  true,
			BlindHop:  true,
		},
	},
	{
		name: "final blind hop with MPP set in top level TLV payload", // Are we supposed to allow this?
		onionPayload: &Payload{
			MPP: &record.MPP{},
		},
		routeBlindingPayload: &record.BlindedRouteData{
			PathID: bytes.Repeat([]byte{1}, 32),
		},
		updateAddBlindingPoint: testPubKey,
		isFinalHop:             true,
	},
	{
		name: "intro node is last node",
		onionPayload: &Payload{
			FwdInfo: ForwardingInfo{
				NextHop:         Exit,
				AmountToForward: 100,
				OutgoingCTLV:    10,
			},
			blindingPoint: testPubKey, // intro nodes have blinding point in onion
		},
		routeBlindingPayload: &record.BlindedRouteData{
			PathID: bytes.Repeat([]byte{1}, 32),
		},
		isFinalHop: true,
	},
}

// TestEnforceBolt04Validation verifies that the hop iterator correctly
// enforces BOLT-04 validation when processing blind hops. We assert that
// parsing the onion and route blinding TLV payloads yields the expected
// errors depending on whether the proper fields were included or omitted.
//
// TestEnforceBolt04Validation validates that the top level onion TLV
// payload, route blinding TLV payload, and relevant contents from the
// UpdateAddHTLC message conform to the BOLT-04 specification.
func TestEnforceBolt04Validation(t *testing.T) {
	for _, test := range crossPayloadValidationTests {
		t.Run(test.name, func(t *testing.T) {
			testEnforceBolt04Validation(t, test)
		})
	}
}

func testEnforceBolt04Validation(t *testing.T,
	test crossPayloadValidationTest) {

	t.Parallel()

	routeBlindingTLV, err := record.EncodeBlindedRouteData(test.routeBlindingPayload)
	require.Nil(t, err, "unable to encode route blinding payload")
	recipientEncryptedData := routeBlindingTLV
	test.onionPayload.encryptedData = recipientEncryptedData

	// NOTE(1/26/23): Any blinding point in the onion (ex: introduction nodes)
	// will be included here.
	var b bytes.Buffer
	PackHopPayload(&b, *test.onionPayload) // right now this is only used to help with this test.

	// Construct a processed onion packet as if we have just gotten back
	// a freshly decrypted onion packet from the underlying Sphinx implementation.
	sphinxPacket := &sphinx.ProcessedPacket{
		Payload: sphinx.HopPayload{
			Type:    sphinx.PayloadTLV,
			Payload: b.Bytes(),
		},
	}

	// NOTE(1/17/23): Do we want to create a real sphinx.Router for testing?
	// Probably not, as this calls the underlying sphinx implementation (lightning-onion).
	// In the tests I created on my first draft branch, I mocked out the DecryptBlindedData
	// and NextEphemeral functions. For the sake of testing, I just assumed decrypted route
	// blinding payloads so I could build unencrypted TLV payloads for test cases, and lazily
	// echoed the same blinding point back to be used for the next hop instead of actually
	// re-blinding it for the next.
	blindHopProcessor := &mockBlindHopProcessor{}

	// Absent an easy way to anchor our testing at the level
	// of DecodeHopIterators() (due to it's use of external
	// sphinx library that we don't want to mock atm), we instead
	// construct a "hop iterator" fand test that it properly handles
	// blind hops under a variety of scenarios.
	//
	// NOTE(1/26/23): Recall, that a hop iterator is built with
	// the raw/uninterpreted bytes of the decrypted onion packet.
	// The blinding point here, if it exists, would be coming from
	// UpdateAddHTLC. The blinding point in the onion, if it exits,
	// will be pulled out of the hop payload below.
	blindingKit := MakeBlindingKit(blindHopProcessor,
		test.updateAddBlindingPoint,
		test.isFinalHop, test.incomingAmt, test.incomingCltv,
	)
	iterator := makeSphinxHopIterator(nil, sphinxPacket, blindingKit)

	// Parse the onion and route blinding TLV payloads.
	// NOTE: This test assumes that both payloads have
	// already been decrypted.
	//
	// NOTE(1/26/23): We want to make sure that this function correctly
	// returns forwarding information for both blind and normal hops.
	payload, err := iterator.HopPayload()

	if test.expectedErr != nil {
		require.ErrorIs(t, err, test.expectedErr)
		require.Nil(t, payload)
	} else {
		require.ErrorIs(t, err, nil)
		fwdInfo := payload.ForwardingInfo()
		t.Logf("Forwarding Info: %+v", fwdInfo)
		// TODO: do we need to assert anything about the forwarding information?
	}
}
