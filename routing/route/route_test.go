package route

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/record"
)

var (
	testPrivKey1Bytes, _ = hex.DecodeString("e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734")
	_, testPubKey1       = btcec.PrivKeyFromBytes(testPrivKey1Bytes)
	testPubKey1Bytes, _  = NewVertexFromBytes(testPubKey1.SerializeCompressed())

	testPubKey2Hex      = "02e1ce77dfdda9fd1cf5e9d796faf57d1cedef9803aec84a6d7f8487d32781341e"
	testPubKey2Bytes, _ = hex.DecodeString(testPubKey2Hex)

	testPubKey3Hex      = "039ddfc912035417b24aefe8da155267d71c3cf9e35405fc390df8357c5da7a5eb"
	testPubKey3Bytes, _ = hex.DecodeString(testPubKey3Hex)
)

// TestRouteTotalFees checks that a route reports the expected total fee.
func TestRouteTotalFees(t *testing.T) {
	t.Parallel()

	// Make sure empty route returns a 0 fee, and zero amount.
	r := &Route{}
	if r.TotalFees() != 0 {
		t.Fatalf("expected 0 fees, got %v", r.TotalFees())
	}
	if r.ReceiverAmt() != 0 {
		t.Fatalf("expected 0 amt, got %v", r.ReceiverAmt())
	}

	// Make sure empty route won't be allowed in the constructor.
	amt := lnwire.MilliSatoshi(1000)
	_, err := NewRouteFromHops(amt, 100, Vertex{}, []*Hop{})
	if err != ErrNoRouteHopsProvided {
		t.Fatalf("expected ErrNoRouteHopsProvided, got %v", err)
	}

	// For one-hop routes the fee should be 0, since the last node will
	// receive the full amount.
	hops := []*Hop{
		{
			PubKeyBytes:      Vertex{},
			ChannelID:        1,
			OutgoingTimeLock: 44,
			AmtToForward:     amt,
		},
	}
	r, err = NewRouteFromHops(amt, 100, Vertex{}, hops)
	if err != nil {
		t.Fatal(err)
	}

	if r.TotalFees() != 0 {
		t.Fatalf("expected 0 fees, got %v", r.TotalFees())
	}

	if r.ReceiverAmt() != amt {
		t.Fatalf("expected %v amt, got %v", amt, r.ReceiverAmt())
	}

	// Append the route with a node, making the first one take a fee.
	fee := lnwire.MilliSatoshi(100)
	hops = append(hops, &Hop{
		PubKeyBytes:      Vertex{},
		ChannelID:        2,
		OutgoingTimeLock: 33,
		AmtToForward:     amt - fee,
	},
	)

	r, err = NewRouteFromHops(amt, 100, Vertex{}, hops)
	if err != nil {
		t.Fatal(err)
	}

	if r.TotalFees() != fee {
		t.Fatalf("expected %v fees, got %v", fee, r.TotalFees())
	}

	if r.ReceiverAmt() != amt-fee {
		t.Fatalf("expected %v amt, got %v", amt-fee, r.ReceiverAmt())
	}
}

var (
	testAmt  = lnwire.MilliSatoshi(1000)
	testAddr = [32]byte{0x01, 0x02}
)

// TestMPPHop asserts that a Hop will encode a non-nil MPP to final nodes, and
// fail when trying to send to intermediaries.
func TestMPPHop(t *testing.T) {
	t.Parallel()

	hop := Hop{
		ChannelID:        1,
		OutgoingTimeLock: 44,
		AmtToForward:     testAmt,
		LegacyPayload:    false,
		MPP:              record.NewMPP(testAmt, testAddr),
	}

	// Encoding an MPP record to an intermediate hop should result in a
	// failure.
	var b bytes.Buffer
	err := hop.PackHopPayload(&b, 2)
	if err != ErrIntermediateMPPHop {
		t.Fatalf("expected err: %v, got: %v",
			ErrIntermediateMPPHop, err)
	}

	// Encoding an MPP record to a final hop should be successful.
	b.Reset()
	err = hop.PackHopPayload(&b, 0)
	if err != nil {
		t.Fatalf("expected err: %v, got: %v", nil, err)
	}
}

// TestAMPHop asserts that a Hop will encode a non-nil AMP to final nodes of an
// MPP record is also present, and fail otherwise.
func TestAMPHop(t *testing.T) {
	t.Parallel()

	hop := Hop{
		ChannelID:        1,
		OutgoingTimeLock: 44,
		AmtToForward:     testAmt,
		LegacyPayload:    false,
		AMP:              record.NewAMP([32]byte{}, [32]byte{}, 3),
	}

	// Encoding an AMP record to an intermediate hop w/o an MPP record
	// should result in a failure.
	var b bytes.Buffer
	err := hop.PackHopPayload(&b, 2)
	if err != ErrAMPMissingMPP {
		t.Fatalf("expected err: %v, got: %v",
			ErrAMPMissingMPP, err)
	}

	// Encoding an AMP record to a final hop w/o an MPP record should result
	// in a failure.
	b.Reset()
	err = hop.PackHopPayload(&b, 0)
	if err != ErrAMPMissingMPP {
		t.Fatalf("expected err: %v, got: %v",
			ErrAMPMissingMPP, err)
	}

	// Encoding an AMP record to a final hop w/ an MPP record should be
	// successful.
	hop.MPP = record.NewMPP(testAmt, testAddr)
	b.Reset()
	err = hop.PackHopPayload(&b, 0)
	if err != nil {
		t.Fatalf("expected err: %v, got: %v", nil, err)
	}
}

func TestBlindedHop(t *testing.T) {
	t.Parallel()

	hop := Hop{
		ChannelID:                  1,
		OutgoingTimeLock:           44,
		AmtToForward:               testAmt,
		LegacyPayload:              false,
		RouteBlindingEncryptedData: []byte("recipient encrypted data"),
		BlindingPoint:              testPubKey1,
	}

	t.Logf("Hop Information: %+v\n", hop)

	// Encoding a blinded hop should be successful for any node in route.
	var b bytes.Buffer
	err := hop.PackHopPayload(&b, 2)
	if err != nil {
		t.Fatalf("expected err: %v, got: %v", nil, err)
	}

	b.Reset()
	err = hop.PackHopPayload(&b, 0)
	if err != nil {
		t.Fatalf("expected err: %v, got: %v", nil, err)
	}
}

func TestExtendRoute(t *testing.T) {

	as := bytes.Repeat([]byte("a"), 33)
	bs := bytes.Repeat([]byte("b"), 33)
	cs := bytes.Repeat([]byte("c"), 33)
	vertexA, _ := NewVertexFromBytes(as)
	vertexB, _ := NewVertexFromBytes(bs)
	vertexC, _ := NewVertexFromBytes(cs)

	hops := []*Hop{
		{
			PubKeyBytes:  vertexA,
			AmtToForward: 99,
		},
		{
			PubKeyBytes:  vertexB,
			AmtToForward: 99,
		},
		{
			PubKeyBytes:  vertexC,
			AmtToForward: 99,
		},
	}

	// Route A --> B --> C
	routeA := &Route{
		SourcePubKey: vertexA,
		Hops:         hops,
	}

	moreHops := []*Hop{
		{
			PubKeyBytes:  vertexA,
			AmtToForward: 15,
		},
		{
			PubKeyBytes:  vertexB,
			AmtToForward: 10,
		},
		{
			PubKeyBytes:  vertexC,
			AmtToForward: 5,
		},
	}

	// Route C --> B --> A
	moreHopsStrict := []*Hop{
		{
			PubKeyBytes:  vertexC,
			AmtToForward: 5,
		},
		{
			PubKeyBytes:  vertexB,
			AmtToForward: 10,
		},
		{
			PubKeyBytes:  vertexA,
			AmtToForward: 15,
		},
	}

	routeB := &Route{
		SourcePubKey: vertexC,
		Hops:         moreHopsStrict,
	}

	// extendedRoute := routeA.ExtendRouteWithHops(moreHops)
	// extendedRoute := routeA.ExtendRoute(routeB)
	extendedRoute, err := routeA.ExtendRouteStrict(routeB)
	if err != nil {
		t.Fatalf("unable to extend route: %v", err)
	}

	t.Log("Extended Route:")
	for _, hop := range extendedRoute.Hops {
		t.Logf("%+v", hop)
	}

	if len(extendedRoute.Hops) != len(hops)+len(moreHops) {
		t.Fatal("unexpected route length.")
	}

	// extendedRoute = routeA.ExtendRouteWithHops(nil)
	extendedRoute = routeA.ExtendRoute(nil)
	// extendedRoute, err := routeA.ExtendRouteStrict(nil)
	// if err != nil {
	// 	t.Fatalf("unable to extend route: %v", err)
	// }

	t.Log("Extended Route:")
	for _, hop := range extendedRoute.Hops {
		t.Logf("%+v", hop)
	}

	if len(extendedRoute.Hops) != len(hops) {
		t.Fatal("unexpected route length.")
	}

}

// func TestIntroductoryBlindedHop(t *testing.T) {}

// TestPayloadSize tests the payload size calculation that is provided by Hop
// structs.
func TestPayloadSize(t *testing.T) {
	hops := []*Hop{
		{
			PubKeyBytes:      testPubKey1Bytes,
			AmtToForward:     1000,
			OutgoingTimeLock: 600000,
			ChannelID:        3432483437438,
			LegacyPayload:    true,
		},
		{
			PubKeyBytes:      testPubKey1Bytes,
			AmtToForward:     1200,
			OutgoingTimeLock: 700000,
			ChannelID:        63584534844,
		},
		{
			PubKeyBytes:      testPubKey1Bytes,
			AmtToForward:     1200,
			OutgoingTimeLock: 700000,
			MPP:              record.NewMPP(500, [32]byte{}),
			AMP:              record.NewAMP([32]byte{}, [32]byte{}, 8),
			CustomRecords: map[uint64][]byte{
				100000:  {1, 2, 3},
				1000000: {4, 5},
			},
			Metadata: []byte{10, 11},
		},
	}

	rt := Route{
		Hops: hops,
	}
	path, err := rt.ToSphinxPath()
	if err != nil {
		t.Fatal(err)
	}

	for i, onionHop := range path[:path.TrueRouteLength()] {
		hop := hops[i]
		var nextChan uint64
		if i < len(hops)-1 {
			nextChan = hops[i+1].ChannelID
		}

		expected := uint64(onionHop.HopPayload.NumBytes())
		actual := hop.PayloadSize(nextChan)
		if expected != actual {
			t.Fatalf("unexpected payload size at hop %v: "+
				"expected %v, got %v",
				i, expected, actual)
		}
	}
}

// TODO(7/24/22): Flesh out this test.
func TestRouteToBlindedPath(t *testing.T) {

	/*
		Blinded Route:

		Alice (intro) <-----------> Bob (blind) <-----------> Carol (blinded recipient)

	*/
	vertexA := testPubKey1Bytes
	vertexB, _ := NewVertexFromBytes(testPubKey2Bytes)
	vertexC, _ := NewVertexFromBytes(testPubKey3Bytes)
	t.Log("A: ", vertexA.String())
	t.Log("B: ", vertexB.String())
	t.Log("C: ", vertexC.String())

	hops := []*Hop{
		// {
		// 	PubKeyBytes:      vertexA,
		// 	AmtToForward:     1000,
		// 	OutgoingTimeLock: 600000,
		// 	ChannelID:        3432483437438,
		// },
		{
			PubKeyBytes:      vertexB,
			AmtToForward:     1200,
			OutgoingTimeLock: 700000,
			ChannelID:        0101231,
		},
		{
			PubKeyBytes:      vertexC,
			AmtToForward:     1200,
			OutgoingTimeLock: 700000,
			ChannelID:        0204561,
			MPP:              record.NewMPP(500, [32]byte{}),
			AMP:              record.NewAMP([32]byte{}, [32]byte{}, 8),
			CustomRecords: map[uint64][]byte{
				100000:  {1, 2, 3},
				1000000: {4, 5},
			},
		},
	}

	rt := Route{
		SourcePubKey: vertexA,
		Hops:         hops,
	}

	// NOTE: Despite following the convention that a route's source is not
	// included in the list of hops, we expect the source to be included
	// in the list of hops to be blinded as it is the introduction node.
	expectedLength := 3
	expectedPubKeys := []Vertex{vertexA, vertexB, vertexC}

	hopsToBeBlinded, err := rt.ToSphinxBlindPath()
	if err != nil {
		t.Fatal(err)
	}

	for i, hop := range hopsToBeBlinded {
		t.Logf("Blind Hop %d: %x\n", i, hop.NodePub.SerializeCompressed())
		t.Logf("Blind Hop %d TLV Payload: %+v\n", i, hop.Payload)
		if hop.NodePub == nil {
			t.Fatalf("no public key for hop %d", i)
		}
		// if hop.Payload == nil {
		// 	t.Fatalf("no route blinding TLV payload for hop %d", i)
		// }
	}

	// Check that the length is as expected, ie: the source node is handled properly.
	if len(hopsToBeBlinded) != expectedLength {
		t.Fatalf("blinded path (list of hops) not of expected length. want: %d, got: %d", expectedLength, len(hopsToBeBlinded))
	}

	for i, hop := range hopsToBeBlinded {
		hopPubKey, _ := NewVertexFromBytes(hop.NodePub.SerializeCompressed())
		if hopPubKey != expectedPubKeys[i] {
			t.Fatalf("unexpected key at hop %d. want: %s, got: %x", i, expectedPubKeys[i].String(), hop.NodePub.SerializeCompressed())
		}
	}

	// // Use this to check after the blinded path gets returned from sphinx library.
	// for i := 0; i < len(blindPath.BlindedHops); i++ {
	// 	if blindPath.BlindedHops[i] != nil {
	// 		t.Logf("Blind Hop %d: %+v\n", i, blindPath.BlindedHops[i])
	// 	}
	// 	if blindPath.EncryptedData[i] != nil {
	// 		t.Logf("Blind Hop %d: %+v\n", i, blindPath.EncryptedData[i])
	// 	}
	// }

	// for i, onionHop := range blindPath[:blindPath.TrueRouteLength()] {
	// 	hop := hops[i]
	// 	var nextChan uint64
	// 	if i < len(hops)-1 {
	// 		nextChan = hops[i+1].ChannelID
	// 	}

	// 	expected := uint64(onionHop.HopPayload.NumBytes())
	// 	actual := hop.PayloadSize(nextChan)
	// 	if expected != actual {
	// 		t.Fatalf("unexpected payload size at hop %v: "+
	// 			"expected %v, got %v",
	// 			i, expected, actual)
	// 	}
	// }
}

// TestPayloadSize tests the payload size calculation that is provided by Hop
// structs.
func TestFinalHopDetermination(t *testing.T) {
	hops := []*Hop{
		{
			PubKeyBytes:      testPubKey1Bytes,
			AmtToForward:     1000,
			OutgoingTimeLock: 600000,
			ChannelID:        3432483437438,
			LegacyPayload:    true,
		},
		{
			PubKeyBytes:      testPubKey1Bytes,
			AmtToForward:     1200,
			OutgoingTimeLock: 700000,
			ChannelID:        63584534844,
		},
		{
			PubKeyBytes:      testPubKey1Bytes,
			AmtToForward:     1200,
			OutgoingTimeLock: 700000,
			MPP:              record.NewMPP(500, [32]byte{}),
			AMP:              record.NewAMP([32]byte{}, [32]byte{}, 8),
			CustomRecords: map[uint64][]byte{
				100000:  {1, 2, 3},
				1000000: {4, 5},
			},
			Metadata: []byte{10, 11},
		},
	}

	rt := Route{
		Hops: hops,
	}
	path, err := rt.ToSphinxPath()
	if err != nil {
		t.Fatal(err)
	}

	for i, onionHop := range path[:path.TrueRouteLength()] {
		hop := hops[i]
		var nextChan uint64
		if i < len(hops)-1 {
			nextChan = hops[i+1].ChannelID
		}

		expected := uint64(onionHop.HopPayload.NumBytes())
		actual := hop.PayloadSize(nextChan)
		if expected != actual {
			t.Fatalf("unexpected payload size at hop %v: "+
				"expected %v, got %v",
				i, expected, actual)
		}
	}
}
