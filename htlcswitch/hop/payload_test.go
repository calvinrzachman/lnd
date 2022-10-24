package hop_test

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/lightningnetwork/lnd/htlcswitch/hop"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/record"
	"github.com/stretchr/testify/require"
)

const testUnknownRequiredType = 0x80

type decodePayloadTest struct {
	name                        string
	payload                     []byte
	expErr                      error
	expCustomRecords            map[uint64][]byte
	shouldHaveMPP               bool
	shouldHaveAMP               bool
	shouldHaveMetadata          bool
	shouldHaveRouteBlindingInfo bool
	expRouteBlindingErr         error
	isFinalHop                  bool
}

var decodePayloadTests = []decodePayloadTest{
	{
		name:    "empty hop TLV payload",
		payload: []byte{},
		// All normal hops (ie: not blind) are expected to have an amount.
		expErr: hop.ErrInvalidPayload{
			Type:      record.AmtOnionType,
			Violation: hop.OmittedViolation,
			FinalHop:  true, // Needs to match what sphinx package says.
		},
		isFinalHop: true,
	},
	{
		name:    "final hop valid",
		payload: []byte{0x02, 0x00, 0x04, 0x00},
		// NOTE(9/9/22): Currently thinks we are a blind hop
		// when we attempt to parse nil route blinding TLV payload.
		// Don't feel bad about this! Weird things happen when we
		// parse nil top level onion payload as well. (Fixed via test modification)
		isFinalHop: true,
	},
	{
		name: "intermediate hop valid",
		payload: []byte{0x02, 0x00, 0x04, 0x00, 0x06, 0x08, 0x01, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
	},
	{
		name:    "final hop no amount",
		payload: []byte{0x04, 0x00},
		expErr: hop.ErrInvalidPayload{
			Type:      record.AmtOnionType,
			Violation: hop.OmittedViolation,
			FinalHop:  true,
		},
		isFinalHop: true,
	},
	{
		name: "intermediate hop no amount",
		payload: []byte{0x04, 0x00, 0x06, 0x08, 0x01, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
		},
		expErr: hop.ErrInvalidPayload{
			Type:      record.AmtOnionType,
			Violation: hop.OmittedViolation,
			FinalHop:  false,
		},
	},
	{
		name:    "final hop no expiry",
		payload: []byte{0x02, 0x00},
		expErr: hop.ErrInvalidPayload{
			Type:      record.LockTimeOnionType,
			Violation: hop.OmittedViolation,
			FinalHop:  true,
		},
		isFinalHop: true,
	},
	{
		name: "intermediate hop no expiry",
		payload: []byte{0x02, 0x00, 0x06, 0x08, 0x01, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
		},
		expErr: hop.ErrInvalidPayload{
			Type:      record.LockTimeOnionType,
			Violation: hop.OmittedViolation,
			FinalHop:  false,
		},
	},
	{
		name: "final hop next sid present",
		payload: []byte{0x02, 0x00, 0x04, 0x00, 0x06, 0x08, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		expErr: hop.ErrInvalidPayload{
			Type:      record.NextHopOnionType,
			Violation: hop.IncludedViolation,
			FinalHop:  true,
		},
		isFinalHop: true,
	},
	{
		name: "required type after omitted hop id",
		payload: []byte{
			0x02, 0x00, 0x04, 0x00,
			testUnknownRequiredType, 0x00,
		},
		expErr: hop.ErrInvalidPayload{
			Type:      testUnknownRequiredType,
			Violation: hop.RequiredViolation,
			FinalHop:  true,
		},
	},
	{
		name: "required type after included hop id",
		payload: []byte{
			0x02, 0x00, 0x04, 0x00, 0x06, 0x08, 0x01, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00,
			testUnknownRequiredType, 0x00,
		},
		expErr: hop.ErrInvalidPayload{
			Type:      testUnknownRequiredType,
			Violation: hop.RequiredViolation,
			FinalHop:  false,
		},
	},
	{
		name:    "required type zero final hop",
		payload: []byte{0x00, 0x00, 0x02, 0x00, 0x04, 0x00},
		expErr: hop.ErrInvalidPayload{
			Type:      0,
			Violation: hop.RequiredViolation,
			FinalHop:  true,
		},
		isFinalHop: true,
	},
	{
		name: "required type zero final hop zero sid",
		payload: []byte{0x00, 0x00, 0x02, 0x00, 0x04, 0x00, 0x06, 0x08,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		expErr: hop.ErrInvalidPayload{
			Type:      record.NextHopOnionType,
			Violation: hop.IncludedViolation,
			FinalHop:  true,
		},
		isFinalHop: true,
	},
	{
		name: "required type zero intermediate hop",
		payload: []byte{0x00, 0x00, 0x02, 0x00, 0x04, 0x00, 0x06, 0x08,
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		expErr: hop.ErrInvalidPayload{
			Type:      0,
			Violation: hop.RequiredViolation,
			FinalHop:  false,
		},
	},
	{
		name: "required type in custom range",
		payload: []byte{0x02, 0x00, 0x04, 0x00,
			0xfe, 0x00, 0x01, 0x00, 0x00, 0x02, 0x10, 0x11,
		},
		expCustomRecords: map[uint64][]byte{
			65536: {0x10, 0x11},
		},
	},
	{
		name: "valid intermediate hop",
		payload: []byte{0x02, 0x00, 0x04, 0x00, 0x06, 0x08, 0x01, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		expErr: nil,
	},
	{
		name:       "valid final hop",
		payload:    []byte{0x02, 0x00, 0x04, 0x00},
		expErr:     nil,
		isFinalHop: true,
	},
	{
		name: "intermediate hop with mpp",
		payload: []byte{
			// amount
			0x02, 0x00,
			// cltv
			0x04, 0x00,
			// next hop id
			0x06, 0x08,
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			// mpp
			0x08, 0x21,
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
			0x08,
		},
		expErr: hop.ErrInvalidPayload{
			Type:      record.MPPOnionType,
			Violation: hop.IncludedViolation,
			FinalHop:  false,
		},
	},
	{
		name: "intermediate hop with amp",
		payload: []byte{
			// amount
			0x02, 0x00,
			// cltv
			0x04, 0x00,
			// next hop id
			0x06, 0x08,
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			// amp
			0x0e, 0x41,
			// amp.root_share
			0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
			0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
			0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
			0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
			// amp.set_id
			0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13,
			0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13,
			0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13,
			0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13,
			// amp.child_index
			0x09,
		},
		expErr: hop.ErrInvalidPayload{
			Type:      record.AMPOnionType,
			Violation: hop.IncludedViolation,
			FinalHop:  false,
		},
	},
	{
		name: "final hop with mpp",
		payload: []byte{
			// amount
			0x02, 0x00,
			// cltv
			0x04, 0x00,
			// mpp
			0x08, 0x21,
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
			0x08,
		},
		expErr:        nil,
		shouldHaveMPP: true,
		isFinalHop:    true,
	},
	{
		name: "final hop with amp",
		payload: []byte{
			// amount
			0x02, 0x00,
			// cltv
			0x04, 0x00,
			// amp
			0x0e, 0x41,
			// amp.root_share
			0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
			0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
			0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
			0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
			// amp.set_id
			0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13,
			0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13,
			0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13,
			0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13,
			// amp.child_index
			0x09,
		},
		shouldHaveAMP: true,
		isFinalHop:    true,
	},
	{
		name: "final hop with metadata",
		payload: []byte{
			// amount
			0x02, 0x00,
			// cltv
			0x04, 0x00,
			// metadata
			0x10, 0x03, 0x01, 0x02, 0x03,
		},
		shouldHaveMetadata: true,
		isFinalHop:         true,
	},
	{
		name: "introduction node blinded route",
		payload: []byte{
			// - no amount
			// - no timelock
			// NOTE(9/21/22): the introduction node will receive an
			// amount and timelock on the inbound HTLC but its top
			// level onion TLV payload should not contain an amount
			// to be forwarded or an outgoing timelock.
			// no unblinded next hop id in blinded portion of route
			// (route blinding - top level TLV payload) recipient encrypted data
			// START: route blinding TLV data
			byte(int(record.RouteBlindingEncryptedDataOnionType)), 0x70,
			// byte(int(record.RouteBlindingEncryptedDataOnionType)), 0x56,
			// (route blinding) padding
			byte(int(record.PaddingOnionType)), 0x04, 0x00, 0x01, 0x00, 0x00,
			// (route blinding) next hop
			byte(int(record.BlindedNextHopOnionType)), 0x08,
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			// (route blinding) next node ID
			byte(int(record.NextNodeIDOnionType)), 0x21,
			0x02, 0xee, 0xc7, 0x24, 0x5d, 0x6b, 0x7d, 0x2c, 0xcb, 0x30, 0x38,
			0x0b, 0xfb, 0xe2, 0xa3, 0x64, 0x8c, 0xd7, 0xa9, 0x42, 0x65, 0x3f,
			0x5a, 0xa3, 0x40, 0xed, 0xce, 0xa1, 0xf2, 0x83, 0x68, 0x66, 0x19,
			// (route blinding) path ID (ONLY set for final node)
			// 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			// (route blinding) blinding point override
			byte(int(record.BlindingOverrideOnionType)), 0x21,
			0x02, 0xee, 0xc7, 0x24, 0x5d, 0x6b, 0x7d, 0x2c, 0xcb, 0x30, 0x38,
			0x0b, 0xfb, 0xe2, 0xa3, 0x64, 0x8c, 0xd7, 0xa9, 0x42, 0x65, 0x3f,
			0x5a, 0xa3, 0x40, 0xed, 0xce, 0xa1, 0xf2, 0x83, 0x68, 0x66, 0x19,
			// (route blinding) payment relay
			byte(int(record.PaymentRelayOnionType)), 0x0a,
			0x00, 0x00, 0x4e, 0x20, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x28,
			// (route blinding) payment constraints
			byte(int(record.PaymentConstraintsOnionType)), 0x0c,
			0x00, 0x00, 0x03, 0xe8,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			// END: route blinding TLV data
			// (route blinding - top level TLV payload) blinding point
			byte(int(record.BlindingPointOnionType)), 0x21,
			0x02, 0xee, 0xc7, 0x24, 0x5d, 0x6b, 0x7d, 0x2c, 0xcb, 0x30, 0x38,
			0x0b, 0xfb, 0xe2, 0xa3, 0x64, 0x8c, 0xd7, 0xa9, 0x42, 0x65, 0x3f,
			0x5a, 0xa3, 0x40, 0xed, 0xce, 0xa1, 0xf2, 0x83, 0x68, 0x66, 0x19,
		},
		shouldHaveRouteBlindingInfo: true,
	},
	{
		name: "intermediate hop blinded route w/ next hop",
		payload: []byte{
			// - no amount
			// - no timelock
			// START: route blinding TLV data
			// recipient encrypted data
			byte(int(record.RouteBlindingEncryptedDataOnionType)), 0x1c,
			// byte(int(record.RouteBlindingEncryptedDataOnionType)), 0x10, // test no payment relay
			// (route blinding) padding
			byte(int(record.PaddingOnionType)), 0x04, 0x00, 0x01, 0x00, 0x00,
			// (route blinding) next hop
			byte(int(record.BlindedNextHopOnionType)), 0x08,
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			// (route blinding) payment relay
			byte(int(record.PaymentRelayOnionType)), 0x0a,
			0x00, 0x00, 0x4e, 0x20, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x28,
			// END: route blinding TLV data
		},
		shouldHaveRouteBlindingInfo: true,
	},
	{
		name: "intermediate hop blinded route w/ next node ID",
		payload: []byte{
			// - no amount
			// - no timelock
			// START: route blinding TLV data
			// recipient encrypted data
			byte(int(record.RouteBlindingEncryptedDataOnionType)), 0x35,
			// byte(int(record.RouteBlindingEncryptedDataOnionType)), 0x29, // test no payment relay
			// (route blinding) padding
			byte(int(record.PaddingOnionType)), 0x04, 0x00, 0x01, 0x00, 0x00,
			// (route blinding) next node ID
			byte(int(record.NextNodeIDOnionType)), 0x21,
			0x02, 0xee, 0xc7, 0x24, 0x5d, 0x6b, 0x7d, 0x2c, 0xcb, 0x30, 0x38,
			0x0b, 0xfb, 0xe2, 0xa3, 0x64, 0x8c, 0xd7, 0xa9, 0x42, 0x65, 0x3f,
			0x5a, 0xa3, 0x40, 0xed, 0xce, 0xa1, 0xf2, 0x83, 0x68, 0x66, 0x19,
			// (route blinding) payment relay
			byte(int(record.PaymentRelayOnionType)), 0x0a,
			0x00, 0x00, 0x4e, 0x20, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x28,
			// END: route blinding TLV data
		},
		shouldHaveRouteBlindingInfo: true,
	},
	{
		name: "intermediate hop blinded route missing payment relay", // error case
		payload: []byte{
			// - no amount
			// - no timelock
			// START: route blinding TLV data
			// recipient encrypted data
			byte(int(record.RouteBlindingEncryptedDataOnionType)), 0x10,
			// padding
			byte(int(record.PaddingOnionType)), 0x04, 0x00, 0x01, 0x00, 0x00,
			// next hop
			byte(int(record.BlindedNextHopOnionType)), 0x08,
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			//  - no payment relay (MUST be set for blind hops)
			// END: route blinding TLV data
		},
		shouldHaveRouteBlindingInfo: true,
		expRouteBlindingErr: hop.ErrInvalidPayload{
			Type:      record.PaymentRelayOnionType,
			Violation: hop.OmittedViolation,
			FinalHop:  false,
		},
	},
	{
		name: "final hop blinded route",
		payload: []byte{
			// amount
			0x02, 0x01, 0x0b,
			// cltv
			0x04, 0x01, 0x11,
			// (route blinding - top level TLV payload) recipient encrypted data
			// START: route blinding TLV data
			byte(int(record.RouteBlindingEncryptedDataOnionType)), 0x0c,
			// (route blinding) padding
			byte(int(record.PaddingOnionType)), 0x04, 0x00, 0x01, 0x00, 0x00,
			// (route blinding) path ID (ONLY set for final node)
			byte(int(record.PathIDOnionType)), 0x04, 0xff, 0x00, 0xff, 0x00,
			// END: route blinding TLV data
		},
		shouldHaveRouteBlindingInfo: true,
		isFinalHop:                  true,
	},
	{
		name: "final hop blinded route missing path ID", // error case
		payload: []byte{
			// amount
			0x02, 0x01, 0x0b,
			// cltv
			0x04, 0x01, 0x11,
			// (route blinding - top level TLV payload) recipient encrypted data
			// START: route blinding TLV data
			byte(int(record.RouteBlindingEncryptedDataOnionType)), 0x06,
			// padding
			byte(int(record.PaddingOnionType)), 0x04, 0x00, 0x01, 0x00, 0x00,
			// - no path ID (MUST be set for final node)
			// END: route blinding TLV data
		},
		shouldHaveRouteBlindingInfo: true,
		expRouteBlindingErr: hop.ErrInvalidPayload{
			Type:      record.PathIDOnionType,
			Violation: hop.OmittedViolation,
			FinalHop:  true,
		},
		isFinalHop: true,
	},
	{
		name: "christmas tree TLV payload (all lights on)",
		payload: []byte{
			// amount
			0x02, 0x01, 0x0b,
			// cltv
			0x04, 0x01, 0x11,
			// (route blinding - top level TLV payload) recipient encrypted data
			// START: route blinding TLV data
			byte(int(record.RouteBlindingEncryptedDataOnionType)), 0x76,
			// (route blinding) padding
			byte(int(record.PaddingOnionType)), 0x04, 0x00, 0x01, 0x00, 0x00,
			// (route blinding) next hop
			byte(int(record.BlindedNextHopOnionType)), 0x08,
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			// (route blinding) next node ID
			byte(int(record.NextNodeIDOnionType)), 0x21,
			0x02, 0xee, 0xc7, 0x24, 0x5d, 0x6b, 0x7d, 0x2c, 0xcb, 0x30, 0x38,
			0x0b, 0xfb, 0xe2, 0xa3, 0x64, 0x8c, 0xd7, 0xa9, 0x42, 0x65, 0x3f,
			0x5a, 0xa3, 0x40, 0xed, 0xce, 0xa1, 0xf2, 0x83, 0x68, 0x66, 0x19,
			// (route blinding) path ID (ONLY set for final node)
			byte(int(record.PathIDOnionType)), 0x04, 0xff, 0x00, 0xff, 0x00,
			// (route blinding) blinding point override
			byte(int(record.BlindingOverrideOnionType)), 0x21,
			0x02, 0xee, 0xc7, 0x24, 0x5d, 0x6b, 0x7d, 0x2c, 0xcb, 0x30, 0x38,
			0x0b, 0xfb, 0xe2, 0xa3, 0x64, 0x8c, 0xd7, 0xa9, 0x42, 0x65, 0x3f,
			0x5a, 0xa3, 0x40, 0xed, 0xce, 0xa1, 0xf2, 0x83, 0x68, 0x66, 0x19,
			// (route blinding) payment relay
			byte(int(record.PaymentRelayOnionType)), 0x0a,
			0x00, 0x00, 0x4e, 0x20, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x28,
			// (route blinding) payment constraints
			byte(int(record.PaymentConstraintsOnionType)), 0x0c,
			0x00, 0x00, 0x03, 0xe8,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			// END: route blinding TLV data
			// (route blinding - top level TLV payload) blinding point
			byte(int(record.BlindingPointOnionType)), 0x21,
			0x02, 0xee, 0xc7, 0x24, 0x5d, 0x6b, 0x7d, 0x2c, 0xcb, 0x30, 0x38,
			0x0b, 0xfb, 0xe2, 0xa3, 0x64, 0x8c, 0xd7, 0xa9, 0x42, 0x65, 0x3f,
			0x5a, 0xa3, 0x40, 0xed, 0xce, 0xa1, 0xf2, 0x83, 0x68, 0x66, 0x19,
		},
		shouldHaveRouteBlindingInfo: true,
		// Expect validation for intermediate hop to complain about
		// inclusion of first (lowest type ID #) missing type (amt).
		// isFinalHop: true, // christmas-tree does not error for final hop.
		expErr: hop.ErrInvalidPayload{
			Type:      record.AmtOnionType,
			Violation: hop.IncludedViolation,
			FinalHop:  false,
		},
	},
	// NOTE(9/9/22): Some of these tests might need to be relocated to a
	// similarly constructed unit test in the Channel Link as that is where
	// we can verify that our blind hop processing/validation routine properly
	// considers both top level onion TLV and route blinding TLV payloads
	// when enforcing BOLT-04 specifications.
	// {
	// 	name:   "route blinding intermediate hop, amount & timelock set",
	// 	expErr: hop.ErrInvalidPayload{},
	// },
	// {
	// 	name:   "route blinding final hop, ...",
	// 	expErr: hop.ErrInvalidPayload{},
	// },
	// {
	// 	name: "intermediate hop blinded route with unblinded next hop",
	// 	// payload: []byte{},
	// 	payload: []byte{
	// 		// amount
	// 		0x02, 0x00,
	// 		// cltv
	// 		0x04, 0x00,
	// 		// next hop id
	// 		0x06, 0x08,
	// 		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// 		// route blinding TLV data
	// 		// TODO (3/27/22): Observe what serialization looks like and
	// 		// update test to use that.
	// 		// recipient encrypted data
	// 		0x0a, 0x08,
	// 		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// 		// blinding point
	// 		0x0c, 0x21,
	// 		0x00,
	// 		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// 		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// 		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// 		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// 	},
	// 	expErr: hop.ErrInvalidPayload{
	// 		Type:      record.NextHopOnionType,
	// 		Violation: hop.IncludedViolation,
	// 		FinalHop:  false,
	// 	},
	// },
}

// TestDecodeHopPayloadRecordValidation asserts that parsing the payloads in the
// tests yields the expected errors depending on whether the proper fields were
// included or omitted.
func TestDecodeHopPayloadRecordValidation(t *testing.T) {
	for _, test := range decodePayloadTests {
		t.Run(test.name, func(t *testing.T) {
			testDecodeHopPayloadValidation(t, test)
		})
	}
}

func testDecodeHopPayloadValidation(t *testing.T, test decodePayloadTest) {
	var (
		testTotalMsat = lnwire.MilliSatoshi(8)
		testAddr      = [32]byte{
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
		}

		testRootShare = [32]byte{
			0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
			0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
			0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
			0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
		}
		testSetID = [32]byte{
			0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13,
			0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13,
			0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13,
			0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13,
		}
		testMetadata   = []byte{1, 2, 3}
		testChildIndex = uint32(9)
	)

	// Route Blinding: Modify this test too? Ensure that a next hop "scid"
	// has been found in either its usual onion spot or in the encrypted payload
	// from the recipient. It is an error for it to not be found in one of those 2
	// locations.
	t.Logf("raw top level onion tlv payload: %+v\n", test.payload)
	p, err := hop.NewPayloadFromReader(bytes.NewReader(test.payload), test.isFinalHop)
	t.Logf("Parsed Hop Payload: %+v\n", p)
	if p != nil && p.BlindingPoint != nil {
		t.Logf("Blinding Point Pointer in Parsed Hop Payload: %p\n", p.BlindingPoint)
		t.Logf("Blinding Point in Parsed Hop Payload: %+v\n", p.BlindingPoint.SerializeCompressed())
	}

	if !reflect.DeepEqual(test.expErr, err) {
		t.Fatalf("expected error mismatch, want: %v, got: %v",
			test.expErr, err)
	}
	if err != nil {
		return
	}

	// Assert MPP fields if we expect them.
	if test.shouldHaveMPP {
		if p.MPP == nil {
			t.Fatalf("payload should have MPP record")
		}
		if p.MPP.TotalMsat() != testTotalMsat {
			t.Fatalf("invalid total msat")
		}
		if p.MPP.PaymentAddr() != testAddr {
			t.Fatalf("invalid payment addr")
		}
	} else if p.MPP != nil {
		t.Fatalf("unexpected MPP payload")
	}

	if test.shouldHaveAMP {
		if p.AMP == nil {
			t.Fatalf("payload should have AMP record")
		}
		require.Equal(t, testRootShare, p.AMP.RootShare())
		require.Equal(t, testSetID, p.AMP.SetID())
		require.Equal(t, testChildIndex, p.AMP.ChildIndex())
	} else if p.AMP != nil {
		t.Fatalf("unexpected AMP payload")
	}

	if test.shouldHaveMetadata {
		if p.Metadata() == nil {
			t.Fatalf("payload should have metadata")
		}
		require.Equal(t, testMetadata, p.Metadata())
	} else if p.Metadata() != nil {
		t.Fatalf("unexpected metadata")
	}

	// If the top level onion TLV payload contains a route blinding TLV
	// payload, then we'll parse that as well.
	// NOTE: This test should assume the route blinding payload has already been decrypted.
	var blindHopPayload *hop.BlindHopPayload
	if p.RouteBlindingEncryptedData != nil {
		t.Logf("raw route blinding tlv payload: %+v\n", p.RouteBlindingEncryptedData)
		blindHopPayload, err = hop.NewBlindHopPayloadFromReader(bytes.NewReader(p.RouteBlindingEncryptedData), test.isFinalHop)
		// if blindHopPayload != nil {
		// 	t.Logf("parsed route blinding TLV payload: %+v\n", blindHopPayload)
		// 	t.Logf("payment relay: %+v\n", blindHopPayload.PaymentRelay)
		// 	t.Logf("payment constraints: %+v\n", blindHopPayload.PaymentConstraints)
		// 	// t.Logf("Next Node ID in Blind Hop Payload: %+v\n", blindHopPayload.NextNodeID.SerializeCompressed())
		// }
		if !reflect.DeepEqual(test.expRouteBlindingErr, err) {
			t.Fatalf("expected error mismatch, want: %v, got: %v",
				test.expErr, err)
		}
		if err != nil {
			return
		}
	} else {
		t.Log("no route blinding payload")
	}

	if test.shouldHaveRouteBlindingInfo {
		if p.RouteBlindingEncryptedData == nil {
			t.Fatalf("payload should have encrypted data from route blinder")
		}

		if blindHopPayload == nil {
			t.Fatalf("should have parsed route blinding payload")
		}

	} else if p.RouteBlindingEncryptedData != nil || p.BlindingPoint != nil {
		t.Fatalf("unexpected route blinding info included in payload")
	}

	// Convert expected nil map to empty map, because we always expect an
	// initiated map from the payload.
	expCustomRecords := make(record.CustomSet)
	if test.expCustomRecords != nil {
		expCustomRecords = test.expCustomRecords
	}
	if !reflect.DeepEqual(expCustomRecords, p.CustomRecords()) {
		t.Fatalf("invalid custom records")
	}
}

// NOTE(9/1/22): Test the parsing of the route blinding TLV payload individually.
type decodeRouteBlindingPayloadTest struct {
	name                 string
	routeBlindingPayload []byte
	expectedErr          error

	// isFinalHop indicates that our sphinx implementation has encountered
	// an all-zero 32 byte onion HMAC signaling we are the final hop.
	isFinalHop bool
}

var decodeRouteBlindingPayloadTests = []decodeRouteBlindingPayloadTest{
	{
		name:                 "empty route blinding TLV payload",
		routeBlindingPayload: []byte{},
		// All route blinding payloads are expected to have payment
		// relay information (TODO: check on this as route blinding
		// doesn't have to be used for payments).
		expectedErr: hop.ErrInvalidPayload{
			Type:      record.PaymentRelayOnionType,
			Violation: hop.OmittedViolation,
			FinalHop:  false, // Needs to match what sphinx package says.
		},
	},
	{
		name: "introduction node blinded route",
		routeBlindingPayload: []byte{
			// START: route blinding TLV data
			// padding
			byte(int(record.PaddingOnionType)), 0x04, 0x00, 0x01, 0x00, 0x00,
			// next hop
			byte(int(record.BlindedNextHopOnionType)), 0x08,
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			// next node ID
			byte(int(record.NextNodeIDOnionType)), 0x21,
			0x02, 0xee, 0xc7, 0x24, 0x5d, 0x6b, 0x7d, 0x2c, 0xcb, 0x30, 0x38,
			0x0b, 0xfb, 0xe2, 0xa3, 0x64, 0x8c, 0xd7, 0xa9, 0x42, 0x65, 0x3f,
			0x5a, 0xa3, 0x40, 0xed, 0xce, 0xa1, 0xf2, 0x83, 0x68, 0x66, 0x19,
			// path ID (ONLY set for final node)
			// 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			// blinding point override
			byte(int(record.BlindingOverrideOnionType)), 0x21,
			0x02, 0xee, 0xc7, 0x24, 0x5d, 0x6b, 0x7d, 0x2c, 0xcb, 0x30, 0x38,
			0x0b, 0xfb, 0xe2, 0xa3, 0x64, 0x8c, 0xd7, 0xa9, 0x42, 0x65, 0x3f,
			0x5a, 0xa3, 0x40, 0xed, 0xce, 0xa1, 0xf2, 0x83, 0x68, 0x66, 0x19,
			// payment relay
			byte(int(record.PaymentRelayOnionType)), 0x0a,
			0x00, 0x00, 0x4e, 0x20, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x28,
			// payment constraints
			byte(int(record.PaymentConstraintsOnionType)), 0x0c,
			0x00, 0x00, 0x03, 0xe8,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			// END: route blinding TLV data
		},
	},
	{
		name: "intermediate hop blinded route w/ next hop",
		routeBlindingPayload: []byte{
			// START: route blinding TLV data
			// padding
			byte(int(record.PaddingOnionType)), 0x04, 0x00, 0x01, 0x00, 0x00,
			// next hop
			byte(int(record.BlindedNextHopOnionType)), 0x08,
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			// payment relay
			byte(int(record.PaymentRelayOnionType)), 0x0a,
			0x00, 0x00, 0x4e, 0x20, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x28,
			// END: route blinding TLV data
		},
	},
	{
		name: "intermediate hop blinded route w/ next node ID",
		routeBlindingPayload: []byte{
			// START: route blinding TLV data
			// padding
			byte(int(record.PaddingOnionType)), 0x04, 0x00, 0x01, 0x00, 0x00,
			// next node ID
			byte(int(record.NextNodeIDOnionType)), 0x21,
			0x02, 0xee, 0xc7, 0x24, 0x5d, 0x6b, 0x7d, 0x2c, 0xcb, 0x30, 0x38,
			0x0b, 0xfb, 0xe2, 0xa3, 0x64, 0x8c, 0xd7, 0xa9, 0x42, 0x65, 0x3f,
			0x5a, 0xa3, 0x40, 0xed, 0xce, 0xa1, 0xf2, 0x83, 0x68, 0x66, 0x19,
			// payment relay
			byte(int(record.PaymentRelayOnionType)), 0x0a,
			0x00, 0x00, 0x4e, 0x20, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x28,
			// END: route blinding TLV data
		},
	},
	{
		name: "intermediate hop blinded route missing both next_hop " + // error case
			"and next_node_id",
		routeBlindingPayload: []byte{
			// START: route blinding TLV data
			// padding
			byte(int(record.PaddingOnionType)), 0x04, 0x00, 0x01, 0x00, 0x00,
			// - no next hop
			// - no next node ID
			// payment relay
			byte(int(record.PaymentRelayOnionType)), 0x0a,
			0x00, 0x00, 0x4e, 0x20, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x28,
			// END: route blinding TLV data
		},
		expectedErr: hop.ErrInvalidPayload{
			Type:      record.BlindedNextHopOnionType,
			Violation: hop.OmittedViolation,
			FinalHop:  false,
		},
	},
	{
		name: "intermediate hop blinded route missing payment relay", // error case
		routeBlindingPayload: []byte{
			// START: route blinding TLV data
			// padding
			byte(int(record.PaddingOnionType)), 0x04, 0x00, 0x01, 0x00, 0x00,
			// next hop
			byte(int(record.BlindedNextHopOnionType)), 0x08,
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			//  - no payment relay (MUST be set for blind hops)
			// END: route blinding TLV data
		},
		expectedErr: hop.ErrInvalidPayload{
			Type:      record.PaymentRelayOnionType,
			Violation: hop.OmittedViolation,
			FinalHop:  false,
		},
	},
	{
		name: "final hop blinded route",
		routeBlindingPayload: []byte{
			// START: route blinding TLV data
			// padding
			byte(int(record.PaddingOnionType)), 0x04, 0x00, 0x01, 0x00, 0x00,
			// path ID (ONLY set for final node)
			byte(int(record.PathIDOnionType)), 0x04, 0xff, 0x00, 0xff, 0x00,
			// END: route blinding TLV data
		},
		isFinalHop: true,
	},
	// { // Treats like intermediate hop and complains about lack of payment_relay
	// 	name: "TEMP: final hop blinded route w/ non-final signal from sphinx",
	// 	routeBlindingPayload: []byte{
	// 		// START: route blinding TLV data
	// 		// padding
	// 		byte(int(record.PaddingOnionType)), 0x04, 0x00, 0x01, 0x00, 0x00,
	// 		// path ID (ONLY set for final node)
	// 		byte(int(record.PathIDOnionType)), 0x04, 0xff, 0x00, 0xff, 0x00,
	// 		// END: route blinding TLV data
	// 	},
	// },
	{
		name: "final hop blinded route missing path ID", // error case
		routeBlindingPayload: []byte{
			// START: route blinding TLV data
			// padding
			byte(int(record.PaddingOnionType)), 0x04, 0x00, 0x01, 0x00, 0x00,
			// - no path ID (MUST be set for final node)
			// END: route blinding TLV data
		},
		expectedErr: hop.ErrInvalidPayload{
			Type:      record.PathIDOnionType,
			Violation: hop.OmittedViolation,
			FinalHop:  true,
		},
		isFinalHop: true,
	},
	{
		name: "christmas tree route blinding payload (all lights on)",
		routeBlindingPayload: []byte{
			// START: route blinding TLV data
			// padding
			byte(int(record.PaddingOnionType)), 0x04, 0x00, 0x01, 0x00, 0x00,
			// next hop
			byte(int(record.BlindedNextHopOnionType)), 0x08,
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			// next node ID
			byte(int(record.NextNodeIDOnionType)), 0x21,
			0x02, 0xee, 0xc7, 0x24, 0x5d, 0x6b, 0x7d, 0x2c, 0xcb, 0x30, 0x38,
			0x0b, 0xfb, 0xe2, 0xa3, 0x64, 0x8c, 0xd7, 0xa9, 0x42, 0x65, 0x3f,
			0x5a, 0xa3, 0x40, 0xed, 0xce, 0xa1, 0xf2, 0x83, 0x68, 0x66, 0x19,
			// path ID (ONLY set for final node)
			byte(int(record.PathIDOnionType)), 0x04, 0xff, 0x00, 0xff, 0x00,
			// blinding point override
			byte(int(record.BlindingOverrideOnionType)), 0x21,
			0x02, 0xee, 0xc7, 0x24, 0x5d, 0x6b, 0x7d, 0x2c, 0xcb, 0x30, 0x38,
			0x0b, 0xfb, 0xe2, 0xa3, 0x64, 0x8c, 0xd7, 0xa9, 0x42, 0x65, 0x3f,
			0x5a, 0xa3, 0x40, 0xed, 0xce, 0xa1, 0xf2, 0x83, 0x68, 0x66, 0x19,
			// payment relay
			byte(int(record.PaymentRelayOnionType)), 0x0a,
			0x00, 0x00, 0x4e, 0x20, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x28,
			// payment constraints
			byte(int(record.PaymentConstraintsOnionType)), 0x0c,
			0x00, 0x00, 0x03, 0xe8,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			// END: route blinding TLV data
		},
	},
}

// TestDecodeBlindHopPayloadRecordValidation asserts that parsing the route
// blinding TLV payloads in the tests yields the expected errors depending
// on whether the proper fields were included or omitted.
//
// NOTE(9/16/22): This test isolates the parsing of the route blinding TLV
// payload from the parsing of the top level onion TLV payload and excercises
// the little validation we can at this stage.
func TestDecodeBlindHopPayloadRecordValidation(t *testing.T) {
	for _, test := range decodeRouteBlindingPayloadTests {
		t.Run(test.name, func(t *testing.T) {
			testDecodeBlindHopPayloadValidation(t, test)
		})
	}
}

func testDecodeBlindHopPayloadValidation(t *testing.T, test decodeRouteBlindingPayloadTest) {

	// Parse the route blinding TLV payload.
	// NOTE: This test assumes the route blinding payload has already been decrypted.
	blindHopPayload, err := hop.NewBlindHopPayloadFromReader(
		bytes.NewReader(test.routeBlindingPayload), test.isFinalHop,
	)
	if blindHopPayload != nil {
		t.Logf("parsed route blinding TLV payload: %+v\n", blindHopPayload)
		t.Logf("payment relay: %+v\n", blindHopPayload.PaymentRelay)
		t.Logf("payment constraints: %+v\n", blindHopPayload.PaymentConstraints)
	}
	if !reflect.DeepEqual(test.expectedErr, err) {
		t.Fatalf("expected error mismatch, want: %v, got: %v",
			test.expectedErr, err)
	}

}
