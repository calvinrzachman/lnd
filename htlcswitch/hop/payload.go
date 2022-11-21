package hop

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/btcec/v2"
	sphinx "github.com/lightningnetwork/lightning-onion"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/record"
	"github.com/lightningnetwork/lnd/tlv"
)

// PayloadViolation is an enum encapsulating the possible invalid payload
// violations that can occur when processing or validating a payload.
type PayloadViolation byte

const (
	// OmittedViolation indicates that a type was expected to be found the
	// payload but was absent.
	OmittedViolation PayloadViolation = iota

	// IncludedViolation indicates that a type was expected to be omitted
	// from the payload but was present.
	IncludedViolation

	// RequiredViolation indicates that an unknown even type was found in
	// the payload that we could not process.
	RequiredViolation

	// InsufficientViolation indicates that the provided type does
	// not satisfy constraints.
	InsufficientViolation
)

// String returns a human-readable description of the violation as a verb.
func (v PayloadViolation) String() string {
	switch v {
	case OmittedViolation:
		return "omitted"

	case IncludedViolation:
		return "included"

	case RequiredViolation:
		return "required"

	case InsufficientViolation:
		return "insufficient"

	default:
		return "unknown violation"
	}
}

// ErrInvalidPayload is an error returned when a parsed onion payload either
// included or omitted incorrect records for a particular hop type.
type ErrInvalidPayload struct {
	// Type the record's type that cause the violation.
	Type tlv.Type

	// Violation is an enum indicating the type of violation detected in
	// processing Type.
	Violation PayloadViolation

	// FinalHop if true, indicates that the violation is for the final hop
	// in the route (identified by next hop id), otherwise the violation is
	// for an intermediate hop.
	FinalHop bool
}

// Error returns a human-readable description of the invalid payload error.
func (e ErrInvalidPayload) Error() string {
	hopType := "intermediate"
	if e.FinalHop {
		hopType = "final"
	}

	return fmt.Sprintf("onion payload for %s hop %v record with type %d",
		hopType, e.Violation, e.Type)
}

// Payload encapsulates all information delivered to a hop in an onion payload.
// A Hop can represent either a TLV or legacy payload. The primary forwarding
// instruction can be accessed via ForwardingInfo, and additional records can be
// accessed by other member functions.
type Payload struct {
	// FwdInfo holds the basic parameters required for HTLC forwarding, e.g.
	// amount, cltv, and next hop.
	FwdInfo ForwardingInfo

	// MPP holds the info provided in an option_mpp record when parsed from
	// a TLV onion payload.
	MPP *record.MPP

	// AMP holds the info provided in an option_amp record when parsed from
	// a TLV onion payload.
	AMP *record.AMP

	// customRecords are user-defined records in the custom type range that
	// were included in the payload.
	customRecords record.CustomSet

	// encryptedData is a blob of data encrypted by the receiver for use
	// in blinded routes.
	encryptedData []byte

	// blindingPoint is an ephemeral pubkey for use in blinded routes.
	blindingPoint *btcec.PublicKey

	// metadata is additional data that is sent along with the payment to
	// the payee.
	metadata []byte

	// totalAmtMsat holds the info provided in total_amount_msat when
	// parsed from a TLV onion payload.
	totalAmtMsat lnwire.MilliSatoshi
}

// NewLegacyPayload builds a Payload from the amount, cltv, and next hop
// parameters provided by leegacy onion payloads.
func NewLegacyPayload(f *sphinx.HopData) *Payload {
	nextHop := binary.BigEndian.Uint64(f.NextAddress[:])

	return &Payload{
		FwdInfo: ForwardingInfo{
			NextHop:         lnwire.NewShortChanIDFromInt(nextHop),
			AmountToForward: lnwire.MilliSatoshi(f.ForwardAmount),
			OutgoingCTLV:    f.OutgoingCltv,
		},
		customRecords: make(record.CustomSet),
	}
}

// NewPayloadFromReader builds a new Hop from the passed io.Reader. The reader
// should correspond to the bytes encapsulated in a TLV onion payload. The
// final hop bool signals that this payload was the final packet parsed by
// sphinx. A blinding kit is passed in to help handle payloads that are part
// of a blinded route.
func NewPayloadFromReader(r io.Reader, finalHop bool,
	blindingKit *BlindingKit) (*Payload, error) {

	var (
		cid           uint64
		amt           uint64
		totalAmtMsat  uint64
		cltv          uint32
		mpp           = &record.MPP{}
		amp           = &record.AMP{}
		encryptedData []byte
		blindingPoint *btcec.PublicKey
		metadata      []byte
	)

	tlvStream, err := tlv.NewStream(
		record.NewAmtToFwdRecord(&amt),
		record.NewLockTimeRecord(&cltv),
		record.NewNextHopIDRecord(&cid),
		mpp.Record(),
		record.NewEncryptedDataRecord(&encryptedData),
		record.NewBlindingPointRecord(&blindingPoint),
		amp.Record(),
		record.NewMetadataRecord(&metadata),
		record.NewTotalAmtMsatBlinded(&totalAmtMsat),
	)
	if err != nil {
		return nil, err
	}

	// Since this data is provided by a potentially malicious peer, pass it
	// into the P2P decoding variant.
	parsedTypes, err := tlvStream.DecodeWithParsedTypesP2P(r)
	if err != nil {
		return nil, err
	}

	// Validate whether the sender properly included or omitted tlv records
	// in accordance with BOLT 04.
	err = ValidateParsedPayloadTypes(
		parsedTypes, finalHop, blindingKit.BlindingPoint != nil,
	)
	if err != nil {
		return nil, err
	}

	// Check for violation of the rules for mandatory fields.
	violatingType := getMinRequiredViolation(parsedTypes)
	if violatingType != nil {
		return nil, ErrInvalidPayload{
			Type:      *violatingType,
			Violation: RequiredViolation,
			FinalHop:  finalHop,
		}
	}

	// If no MPP field was parsed, set the MPP field on the resulting
	// payload to nil.
	if _, ok := parsedTypes[record.MPPOnionType]; !ok {
		mpp = nil
	}

	// If no AMP field was parsed, set the MPP field on the resulting
	// payload to nil.
	if _, ok := parsedTypes[record.AMPOnionType]; !ok {
		amp = nil
	}

	// If no encrypted data was parsed, set the field on our resulting
	// payload to nil.
	if _, ok := parsedTypes[record.EncryptedDataOnionType]; !ok {
		encryptedData = nil
	}

	// If no metadata field was parsed, set the metadata field on the
	// resulting payload to nil.
	if _, ok := parsedTypes[record.MetadataOnionType]; !ok {
		metadata = nil
	}

	// Filter out the custom records.
	customRecords := NewCustomRecords(parsedTypes)

	// If we have a blinding point, pick it from our two options (we've
	// already validated that we don't have _both_ set).
	var activeBlindingPoint *btcec.PublicKey
	if blindingKit.BlindingPoint != nil {
		activeBlindingPoint = blindingKit.BlindingPoint
	}

	if _, ok := parsedTypes[record.BlindingPointOnionType]; ok {
		activeBlindingPoint = blindingPoint
	}

	payload := &Payload{
		MPP:           mpp,
		AMP:           amp,
		metadata:      metadata,
		encryptedData: encryptedData,
		blindingPoint: activeBlindingPoint,
		customRecords: customRecords,
		totalAmtMsat:  lnwire.MilliSatoshi(totalAmtMsat),
	}

	// If there is no blinding point, set forwarding information from
	// the payload. If we have a blinding point we'll get this information
	// from the encrypted data blob.
	if activeBlindingPoint == nil {
		payload.FwdInfo = ForwardingInfo{
			NextHop:         lnwire.NewShortChanIDFromInt(cid),
			AmountToForward: lnwire.MilliSatoshi(amt),
			OutgoingCTLV:    cltv,
		}
	} else {
		forwarding, err := blindingKit.ForwardingInfo(
			activeBlindingPoint, payload.encryptedData,
		)
		if err != nil {
			return nil, fmt.Errorf("decrypting blinded data "+
				"failed: %w", err)
		}

		// If we obtained forwarding info without error, we expect this
		// to be non-nil.
		payload.FwdInfo = *forwarding
	}

	return payload, nil
}

// ForwardingInfo returns the basic parameters required for HTLC forwarding,
// e.g. amount, cltv, and next hop.
func (h *Payload) ForwardingInfo() ForwardingInfo {
	return h.FwdInfo
}

// NewCustomRecords filters the types parsed from the tlv stream for custom
// records.
func NewCustomRecords(parsedTypes tlv.TypeMap) record.CustomSet {
	customRecords := make(record.CustomSet)
	for t, parseResult := range parsedTypes {
		if parseResult == nil || t < record.CustomTypeStart {
			continue
		}
		customRecords[uint64(t)] = parseResult
	}
	return customRecords
}

// ValidateParsedPayloadTypes checks the types parsed from a hop payload to
// ensure that the proper fields are either included or omitted. The finalHop
// boolean should be true if the payload was parsed for an exit hop. The
// requirements for this method are described in BOLT 04.
func ValidateParsedPayloadTypes(parsedTypes tlv.TypeMap, isFinalHop,
	updateAddBlindingPoint bool) error {

	_, hasAmt := parsedTypes[record.AmtOnionType]
	_, hasLockTime := parsedTypes[record.LockTimeOnionType]
	_, hasNextHop := parsedTypes[record.NextHopOnionType]
	_, hasMPP := parsedTypes[record.MPPOnionType]
	_, hasAMP := parsedTypes[record.AMPOnionType]
	_, hasEncryptedData := parsedTypes[record.EncryptedDataOnionType]
	_, hasPayloadBlinding := parsedTypes[record.BlindingPointOnionType]

	// All cleartext hops (including final hop) and the final hop in a
	// blinded path require the forwading amount and expiry TLVs to be set.
	needFwdInfo := isFinalHop || !hasEncryptedData

	// No blinded hops should have a next hop specified, and only the final
	// hop in a cleartext route should exclude it.
	needNextHop := !(hasEncryptedData || isFinalHop)

	// hasBlindingPoint is true for introduction and intermediate nodes
	// in blinded paths.
	hasBlindingPoint := hasPayloadBlinding || updateAddBlindingPoint

	switch {
	// If a blinding point is provided, we expect encrypted data.
	case hasBlindingPoint && !hasEncryptedData:
		return ErrInvalidPayload{
			Type:      record.EncryptedDataOnionType,
			Violation: OmittedViolation,
			FinalHop:  isFinalHop,
		}

	// A blinding point should not be set in both update_add_htlc and the
	// onion payload - only one is expected.
	case hasPayloadBlinding && updateAddBlindingPoint:
		return ErrInvalidPayload{
			Type:      record.BlindingPointOnionType,
			Violation: IncludedViolation,
			FinalHop:  isFinalHop,
		}

	// Hops that need forwarding info must include an amount to forward.
	case needFwdInfo && !hasAmt:
		return ErrInvalidPayload{
			Type:      record.AmtOnionType,
			Violation: OmittedViolation,
			FinalHop:  isFinalHop,
		}

	// Hops that need forwarding info must include a cltv expiry.
	case needFwdInfo && !hasLockTime:
		return ErrInvalidPayload{
			Type:      record.LockTimeOnionType,
			Violation: OmittedViolation,
			FinalHop:  isFinalHop,
		}

	// Hops that don't need forwarding info shouldn't have an amount TLV.
	case !needFwdInfo && hasAmt:
		return ErrInvalidPayload{
			Type:      record.AmtOnionType,
			Violation: IncludedViolation,
			FinalHop:  isFinalHop,
		}

	// Hops that don't need forwarding info shouldn't have a cltv TLV.
	case !needFwdInfo && hasLockTime:
		return ErrInvalidPayload{
			Type:      record.LockTimeOnionType,
			Violation: IncludedViolation,
			FinalHop:  isFinalHop,
		}

	// The exit hop and all blinded hops should omit the next hop id.
	case !needNextHop && hasNextHop:
		return ErrInvalidPayload{
			Type:      record.NextHopOnionType,
			Violation: IncludedViolation,
			FinalHop:  isFinalHop,
		}

	// Require that the next hop is set for intermediate hops in regular
	// routes.
	case needNextHop && !hasNextHop:
		return ErrInvalidPayload{
			Type:      record.NextHopOnionType,
			Violation: OmittedViolation,
			FinalHop:  isFinalHop,
		}

	// Intermediate nodes should never receive MPP fields.
	case !isFinalHop && hasMPP:
		return ErrInvalidPayload{
			Type:      record.MPPOnionType,
			Violation: IncludedViolation,
			FinalHop:  isFinalHop,
		}

	// Intermediate nodes should never receive AMP fields.
	case !isFinalHop && hasAMP:
		return ErrInvalidPayload{
			Type:      record.AMPOnionType,
			Violation: IncludedViolation,
			FinalHop:  isFinalHop,
		}

	// Blinded routes restrict the presence of TLVs more strictly than
	// regular routes, check that intermediate and final hops only have
	// the TLVs the spec allows them to have.
	case hasEncryptedData:
		allowedTLVs := map[tlv.Type]bool{
			record.EncryptedDataOnionType: true,
			record.BlindingPointOnionType: true,
		}

		if isFinalHop {
			allowedTLVs[record.AmtOnionType] = true
			allowedTLVs[record.LockTimeOnionType] = true
			allowedTLVs[record.TotalAmtMsatBlindedType] = true
		}

		for tlvType := range parsedTypes {
			if _, ok := allowedTLVs[tlvType]; ok {
				continue
			}

			return ErrInvalidPayload{
				Type:      tlvType,
				Violation: IncludedViolation,
				FinalHop:  isFinalHop,
			}
		}
	}

	return nil
}

// MultiPath returns the record corresponding the option_mpp parsed from the
// onion payload.
func (h *Payload) MultiPath() *record.MPP {
	return h.MPP
}

// AMPRecord returns the record corresponding with option_amp parsed from the
// onion payload.
func (h *Payload) AMPRecord() *record.AMP {
	return h.AMP
}

// CustomRecords returns the custom tlv type records that were parsed from the
// payload.
func (h *Payload) CustomRecords() record.CustomSet {
	return h.customRecords
}

// EncryptedData returns the route blinding encrypted data parsed from the
// onion payload.
func (h *Payload) EncryptedData() []byte {
	return h.encryptedData
}

// BlindingPoint returns the route blinding point parsed from the onion payload.
func (h *Payload) BlindingPoint() *btcec.PublicKey {
	return h.blindingPoint
}

// Metadata returns the additional data that is sent along with the
// payment to the payee.
func (h *Payload) Metadata() []byte {
	return h.metadata
}

// TotalAmtMsat returns the total amount sent to the final hop, as set by the
// payee.
func (h *Payload) TotalAmtMsat() lnwire.MilliSatoshi {
	return h.totalAmtMsat
}

// getMinRequiredViolation checks for unrecognized required (even) fields in the
// standard range and returns the lowest required type. Always returning the
// lowest required type allows a failure message to be deterministic.
func getMinRequiredViolation(set tlv.TypeMap) *tlv.Type {
	var (
		requiredViolation        bool
		minRequiredViolationType tlv.Type
	)
	for t, parseResult := range set {
		// If a type is even but not known to us, we cannot process the
		// payload. We are required to understand a field that we don't
		// support.
		//
		// We always accept custom fields, because a higher level
		// application may understand them.
		if parseResult == nil || t%2 != 0 ||
			t >= record.CustomTypeStart {

			continue
		}

		if !requiredViolation || t < minRequiredViolationType {
			minRequiredViolationType = t
		}
		requiredViolation = true
	}

	if requiredViolation {
		return &minRequiredViolationType
	}

	return nil
}

// ValidateBlindedRouteData performs the additional validation that is
// required for payments that rely on data provided in an encrypted blob to
// be forwarded. We enforce the blinded route's maximum expiry height so that
// the route "expires" and a malicious party does not have endless opportunity
// to probe the blinded route and compare it to updated channel policies in
// the network.
func ValidateBlindedRouteData(blindedData *record.BlindedRouteData,
	incomingAmount lnwire.MilliSatoshi, incomingTimelock uint32) error {

	// Bolt 04 notes that we should enforce payment constraints _if_ they
	// are present, so we do not fail if not provided.
	if blindedData.Constraints != nil {
		// MUST fail if the expiry is greater than max_cltv_expiry.
		maxCLTV := blindedData.Constraints.MaxCltvExpiry
		if incomingTimelock > maxCLTV {
			return ErrInvalidPayload{
				Type:      record.LockTimeOnionType,
				Violation: InsufficientViolation,
			}
		}

		// MUST fail if the amount is below htlc_minimum_msat.
		if incomingAmount < blindedData.Constraints.HtlcMinimumMsat {
			return ErrInvalidPayload{
				Type:      record.AmtOnionType,
				Violation: InsufficientViolation,
			}
		}
	}

	// Encrypted data MUST include payment relay information.
	if blindedData.RelayInfo == nil {
		return ErrInvalidPayload{
			Type:      record.PaymentRelayType,
			Violation: OmittedViolation,
		}
	}

	// Specification validation instructions for receivers are:
	// * encrypted data must either have short_channel id _or_ next_node_id.
	//
	// However, instructions for creators of blinded route encrypted data
	// for payments state that a short_channel_id MUST be included.
	//
	// This difference in validation and creation instructions is present
	// because blinded routes are used for blinded payments and onion
	// messages (the latter relying on node IDs rather than short channel
	// ids).
	//
	// While we may transition relaying to node_id based payments, this is
	// not currently a valid option for blinded payments (because the
	// receiver must give us a short channel ID), so we simply validate
	// that we have a short channel ID.
	//
	// TODO: relax validation if node_id based blinded payments are
	// introduced to the specification.
	if blindedData.ShortChannelID == nil {
		return ErrInvalidPayload{
			Type:      record.ShortChannelIDType,
			Violation: OmittedViolation,
		}
	}

	// No need to check anything else if features are not provided (bolt 4
	// indicates that omitted features should be treated like an empty
	// vector).
	if blindedData.Features == nil {
		return nil
	}

	// Fail if we don't understand any features (even or odd), because we
	// expect the features to have been set from our announcement.
	if blindedData.Features.UnknownFeatures() {
		return ErrInvalidPayload{
			Type:      record.FeatureVectorType,
			Violation: IncludedViolation,
		}
	}

	return nil
}
