package route

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	sphinx "github.com/lightningnetwork/lightning-onion"
	"github.com/lightningnetwork/lnd/htlcswitch/hop"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/record"
	"github.com/lightningnetwork/lnd/tlv"
)

// VertexSize is the size of the array to store a vertex.
const VertexSize = 33

var (
	// ErrNoRouteHopsProvided is returned when a caller attempts to
	// construct a new sphinx packet, but provides an empty set of hops for
	// each route.
	ErrNoRouteHopsProvided = fmt.Errorf("empty route hops provided")

	// ErrMaxRouteHopsExceeded is returned when a caller attempts to
	// construct a new sphinx packet, but provides too many hops.
	ErrMaxRouteHopsExceeded = fmt.Errorf("route has too many hops")

	// ErrIntermediateMPPHop is returned when a hop tries to deliver an MPP
	// record to an intermediate hop, only final hops can receive MPP
	// records.
	ErrIntermediateMPPHop = errors.New("cannot send MPP to intermediate")

	// ErrAMPMissingMPP is returned when the caller tries to attach an AMP
	// record but no MPP record is presented for the final hop.
	ErrAMPMissingMPP = errors.New("cannot send AMP without MPP record")

	ErrDisjointRouteSegments = errors.New("cannot concatenate disjoint route segments")
)

// Vertex is a simple alias for the serialization of a compressed Bitcoin
// public key.
type Vertex [VertexSize]byte

// NewVertex returns a new Vertex given a public key.
func NewVertex(pub *btcec.PublicKey) Vertex {
	var v Vertex
	copy(v[:], pub.SerializeCompressed())
	return v
}

// NewVertexFromBytes returns a new Vertex based on a serialized pubkey in a
// byte slice.
func NewVertexFromBytes(b []byte) (Vertex, error) {
	vertexLen := len(b)
	if vertexLen != VertexSize {
		return Vertex{}, fmt.Errorf("invalid vertex length of %v, "+
			"want %v", vertexLen, VertexSize)
	}

	var v Vertex
	copy(v[:], b)
	return v, nil
}

// NewVertexFromStr returns a new Vertex given its hex-encoded string format.
func NewVertexFromStr(v string) (Vertex, error) {
	// Return error if hex string is of incorrect length.
	if len(v) != VertexSize*2 {
		return Vertex{}, fmt.Errorf("invalid vertex string length of "+
			"%v, want %v", len(v), VertexSize*2)
	}

	vertex, err := hex.DecodeString(v)
	if err != nil {
		return Vertex{}, err
	}

	return NewVertexFromBytes(vertex)
}

// String returns a human readable version of the Vertex which is the
// hex-encoding of the serialized compressed public key.
func (v Vertex) String() string {
	return fmt.Sprintf("%x", v[:])
}

// Hop represents an intermediate or final node of the route. This naming
// is in line with the definition given in BOLT #4: Onion Routing Protocol.
// The struct houses the channel along which this hop can be reached and
// the values necessary to create the HTLC that needs to be sent to the
// next hop. It is also used to encode the per-hop payload included within
// the Sphinx packet.
//
// NOTE: This can be used for BOTH normal and blinded hops!
type Hop struct {
	// PubKeyBytes is the raw bytes of the public key of the target node.
	//
	// NOTE: For blinded routes this will be the blinded node ID public key, B(i).
	PubKeyBytes Vertex

	// ChannelID is the unique channel ID for the channel by which this hop can be reached.
	// The first 3 bytes are the block height, the next 3 the index within the block,
	// and the last 2 bytes are the output index for the channel.
	ChannelID uint64

	// OutgoingTimeLock is the timelock value that should be used when
	// crafting the _outgoing_ HTLC from this hop.
	OutgoingTimeLock uint32

	// AmtToForward is the amount that this hop will forward to the next
	// hop. This value is less than the value that the incoming HTLC
	// carries as a fee will be subtracted by the hop.
	AmtToForward lnwire.MilliSatoshi

	// MPP encapsulates the data required for option_mpp. This field should
	// only be set for the final hop.
	MPP *record.MPP

	// AMP encapsulates the data required for option_amp. This field should
	// only be set for the final hop.
	AMP *record.AMP

	// CustomRecords if non-nil are a set of additional TLV records that
	// should be included in the forwarding instructions for this node.
	CustomRecords record.CustomSet

	// QUESTION: How should optional vs. required fields be handled?
	// Does it make sense to encapsulate optional + required fields together?
	//
	// HopBlinding encapsulates the data required for option_route_blinding.
	// This field can be set for any hop in the route, but only the first
	// should have a blinding point. Does it make sense to encapsulate this?
	// HopBlinding *record.BlindedHop

	// RouteBlindingEncryptedData is for an intermediate processing (routing) node
	// in the blinded portion of the route.
	RouteBlindingEncryptedData []byte

	// BlindingPoint delivered to the introductory node in the blinded route.
	// NOTE: Could use [33]byte for compressed pubkey and remove btcec dependency.
	BlindingPoint *btcec.PublicKey

	// TODO(7/26/22): This will hold all the information
	// needed to pack a blind hop payload.
	BlindHopPayload hop.BlindHopPayload

	// NOTE(8/25/22): One method of building blinded route payloads.
	MinimumHTLC uint64

	// LegacyPayload if true, then this signals that this node doesn't
	// understand the new TLV payload, so we must instead use the legacy
	// payload.
	LegacyPayload bool

	// Metadata is additional data that is sent along with the payment to
	// the payee.
	Metadata []byte

	// TotalAmountMsat is the total payment amount...
	TotalAmountMsat lnwire.MilliSatoshi
}

// Copy returns a deep copy of the Hop.
func (h *Hop) Copy() *Hop {
	c := *h

	if h.MPP != nil {
		m := *h.MPP
		c.MPP = &m
	}

	if h.AMP != nil {
		a := *h.AMP
		c.AMP = &a
	}

	return &c
}

// PackRouteBlindingPayload writes the series of bytes that can be placed
// directly into the route blinding TLV payload for this hop. This will
// include the required information for relaying payment, as well as any
// constraints meant to be enforced by processing nodes in the blinded route.
// nextChanID is the unique channel ID that references the _outgoing_ channel
// ID that follows this hop. This field follows the same semantics as the
// NextAddress field in the onion: it should be set to zero to indicate the terminal hop.
// TODO(10/26/22): Better explain why we accept the next SCID.
func (h *Hop) PackRouteBlindingPayload(w io.Writer, nextChanID uint64) error {
	// If this is a legacy payload, then we'll exit here as this method
	// shouldn't be called.
	if h.LegacyPayload {
		return fmt.Errorf("cannot pack route blinding payloads " +
			"for legacy payloads")
	}

	p := h.BlindHopPayload

	// Encode route blinding payload as TLV stream.
	var records = []tlv.Record{}

	// NOTE(8/13/22): The following checks ensure that we do not waste
	// bytes on the wire for empty TLV fields.
	// As an example, if we encode a nil slice in our TLV stream we will
	// waste 2 bytes on the type and length (0).
	if p.Padding != nil {
		records = append(records,
			record.NewPaddingRecord(&p.Padding),
		)
	}

	if nextChanID != 0 {
		records = append(records,
			record.NewBlindedNextHopRecord(&nextChanID),
		)
	}

	if p.NextNodeID != nil {
		fmt.Printf("[Packing Route Blinding Payload]: next node ID - %+v\n", p.NextNodeID.SerializeCompressed())
		records = append(records,
			record.NewNextNodeIDRecord(&p.NextNodeID),
		)
	}

	if p.PathID != nil {
		fmt.Printf("[Packing Route Blinding Payload]: next node ID - %+v\n", p.PathID)
		records = append(records, record.NewPathIDRecord(&p.PathID))
	}

	if p.BlindingPointOverride != nil {
		fmt.Printf("[Packing Route Blinding Payload]: blinding point override - %+v\n", p.BlindingPointOverride.SerializeCompressed())
		records = append(records,
			record.NewBlindingOverrideRecord(
				&p.BlindingPointOverride,
			),
		)
	}

	if p.PaymentRelay != nil {
		fmt.Printf("[Packing Route Blinding Payload]: payment relay details - %d\n", p.PaymentRelay)
		records = append(records, p.PaymentRelay.Record())
	}

	if p.PaymentConstraints != nil {
		fmt.Printf("[Packing Route Blinding Payload]: payment constraint details - %d\n", p.PaymentConstraints)
		records = append(records, p.PaymentConstraints.Record())
	}

	tlvStream, err := tlv.NewStream(records...)
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// PackHopPayload writes to the passed io.Writer, the series of bytes that can
// be placed directly into the per-hop payload (EOB) for this hop. This will
// include the required routing fields, as well as serializing any of the
// passed optional TLVRecords.  nextChanID is the unique channel ID that
// references the _outgoing_ channel ID that follows this hop. This field
// follows the same semantics as the NextAddress field in the onion: it should
// be set to zero to indicate the terminal hop.
// NOTE(8/12/22): We might be on the trail for why the nextChanID is passed here.
// Each hop contains the channel ID by which it can be reached. This is in
// contrast to each hop containing the channel ID by which the next hop can be
// reached. What implication does this have? Combine this with the fact that
// the source of a route is NOT included in the list of the route's hops.
func (h *Hop) PackHopPayload(w io.Writer, nextChanID uint64) error {
	// If this is a legacy payload, then we'll exit here as this method
	// shouldn't be called.
	if h.LegacyPayload {
		return fmt.Errorf("cannot pack hop payloads for legacy " +
			"payloads")
	}

	// Otherwise, we'll need to make a new stream that includes our
	// required routing fields, as well as these optional values.
	var records []tlv.Record

	// Every hop must have an amount to forward and CLTV expiry.
	// NOTE(9/8/22): No longer true! This depends on whether this hop is blinded.
	amt := uint64(h.AmtToForward)
	// records = append(records,
	// 	record.NewAmtToFwdRecord(&amt),
	// 	record.NewLockTimeRecord(&h.OutgoingTimeLock),
	// )
	if amt != 0 {
		records = append(records,
			record.NewAmtToFwdRecord(&amt),
		)
	}

	if h.OutgoingTimeLock != 0 {
		records = append(records,
			record.NewLockTimeRecord(&h.OutgoingTimeLock),
		)
	}

	// BOLT 04 says the next_hop_id should be omitted for the final hop,
	// but present for all others.
	//
	// TODO(conner): test using hop.Exit once available
	// NOTE(9/8/22): No longer true! This depends on whether this hop is blinded.
	// nextScid := lnwire.NewShortChanIDFromInt(nextChanID)
	// if nextScid == hop.Exit {
	if nextChanID != 0 {
		records = append(records,
			record.NewNextHopIDRecord(&nextChanID),
		)
	}

	// Routing nodes which support route blinding must have
	// recipient encrypted data which contains the unblinded
	// node to use for forwarding.
	records = append(records,
		record.NewRouteBlindingEncryptedDataRecord(&h.RouteBlindingEncryptedData),
	)

	// Only the first node in a blinded route shall receive
	// an ephemeral blinding point from the recipient.
	// TODO (3/26/22): validate that this is only set for such
	// nodes somewhere.
	if h.BlindingPoint != nil {
		records = append(records,
			record.NewBlindingPointRecord(&h.BlindingPoint),
		)
	}

	// If an MPP record is destined for this hop, ensure that we only ever
	// attach it to the final hop. Otherwise the route was constructed
	// incorrectly.
	if h.MPP != nil {
		if nextChanID == 0 {
			records = append(records, h.MPP.Record())
		} else {
			return ErrIntermediateMPPHop
		}
	}

	// If an AMP record is destined for this hop, ensure that we only ever
	// attach it if we also have an MPP record. We can infer that this is
	// already a final hop if MPP is non-nil otherwise we would have exited
	// above.
	if h.AMP != nil {
		if h.MPP != nil {
			records = append(records, h.AMP.Record())
		} else {
			return ErrAMPMissingMPP
		}
	}

	// If metadata is specified, generate a tlv record for it.
	if h.Metadata != nil {
		records = append(records,
			record.NewMetadataRecord(&h.Metadata),
		)
	}

	if h.TotalAmountMsat != 0 {
		totalAmtMsat := uint64(h.TotalAmountMsat)
		records = append(records,
			record.NewTotalAmountMsatRecord(&totalAmtMsat),
		)
	}

	// If total_amount_msat is specified, generate a tlv record for it.
	totalAmt := uint64(h.TotalAmountMsat)
	records = append(records,
		record.NewTotalAmountMsatRecord(&totalAmt),
	)

	// Append any custom types destined for this hop.
	tlvRecords := tlv.MapToRecords(h.CustomRecords)
	records = append(records, tlvRecords...)

	// To ensure we produce a canonical stream, we'll sort the records
	// before encoding them as a stream in the hop payload.
	tlv.SortRecords(records)

	tlvStream, err := tlv.NewStream(records...)
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Size returns the total size this hop's payload would take up in the onion
// packet.
func (h *Hop) PayloadSize(nextChanID uint64) uint64 {
	if h.LegacyPayload {
		return sphinx.LegacyHopDataSize
	}

	var payloadSize uint64

	addRecord := func(tlvType tlv.Type, length uint64) {
		payloadSize += tlv.VarIntSize(uint64(tlvType)) +
			tlv.VarIntSize(length) + length
	}

	// Add amount size.
	addRecord(record.AmtOnionType, tlv.SizeTUint64(uint64(h.AmtToForward)))

	// Add lock time size.
	addRecord(
		record.LockTimeOnionType,
		tlv.SizeTUint64(uint64(h.OutgoingTimeLock)),
	)

	// Add next hop if present.
	if nextChanID != 0 {
		addRecord(record.NextHopOnionType, 8)
	}

	// Add mpp if present.
	if h.MPP != nil {
		addRecord(record.MPPOnionType, h.MPP.PayloadSize())
	}

	// Add amp if present.
	if h.AMP != nil {
		addRecord(record.AMPOnionType, h.AMP.PayloadSize())
	}

	// Add metadata if present.
	if h.Metadata != nil {
		addRecord(record.MetadataOnionType, uint64(len(h.Metadata)))
	}

	// Add route blinding parameters if present.
	if h.BlindingPoint != nil {
		addRecord(record.BlindingPointOnionType, 33)
	}

	if h.RouteBlindingEncryptedData != nil {
		addRecord(record.RouteBlindingEncryptedDataOnionType, uint64(len(h.RouteBlindingEncryptedData)))
	}

	// Add custom records.
	for k, v := range h.CustomRecords {
		addRecord(tlv.Type(k), uint64(len(v)))
	}

	// Add the size required to encode the payload length.
	payloadSize += tlv.VarIntSize(payloadSize)

	// Add HMAC.
	payloadSize += sphinx.HMACSize

	return payloadSize
}

// Route represents a path through the channel graph which runs over one or
// more channels in succession. This struct carries all the information
// required to craft the Sphinx onion packet, and send the payment along the
// first hop in the path. A route is only selected as valid if all the channels
// have sufficient capacity to carry the initial payment amount after fees are
// accounted for.
//
// TODO (3/26/22): How does this change for routes with blinded hops?
// The hops are blinded from the perspective of the sender as we have
// delegated a portion of the route construction to the recipient.
//
// UPDATE (3/30/22): It looks like the top level struct may be able to
// remain unchanged, with the details of route blinding confined to the
// Hops within the route. Pathfinding will need to target the 'introduction'
// node rather than the terminal node which will be blinded and not locatable
// in the public graph.
//
// UPDATE (4/17/22): I still agree with the comment above.
type Route struct {
	// TotalTimeLock is the cumulative (final) time lock across the entire
	// route. This is the CLTV value that should be extended to the first
	// hop in the route. All other hops will decrement the time-lock as
	// advertised, leaving enough time for all hops to wait for or present
	// the payment preimage to complete the payment.
	TotalTimeLock uint32

	// TotalAmount is the total amount of funds required to complete a
	// payment over this route. This value includes the cumulative fees at
	// each hop. As a result, the HTLC extended to the first-hop in the
	// route will need to have at least this many satoshis, otherwise the
	// route will fail at an intermediate node due to an insufficient
	// amount of fees.
	TotalAmount lnwire.MilliSatoshi

	// SourcePubKey is the pubkey of the node where this route originates
	// from.
	// NOTE: If this SourcePubKey is not ourselves then we have a route segment
	// with a different source node. Such is expected when handling blinded routes.
	SourcePubKey Vertex

	// Hops contains details concerning the specific forwarding details at
	// each hop.
	//
	// NOTE
	Hops []*Hop
}

// NOTE: I do not think we will need something like this.
// Each 'Hop' can carry the neccessary data whether the hop
// is part of a regular or blinded route.
// type BlindedRoute struct {
// 	FirstLeg Route
// 	SecondLeg BlindedRoute
// }

// Copy returns a deep copy of the Route.
func (r *Route) Copy() *Route {
	c := *r

	c.Hops = make([]*Hop, len(r.Hops))
	for i := range r.Hops {
		c.Hops[i] = r.Hops[i].Copy()
	}

	return &c
}

// HopFee returns the fee charged by the route hop indicated by hopIndex.
func (r *Route) HopFee(hopIndex int) lnwire.MilliSatoshi {
	var incomingAmt lnwire.MilliSatoshi
	if hopIndex == 0 {
		incomingAmt = r.TotalAmount
	} else {
		incomingAmt = r.Hops[hopIndex-1].AmtToForward
	}

	// Fee is calculated as difference between incoming and outgoing amount.
	return incomingAmt - r.Hops[hopIndex].AmtToForward
}

// TotalFees is the sum of the fees paid at each hop within the final route. In
// the case of a one-hop payment, this value will be zero as we don't need to
// pay a fee to ourself.
func (r *Route) TotalFees() lnwire.MilliSatoshi {
	if len(r.Hops) == 0 {
		return 0
	}

	return r.TotalAmount - r.ReceiverAmt()
}

// ReceiverAmt is the amount received by the final hop of this route.
func (r *Route) ReceiverAmt() lnwire.MilliSatoshi {
	if len(r.Hops) == 0 {
		return 0
	}

	return r.Hops[len(r.Hops)-1].AmtToForward
}

// FinalHop returns the last hop of the route, or nil if the route is empty.
func (r *Route) FinalHop() *Hop {
	if len(r.Hops) == 0 {
		return nil
	}

	return r.Hops[len(r.Hops)-1]
}

func NewRoute(hops []*btcec.PublicKey) (*Route, error) {
	return nil, nil
}

// Does this add coupling between routing/sphinx package?
// Is such coupling/dependence necessary? Is it even something to worry about?
func FromSphinxRoute(blind *sphinx.BlindedPath, amtToSend lnwire.MilliSatoshi, timeLock uint32) (*Route, error) {
	// func FromSphinxRoute(blind *sphinx.BlindedRoute, amtToSend lnwire.MilliSatoshi, timeLock uint32) (*Route, error) {

	var hops []*Hop

	// Process introduction node
	// first := blind.BlindedHops[0]
	// first := blind.BlindedNodes[0]
	intro := &Hop{
		PubKeyBytes:                NewVertex(blind.IntroductionPoint),
		BlindingPoint:              blind.BlindingPoint,
		RouteBlindingEncryptedData: blind.EncryptedData[0],
		// BlindingPoint:          first.EphemeralBlindingPoint,
		// RouteBlindingEncryptedData: first.EncryptedData,
	}
	hops = append(hops, intro)
	blind.BlindedHops = blind.BlindedHops[1:]
	// blind.BlindedNodes = blind.BlindedNodes[1:]

	// Convert blinded hops to our routing package hop.
	// TODO(5/1/22): We likely need more info for each hop.
	// Review the route blinding spec for payments.
	for i, hop := range blind.BlindedHops {
		// for _, hop := range blind.BlindedNodes {
		h := &Hop{
			PubKeyBytes:                NewVertex(hop),
			RouteBlindingEncryptedData: blind.EncryptedData[i],
			// NOTE (5/1/22): The following fields are assumed to be set.
			// How are they set for blinded hops?
			// This will not be set to any meaningful value for blinded
			// hops as they are to uncover the channel ID over which to
			// forward via the encrypted payload left by the recipient.
			// ChannelID: 0,
			// OutgoingTimeLock: 0,
		}
		hops = append(hops, h)
	}

	route := &Route{
		SourcePubKey:  NewVertex(blind.IntroductionPoint),
		Hops:          hops,
		TotalTimeLock: timeLock,
		TotalAmount:   amtToSend,
	}

	return route, nil
}

// NewRouteFromHops creates a new Route structure from the minimally required
// information to perform the payment. It infers fee amounts and populates the
// node, chan and prev/next hop maps.
//
// NOTE (Route Blinding): The route will contain a sequence of persistent
// node ID keys followed by a sequence of blinded node ID keys
// representing the blinded portion of the route.
func NewRouteFromHops(amtToSend lnwire.MilliSatoshi, timeLock uint32,
	sourceVertex Vertex, hops []*Hop) (*Route, error) {

	if len(hops) == 0 {
		return nil, ErrNoRouteHopsProvided
	}

	// First, we'll create a route struct and populate it with the fields
	// for which the values are provided as arguments of this function.
	// TotalFees is determined based on the difference between the amount
	// that is send from the source and the final amount that is received
	// by the destination.
	route := &Route{
		SourcePubKey:  sourceVertex,
		Hops:          hops,
		TotalTimeLock: timeLock,
		TotalAmount:   amtToSend,
	}

	return route, nil
}

// Extend an existing route with additional hops.
func (r *Route) ExtendRoute(extension *Route) *Route {

	if extension == nil {
		return r
	}

	route := r.Copy()

	// Route builders/onion encryptors will accept on faith that a
	// blinded route is well formed. If the blinded route is malformed,
	// then surely they will encounter an error when they attempt to send
	// a payment using the blinded route.
	// route.Hops = append(r.Hops, hops...)
	route.Hops = append(r.Hops, extension.Hops...)

	// TODO (4/17/22): Figure out how to handle amount, fees, timelock when
	// extending the route. Might be okay to leave as is?
	return route
}

// Extend an existing route with additional hops.
// NOTE: Used for route blinding.
// TODO (4/27/22): write a unit test for this since
// it seems simple enough to do.
func (r *Route) ExtendRouteWithHops(hops []*Hop) *Route {

	if hops == nil {
		return r
	}

	route := r.Copy()

	// Route builders/onion encryptors will accept on faith that a
	// blinded route is well formed. If the blinded route is malformed,
	// then surely they will encounter an error when they attempt to send
	// a payment using the blinded route.
	route.Hops = append(r.Hops, hops...)

	// TODO (4/17/22): Figure out how to handle amount, fees, timelock when
	// extending the route. Might be okay to leave as is?
	return route
}

/*

	CONVENTION: Does our route extension include the introduction node?
	If so then it should overlap with the last hop of the first route segment.
	This sounds like a distinctly blinded route concept rather than a more
	general thing which should be done for normal routes.

	- Should we blindly append hops? The only way to verify that the
	  first hop in the second route segment actually connects with the
	  last hop in the first route segment is to consult the network graph.
	  Is checking the graph necessary or can we just attempt the route in
	  good raith and handle errors if they come up?

	In general I see little point in handling overlapping route segments.
	While the overlap allows us to verify that the second route segment has
	some relationship to the first, it does not guarantee that the rest of the
	second route segment is validly connected.
	(A, B, C) + (C, D, E)
	(A, B, C) + (C, D, E) = (A, B, C, C, D, E) (NOTE: This is NOT what we want)

	(A, B, C) + (D, E) = (A, B, C, D, E)

	Blinded Route:
	(A, B, Rendezvous/Intro) + (Rendezvous/Intro, D, E) = (A, B, Rendezvous/Intro, D, E)
	Could we do this for blinded routes?
	(A, B, Rendezvous/Intro) + (info to append to last hop of first segment, D, E) =
	(A, B, Rendezvous/Intro w/ appended info, D, E)

	Is there any merit to a general route extending function? Maybe not.
	It seems the only current use would be route blinding so perhaps the method
	should explicitly indicate such - (ie: route.AddBlindExtension())

*/

// TODO(7/22/22): I think this is slightly off. Write a unit test.
func (r *Route) AddBlindExtension(amt lnwire.MilliSatoshi, finalCltv uint32, blindRoute *sphinx.BlindedPath) (*Route, error) {
	// func (r *Route) AddBlindExtension(blindRoute *sphinx.BlindedPath) (*Route, error) {
	// func (r *Route) AddBlindExtension(blindRoute *sphinx.BlindedRoute) (*Route, error) {

	// var err error
	// if len(blindRoute.BlindedNodes) == 0 { return r, err}
	// if blindRoute.IntroductionNode.EphemeralBlindingPoint == nil { return r, err }
	// if blindRoute.IntroductionNode.EncryptedData == nil { return r, err }
	if len(blindRoute.BlindedHops) < 1 { // < 2 since first hop isnt even blinded?
		return r, errors.New("attempting to add empty blind route extension")
	}
	if len(blindRoute.BlindedHops) != len(blindRoute.EncryptedData) {
		return r, fmt.Errorf("every hop in blinded route must have a payload. "+
			"hops: %d, payloads: %d", len(blindRoute.BlindedHops), len(blindRoute.EncryptedData))
	}
	if blindRoute.BlindingPoint == nil {
		return r, errors.New("first node in blinded route MUST have blinding point")
	}
	if blindRoute.EncryptedData[0] == nil {
		return r, errors.New("first node in blinded route MUST have encrypted route blinding payload")
	}

	route := r.Copy()
	var hops []*Hop

	// Process introduction node
	// first := blindRoute.BlindedNodes[0]
	// introNode := blindRoute.IntroductionNode
	// introVertex := NewVertex(introNode.PublicKey)
	// introNode := blindRoute.IntroductionNode
	introVertex := NewVertex(blindRoute.IntroductionPoint)

	if lastHop := route.FinalHop(); lastHop != nil {
		if introVertex != lastHop.PubKeyBytes {
			return nil, fmt.Errorf("unable to extend route. route segments disjoint. "+
				"last: %v, first: %v", [33]byte(lastHop.PubKeyBytes), [33]byte(introVertex))
		}
	}

	// intro := &Hop{
	// 	PubKeyBytes:            NewVertex(introNode.PublicKey),
	// 	BlindingPoint:          introNode.EphemeralBlindingPoint,
	// 	RouteBlindingEncryptedData: introNode.EncryptedData,
	// }

	// Verify that info has been added for introduction node.
	introNode := route.FinalHop()
	// introNode.BlindingPoint = introNode.EphemeralBlindingPoint
	// introNode.RouteBlindingEncryptedData = introNode.EncryptedData
	introNode.BlindingPoint = blindRoute.BlindingPoint
	introNode.RouteBlindingEncryptedData = blindRoute.EncryptedData[0]

	// NOTE(9/10/22): According to the spec these MUST be empty
	// for all nodes in a blinded route, including the introduction node.
	introNode.AmtToForward = 0
	introNode.OutgoingTimeLock = 0

	// hops = append(hops, introNode)
	hops = append(hops, route.Hops...)

	// hops = append(hops, intro)
	// blindRoute.BlindedNodes = blindRoute.BlindedNodes[1:]

	// NOTE: This includes the introduction node. Be sure not to double count it!
	for i := 1; i < len(blindRoute.BlindedHops); i++ {
		// for i, hop := range blindRoute.BlindedHops {
		// for _, hop := range blindRoute.BlindedNodes[1:] {
		// for _, hop := range blindRoute.BlindedNodes {
		// hops = append(hops, &Hop{
		// 	// route.Hops = append(route.HoŹs, &Hop{
		// 	// PubKeyBytes:            NewVertex(hop.BlindedPublicKey),
		// 	// RouteBlindingEncryptedData: hop.EncryptedData,
		// 	PubKeyBytes:            NewVertex(blindRoute.BlindedHops[i]),
		// 	RouteBlindingEncryptedData: blindRoute.EncryptedData[i],
		// 	// TotalAmountMsat:        r.TotalAmount,
		// 	// NOTE (5/1/22): The following fields are assumed to be set.
		// 	// How are they set for blinded hops?
		// 	// ChannelID: 0,
		// 	// OutgoingTimeLock: 0,
		// })
		h := &Hop{
			PubKeyBytes:                NewVertex(blindRoute.BlindedHops[i]),
			RouteBlindingEncryptedData: blindRoute.EncryptedData[i],
		}

		// NOTE(9/10/22): According to the spec, we MUST set the
		// amt_to_forward & outgoing_cltv_value for the final node
		// in a blinded route.
		// The last hop should have the total amount.
		if i == len(blindRoute.BlindedHops)-1 {
			// h.AmtToForward = r.TotalAmount
			// h.AmtToForward = route.FinalHop().AmtToForward
			h.AmtToForward = amt
			h.OutgoingTimeLock = finalCltv
			h.TotalAmountMsat = amt
			fmt.Printf("[AddBlindExtension]: last hop info: %+v\n", h)
		}
		fmt.Printf("[AddBlindExtension]: hop info: %+v\n", h)

		hops = append(hops, h)
	}

	route.Hops = hops
	return route, nil
}

// Extend an existing route with additional hops. This method is more strict
// in that it verifies that the route segments are not disjoint (ie: they connect).
func (r *Route) ExtendRouteStrict(routeExtension *Route) (*Route, error) {

	if routeExtension == nil {
		return r, fmt.Errorf("route extension is nil")
	}

	route := r.Copy()

	// TODO (4/22): validate that routes fit together like a puzzle piece?
	// The last hop of the first route should match the first hop of the
	// route extension, otherwise the route is discontinuous.
	// QUESTION: Should you able to extend an empty route with a non-empty route?
	// This would be a case where the last hop/first hop public keys do not match.
	//
	// NOTE: Even when extending with a blinded route this still works
	// as the first hop of a blinded route is the "introduction node"
	// which contains an unblinded node ID public key.
	// if r.Hops[-1].PubKeyBytes != hops[0].PubKeyBytes {}
	if lastHop := r.FinalHop(); lastHop != nil {
		if routeExtension.SourcePubKey != lastHop.PubKeyBytes {
			return nil, fmt.Errorf("unable to extend route. route segments disjoint. "+
				"last: %v, first: %v", lastHop.PubKeyBytes, routeExtension.SourcePubKey)
			// return nil, ErrDisjointRouteSegments
		}
	}

	// // Is the route source included in the list of hops?
	// // Should it be?
	// if firstHop := r.Hops[0]; firstHop != nil {
	// 	if r.SourcePubKey != firstHop.PubKeyBytes {
	// 		return nil, fmt.Errorf("route source not included in hops. "+
	// 			"source: %v, first: %v", r.SourcePubKey, firstHop.PubKeyBytes)
	// 	}
	// }

	// Route builders/onion encryptors will accept on faith that a
	// blinded route is well formed. If the blinded route is malformed,
	// then surely they will encounter an error when they attempt to send
	// a payment using the blinded route.
	// route.Hops = append(r.Hops, hops...)
	route.Hops = append(r.Hops, routeExtension.Hops...)

	// TODO (4/17/22): Figure out how to handle amount, fees, timelock when
	// extending the route. Might be okay to leave as is?
	return route, nil
}

/*

	Current: routing.Route --> sphinx.PaymentPath => NewOnion()
	Blinded Route (test as of 4/22): sphinx.BlindRoute (or alternatively its raw constituent types:
		PublicKey, []byte) --> routing.Route --> routing.Route.Extend() --> sphinx.PaymentPath
		=> NewOnion()

	Blinded Route (w/ data from invoice): Raw route blinding constituent types:
	    (PublicKey, []byte) --> routing.Route --> routing.Route.Extend() --> sphinx.PaymentPath => NewOnion()

	We would like to avoid converting from a sphinx package type (BlindRoute)
	to a routing package type (Route) only to then convert the entire
	Route back to a sphinx package type (PaymentPath) in order to create an onion.
	QUESTION: (Why) Is avoiding this desirable?

	- Is the Sphinx package the appropriate place to define the route blinding
	  functionality? It does seem to have many of the crypto functions we need
	  already defined.


*/
type thingWithHops interface {
	Hops() []*Hop
}

func ParseRoute(thing thingWithHops) (*Route, error) {

	return NewRouteFromHops(10, 10, Vertex{}, thing.Hops())
}

// 	NewRouteFromHops(amtToSend lnwire.MilliSatoshi, timeLock uint32, sourceVertex Vertex, hops []*Hop)
// }

func CombineRoutes(r1, r2 *Route) *Route {
	var combinedRoute *Route

	// TODO: validate that routes fit together like a puzzle piece.
	combinedRoute.Hops = append(r1.Hops, r2.Hops...)

	return combinedRoute
}

// type RouteBlindingParams struct {
// 	RouteExpiration uint32
// }

// // Blind computes the outgoing cltv, fees, minimum htlc values
// // taking into account the whole route.
// //
// // To be used by recipients when creating blinded routes.
// func (r *Route) Blind() (*BlindRoute, error) {
// 	params := &RouteBlindingParams{
// 		RouteExpiration: 0, // block height after which this blinded
// 		// route should no longer work
// 		// ...
// 	}

// 	// Generate an ephemeral key to be used for this blinded route.
// 	// NOTE(8/14/22): Do we need to persist the session key we use
// 	// to build the blinded route? The session key can be used to
// 	// recompute the the ephemeral blinding points, blind node IDs
// 	// as long as we also save the path.
// 	sessionKey, err := routing.GenerateNewSessionKey()
// 	if err != nil {
// 		return nil, err
// 	}

// 	hopsToBeBlinded, aggregateRouteParams, err := r.ToSphinxBlindPath2(params)
// 	// hopsToBeBlinded, err := r.ToSphinxBlindPath()
// 	if err != nil {
// 		return nil, err
// 	}

// 	// Actually build the blinded route (ie: blind the public keys and
// 	// encrypt the route blinding payloads).
// 	blindRoute, err := sphinx.BuildBlindedPath(sessionKey, hopsToBeBlinded)

// 	// Provide types which encapsulate the information which
// 	// must be shared with senders.
// 	return &BlindRoute{
// 		blindRoute,
// 		*aggregateRouteParams,
// 	}, nil
// }

// // BlindRoute represents a completed blinded route. That is a path or collection
// // of public keys along with the amount/fee/timelock information. A sender
// // attempting to make payment to a BlindRoute will not have access to forwarding
// // information within the blind route. This information is intentionally opaque
// // from the sender's perspective. They will instead rely on both fee & timelock
// // information which has been aggregated across the route.
// // in addition to the aggregate (sum total)
// // This struct contains all the information which must be provided to a sender
// // in order to make payments to a blinded route.
// type BlindRoute struct {
// 	*sphinx.BlindedPath
// 	BlindRouteAggregate
// }

// type BlindRouteAggregate struct {
// 	AggregateFee      uint64
// 	AggregateTimeLock uint64
// 	Hops              []*sphinx.BlindedPathHop
// }

// func (r *Route) ToSphinxBlindPath2(params *RouteBlindingParams) ([]*sphinx.BlindedPathHop, *BlindRouteAggregate, error) {
// 	return nil, nil, nil
// }

type BlindRoutePaymentParams struct {
	BaseFee         uint32
	FeeRate         uint32
	MinHtlc         uint64
	CltvDelta       uint16
	RouteCltvExpiry uint32
}

type AggregateRouteParams struct {
	AggregateBaseFee  uint64
	AggregateFeeRate  uint64
	AggregateTimeLock uint32
	Hops              []*sphinx.BlindedPathHop
}

type BlindPayment struct {
	BlindRoute *Route
	BlindRoutePaymentParams
	AggregateRouteParams
}

// ToSphinxBlindPath converts a route (QUESTION 7/24/22 - does this need to be a path,
// ie: WITHOUT all the amount/fee & timelock information computed?) to a set of hops
// which can be used in the route blinding scheme specified in BOLT-04.
// Each hop in a blinded route will contain a "route blinding" TLV payload which
// contains information on how an HTLC is to be forwarded.
// NOTE(7/23/22): I think this should be used by recipients
// when creating a blinded route.
func (r *Route) ToSphinxBlindPath() ([]*sphinx.BlindedPathHop, error) {

	// We can only construct a route if there are hops provided.
	if len(r.Hops) == 0 {
		return nil, ErrNoRouteHopsProvided
	}

	// Check maximum route length.
	if len(r.Hops) > sphinx.NumMaxHops {
		return nil, ErrMaxRouteHopsExceeded
	}

	/*
		Compute payment relay parameters
		- base fee + safety margin (protect against changes to channel policy along blinded route)
		- fee rate + safety margin
		- max(cltv_expiry_delta)
		- max(htlc_min)

		Sum the parameters along the blinded portion of the route.

		routeFeeBaseMsat
		routeFeeProportionalMillionths
		routeCltvExpiryDelta

		NOTE: In order to determine the above, we will need to
		pre-process the path as we need information from each hop.

	*/
	var blindedRouteExpiry uint32 = 1000
	computeAggregateRouteParams := func() (uint32, uint32, uint16, uint64) {
		var base, rate uint32 = 10000, 0
		var maxCltvDelta, cltvDelta uint16 = 0, 40
		var minHtlc, maxSmallestHtlc uint64

		// QUESTION(8/14/22): Do we need the introduction node in
		// this calculation? Also, I am not sure we have access to info
		// on minimum HTLC size here currently.
		// Determine some sensible baseline.
		for _, hop := range r.Hops {
			fmt.Printf("[computeAggregateRouteParams]: hop info: %+v\n", hop)
			// hop.
			minHtlc = 0
			if minHtlc > maxSmallestHtlc {
				maxSmallestHtlc = minHtlc
			}
			if cltvDelta > maxCltvDelta {
				maxCltvDelta = cltvDelta
			}
		}

		// Add additional margin which will allow the route to be used
		// even under a scenario where routing nodes modify their
		// forwarding paramaters.
		//
		// As a sensible default we will double the largest value (100% margin).
		var safetyMargin uint32 = 2
		base = base * safetyMargin
		rate = rate * safetyMargin

		// Compute aggregate route parameters. These will need to be
		// communicated to senders so that they know by how much
		// their route to the introduction node needs to be offset
		// such that the payment can successfully transit the blinded
		// portion of the route.
		// routeFeeBase =
		// routeFeeRate =
		// routeCltvDelta := maxCltvDelta * uint16(len(r.Hops))

		fmt.Printf("[computeAggregateRouteParams]:\n\tbase: %d\n\trate: %d\n\tcltv delta: %d\n\tsmallest htlc: %d\n",
			base, rate, cltvDelta, maxSmallestHtlc)
		return base, rate, cltvDelta, maxSmallestHtlc
	}
	// r.Blind()
	// Alice will receive this information from the recipient.
	// base, rate, maxTimelock, maxSmallestHtlc := r.Blind()
	base, rate, cltv, maxSmallestHtlc := computeAggregateRouteParams()

	// NOTE(7/23/22): sphinx.BlindedPathHop is used for building a blinded route.
	// sphinx.BlindedPath is the completed blind route.
	var blindedPath []*sphinx.BlindedPathHop
	blindedPath = make([]*sphinx.BlindedPathHop, 0, len(r.Hops)+1)
	fmt.Printf("[ToSphinxBlindPath]: creating blind path for route w/ %d hops + intro node.\n", len(r.Hops))
	fmt.Printf("[ToSphinxBlindPath]: introduction node: %s.\n", r.SourcePubKey.String())
	fmt.Printf("[ToSphinxBlindPath]: initial blind hop slice: %+v\n", blindedPath)

	introHop := &Hop{
		PubKeyBytes: r.SourcePubKey,
	}

	// Prepend the introduction node to our list of hops in the route.
	blindHops := append([]*Hop{introHop}, r.Hops...)
	pathLength := len(blindHops)

	// For each hop encoded within the route, we'll convert the hop struct
	// to a BlindPathHop with matching per-hop payload within the path as
	// used by the sphinx package.
	// NOTE(9/11/22): We may want to iterate in reverse to interatively
	// build up timelock as seen in newRoute().
	var h *Hop
	// Working backwards from final hop (recipient) to inroduction node,
	// we'll construct a route blinding payload for each hop in the blinded route.
	for i := pathLength - 1; i >= 0; i-- {

		h = blindHops[i]
		pub, err := btcec.ParsePubKey(h.PubKeyBytes[:])
		if err != nil {
			return nil, err
		}

		// Construct a basic route blinding payload.
		computePadding := func() []byte {
			return []byte{0, 0, 0, 0}
		}
		h.BlindHopPayload = hop.BlindHopPayload{
			// We pad each hop of the blinded route such that all
			// route blinding TLV payloads will be of equal length.
			// NOTE(9/11/22): This means we need, first, to assemble
			// all the BlindHopPayload{}'s and then, in a secondary
			// stage of processing, compute how much padding is needed at each hop.
			Padding: computePadding(),
			PathID:  h.BlindHopPayload.PathID,
			// We'll set constraints on the payment for each node
			// in the blinded route.
			PaymentConstraints: &record.PaymentConstraints{
				// TODO(9/11/22): MaxCltvExpiry needs to change with every hop.
				MaxCltvExpiryDelta: blindedRouteExpiry,
				HtlcMinimumMsat:    maxSmallestHtlc,
				AllowedFeatures:    []byte{},
			},
		}

		// As a base case, the next hop is set to all zeroes in order
		// to indicate that the "last hop" as no further hops after it.
		nextHop := uint64(0)

		// If we aren't on the last hop, then we set the "next address"
		// field to be the channel that directly follows it.
		if i != pathLength-1 {
			nextHop = blindHops[i+1].ChannelID
			// Only set short_channel_id (next hop) an payment relay for intermediate hops.
			// Don't set short_channel_id (next hop) or payment relay for final hop.
			h.BlindHopPayload.PaymentRelay = &record.PaymentRelay{
				BaseFee:         base,
				FeeRate:         rate,
				CltvExpiryDelta: cltv,
			}
		}
		if i == 0 {
			fmt.Printf("[ToSphinxBlindPath]: blind hop slice: %+v\n", blindedPath)
			fmt.Printf("[ToSphinxBlindPath]: intro hop's next hop %+v\n", nextHop)
		}

		fmt.Printf("[ToSphinxBlindPath]: hop %d's next hop %+v\n", i, nextHop)

		// b.Reset()
		var b bytes.Buffer
		// QUESTION(10/26/22): Why is this not in the
		// htlcswitch/hop package?
		err = h.PackRouteBlindingPayload(&b, nextHop)
		if err != nil {
			return nil, err
		}

		// Since we're traversing the path backwards atm, we prepend
		// each new blind hop such that, the final slice of hops will be
		// in the proper order.
		blindedPath = append([]*sphinx.BlindedPathHop{
			{
				NodePub: pub,
				Payload: b.Bytes(),
			},
		}, blindedPath...)

		// We'll increment the absolute block height at which we
		// expect our blinded route to be treated as expired by
		// processing nodes. Doing this avoids leaking information?
		blindedRouteExpiry += uint32(cltv)

	}

	return blindedPath, nil
}

// NOTE(7/23/22): I think this can be used by senders when paying to
// a blinded route.
// ToSphinxPath converts a complete route into a sphinx PaymentPath that
// contains the per-hop paylods used to encoding the HTLC routing data for each
// hop in the route. This method also accepts an optional EOB payload for the
// final hop.
func (r *Route) ToSphinxPath() (*sphinx.PaymentPath, error) {
	var path sphinx.PaymentPath

	// We can only construct a route if there are hops provided.
	if len(r.Hops) == 0 {
		return nil, ErrNoRouteHopsProvided
	}

	// Check maximum route length.
	if len(r.Hops) > sphinx.NumMaxHops {
		return nil, ErrMaxRouteHopsExceeded
	}

	// For each hop encoded within the route, we'll convert the hop struct
	// to an OnionHop with matching per-hop payload within the path as used
	// by the sphinx package.
	for i, hop := range r.Hops {
		pub, err := btcec.ParsePubKey(hop.PubKeyBytes[:])
		if err != nil {
			return nil, err
		}

		// As a base case, the next hop is set to all zeroes in order
		// to indicate that the "last hop" as no further hops after it.
		nextHop := uint64(0)

		// If we aren't on the last hop, then we set the "next address"
		// field to be the channel that directly follows it.
		if i != len(r.Hops)-1 {
			nextHop = r.Hops[i+1].ChannelID
		}

		var payload sphinx.HopPayload

		// If this is the legacy payload, then we can just include the
		// hop data as normal.
		if hop.LegacyPayload {
			// Before we encode this value, we'll pack the next hop
			// into the NextAddress field of the hop info to ensure
			// we point to the right now.
			hopData := sphinx.HopData{
				ForwardAmount: uint64(hop.AmtToForward),
				OutgoingCltv:  hop.OutgoingTimeLock,
			}
			binary.BigEndian.PutUint64(
				hopData.NextAddress[:], nextHop,
			)

			payload, err = sphinx.NewHopPayload(&hopData, nil)
			if err != nil {
				return nil, err
			}
		} else {
			// For non-legacy payloads, we'll need to pack the
			// routing information, along with any extra TLV
			// information into the new per-hop payload format.
			// We'll also pass in the chan ID of the hop this
			// channel should be forwarded to so we can construct a
			// valid payload.
			//
			// NOTE: This is where we create the TLV payload.
			// Make sure it includes the new route blinding fields.
			var b bytes.Buffer
			err := hop.PackHopPayload(&b, nextHop)
			if err != nil {
				return nil, err
			}

			// TODO(roasbeef): make better API for NewHopPayload?
			payload, err = sphinx.NewHopPayload(nil, b.Bytes())
			if err != nil {
				return nil, err
			}
		}

		path[i] = sphinx.OnionHop{
			NodePub:    *pub,
			HopPayload: payload,
		}
	}

	return &path, nil
}

// String returns a human readable representation of the route.
func (r *Route) String() string {
	var b strings.Builder

	amt := r.TotalAmount
	for i, hop := range r.Hops {
		if i > 0 {
			b.WriteString(" -> ")
		}
		b.WriteString(fmt.Sprintf("%v (%v)",
			strconv.FormatUint(hop.ChannelID, 10),
			amt,
		))
		amt = hop.AmtToForward
	}

	return fmt.Sprintf("%v, cltv %v",
		b.String(), r.TotalTimeLock,
	)
}
