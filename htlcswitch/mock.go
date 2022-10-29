package htlcswitch

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/wire"
	"github.com/go-errors/errors"
	sphinx "github.com/lightningnetwork/lightning-onion"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/clock"
	"github.com/lightningnetwork/lnd/contractcourt"
	"github.com/lightningnetwork/lnd/htlcswitch/hop"
	"github.com/lightningnetwork/lnd/invoices"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnpeer"
	"github.com/lightningnetwork/lnd/lntest/mock"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/ticker"
)

func isAlias(scid lnwire.ShortChannelID) bool {
	return scid.BlockHeight >= 16_000_000 && scid.BlockHeight < 16_250_000
}

type mockPreimageCache struct {
	sync.Mutex
	preimageMap map[lntypes.Hash]lntypes.Preimage
}

func newMockPreimageCache() *mockPreimageCache {
	return &mockPreimageCache{
		preimageMap: make(map[lntypes.Hash]lntypes.Preimage),
	}
}

func (m *mockPreimageCache) LookupPreimage(
	hash lntypes.Hash) (lntypes.Preimage, bool) {

	m.Lock()
	defer m.Unlock()

	p, ok := m.preimageMap[hash]
	return p, ok
}

func (m *mockPreimageCache) AddPreimages(preimages ...lntypes.Preimage) error {
	m.Lock()
	defer m.Unlock()

	for _, preimage := range preimages {
		m.preimageMap[preimage.Hash()] = preimage
	}

	return nil
}

func (m *mockPreimageCache) SubscribeUpdates(
	chanID lnwire.ShortChannelID, htlc *channeldb.HTLC,
	payload *hop.Payload,
	nextHopOnionBlob []byte) (*contractcourt.WitnessSubscription, error) {

	return nil, nil
}

type mockFeeEstimator struct {
	byteFeeIn chan chainfee.SatPerKWeight
	relayFee  chan chainfee.SatPerKWeight

	quit chan struct{}
}

func newMockFeeEstimator() *mockFeeEstimator {
	return &mockFeeEstimator{
		byteFeeIn: make(chan chainfee.SatPerKWeight),
		relayFee:  make(chan chainfee.SatPerKWeight),
		quit:      make(chan struct{}),
	}
}

func (m *mockFeeEstimator) EstimateFeePerKW(
	numBlocks uint32) (chainfee.SatPerKWeight, error) {

	select {
	case feeRate := <-m.byteFeeIn:
		return feeRate, nil
	case <-m.quit:
		return 0, fmt.Errorf("exiting")
	}
}

func (m *mockFeeEstimator) RelayFeePerKW() chainfee.SatPerKWeight {
	select {
	case feeRate := <-m.relayFee:
		return feeRate
	case <-m.quit:
		return 0
	}
}

func (m *mockFeeEstimator) Start() error {
	return nil
}
func (m *mockFeeEstimator) Stop() error {
	close(m.quit)
	return nil
}

var _ chainfee.Estimator = (*mockFeeEstimator)(nil)

type mockForwardingLog struct {
	sync.Mutex

	events map[time.Time]channeldb.ForwardingEvent
}

func (m *mockForwardingLog) AddForwardingEvents(events []channeldb.ForwardingEvent) error {
	m.Lock()
	defer m.Unlock()

	for _, event := range events {
		m.events[event.Timestamp] = event
	}

	return nil
}

type mockServer struct {
	started  int32 // To be used atomically.
	shutdown int32 // To be used atomically.
	wg       sync.WaitGroup
	quit     chan struct{}

	t testing.TB

	name     string
	messages chan lnwire.Message

	id         [33]byte
	htlcSwitch *Switch

	registry         *mockInvoiceRegistry
	pCache           *mockPreimageCache
	interceptorFuncs []messageInterceptor
}

var _ lnpeer.Peer = (*mockServer)(nil)

func initSwitchWithDB(startingHeight uint32, db *channeldb.DB) (*Switch, error) {
	signAliasUpdate := func(u *lnwire.ChannelUpdate) (*ecdsa.Signature,
		error) {

		return testSig, nil
	}

	cfg := Config{
		DB:                   db,
		FetchAllOpenChannels: db.ChannelStateDB().FetchAllOpenChannels,
		FetchAllChannels:     db.ChannelStateDB().FetchAllChannels,
		FetchClosedChannels:  db.ChannelStateDB().FetchClosedChannels,
		SwitchPackager:       channeldb.NewSwitchPackager(),
		FwdingLog: &mockForwardingLog{
			events: make(map[time.Time]channeldb.ForwardingEvent),
		},
		FetchLastChannelUpdate: func(scid lnwire.ShortChannelID) (
			*lnwire.ChannelUpdate, error) {

			return &lnwire.ChannelUpdate{
				ShortChannelID: scid,
			}, nil
		},
		Notifier: &mock.ChainNotifier{
			SpendChan: make(chan *chainntnfs.SpendDetail),
			EpochChan: make(chan *chainntnfs.BlockEpoch),
			ConfChan:  make(chan *chainntnfs.TxConfirmation),
		},
		FwdEventTicker:  ticker.NewForce(DefaultFwdEventInterval),
		LogEventTicker:  ticker.NewForce(DefaultLogInterval),
		AckEventTicker:  ticker.NewForce(DefaultAckInterval),
		HtlcNotifier:    &mockHTLCNotifier{},
		Clock:           clock.NewDefaultClock(),
		HTLCExpiry:      time.Hour,
		DustThreshold:   DefaultDustThreshold,
		SignAliasUpdate: signAliasUpdate,
		IsAlias:         isAlias,
	}

	return New(cfg, startingHeight)
}

func initSwitchWithTempDB(t testing.TB, startingHeight uint32) (*Switch,
	error) {

	tempPath := filepath.Join(t.TempDir(), "switchdb")
	db, err := channeldb.Open(tempPath)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { db.Close() })

	s, err := initSwitchWithDB(startingHeight, db)
	if err != nil {
		return nil, err
	}

	return s, nil
}

func newMockServer(t testing.TB, name string, startingHeight uint32,
	db *channeldb.DB, defaultDelta uint32) (*mockServer, error) {

	var id [33]byte
	h := sha256.Sum256([]byte(name))
	copy(id[:], h[:])

	pCache := newMockPreimageCache()

	var (
		htlcSwitch *Switch
		err        error
	)
	if db == nil {
		htlcSwitch, err = initSwitchWithTempDB(t, startingHeight)
	} else {
		htlcSwitch, err = initSwitchWithDB(startingHeight, db)
	}
	if err != nil {
		return nil, err
	}

	t.Cleanup(func() { _ = htlcSwitch.Stop() })

	registry := newMockRegistry(defaultDelta)

	t.Cleanup(func() { registry.cleanup() })

	return &mockServer{
		t:                t,
		id:               id,
		name:             name,
		messages:         make(chan lnwire.Message, 3000),
		quit:             make(chan struct{}),
		registry:         registry,
		htlcSwitch:       htlcSwitch,
		pCache:           pCache,
		interceptorFuncs: make([]messageInterceptor, 0),
	}, nil
}

func (s *mockServer) Start() error {
	if !atomic.CompareAndSwapInt32(&s.started, 0, 1) {
		return errors.New("mock server already started")
	}

	if err := s.htlcSwitch.Start(); err != nil {
		return err
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		defer func() {
			s.htlcSwitch.Stop()
		}()

		for {
			select {
			case msg := <-s.messages:
				var shouldSkip bool

				for _, interceptor := range s.interceptorFuncs {
					skip, err := interceptor(msg)
					if err != nil {
						s.t.Fatalf("%v: error in the "+
							"interceptor: %v", s.name, err)
						return
					}
					shouldSkip = shouldSkip || skip
				}

				if shouldSkip {
					continue
				}

				if err := s.readHandler(msg); err != nil {
					s.t.Fatal(err)
					return
				}
			case <-s.quit:
				return
			}
		}
	}()

	return nil
}

func (s *mockServer) QuitSignal() <-chan struct{} {
	return s.quit
}

// mockHopIterator represents the test version of hop iterator which instead
// of encrypting the path in onion blob just stores the path as a list of hops.
// NOTE(10/22/22): We have dummed down list of hops. We DO NOT have an
// encrypted onion.
// QUESTION(10/22/22): How do we configure the test links we create
// to support processing of blind hops? How do we define a blind hop
// in the test case? Simply a hop where the forwarding information is
// in an alternate location? How do we define a blindHopProcessor?
// Simply an entity which knows how to find/retrieve the forwarding
// information from this alternate location. The alternate location may
// be inside a nested TLV payload which is encrypted using a secret
// shared between hop and recipient (real) OR it might be as simple
// as an alternate plaintext field on a mock struct (test).
// NOTE(10/22/22): The mockHopIterator could contain unencrypted route blinding
// TLV payloads. Paired with a mock implementation of the blindHopProcessor
// interface whose DecryptBlindedPayload() method simply returns the same
// plain text payload.
// For the sake of testing, assume that the payload is already decrypted
// The sphinx package will already have tested that the decryption works.
// No need to test that again here?
// From the perspective of the link, we expect this function implementation
// (sphinx, test, or otherwise) to deliver us a proper serialized route blinding
// payload, which we can then parse into a BlindHopPayload{}
// NOTE(10/5/22): This parsing will be unit tested so I don't think we need to
// test that either?
// NOTE(10/23/22): This mockHopIterator is really not all that much like the
// real hopIterator. I do not like the name of hopIterator. It is not as
// intuitive an iterator like the watchtower's CandidateIterator or newly added
// AddressIterator which do abstract lists of towers and addresses. The
// hop "iterator" does not abstract a list of hops. A processing node does not
// have access to the list of hops in a route. All he knows is his hop and those
// which directly precede and follow his hop.
type mockHopIterator struct {
	hops []*hop.Payload
	// NOTE(10/23/22): Normal hops are encoded differently than blind hops.
	// We presently assume that all hop are either normal or blind.
	// This will work to preserve current testing and allow us to test some
	// aspects of blind hop processing, but it will leave out testing the
	// interaction between the normal and blind route (namely the point of intersection).
	// Consider an approach which allows us to indicate which of the hops
	// are normal and which are blind.
	// routeBlinding bool
}

type mockBlindHopIterator struct {
	hops []*hop.Payload
}

// NOTE(10/22/22) If we have a way to generate route blinding hop payloads
// (which we should already have somehwere), then all we need to do is pass
// its payloads to this function and things should just work!!
// func newMockHopIterator(routeBlinding bool, hops ...*hop.Payload) hop.Iterator {
func newMockHopIterator(hops ...*hop.Payload) hop.Iterator {
	return &mockHopIterator{
		hops: hops,
		// routeBlinding: routeBlinding,
	}
}

func (r *mockHopIterator) HopPayload() (*hop.Payload, error) {
	h := r.hops[0]
	fmt.Printf("[mockHopIterator.HopPayload()]: grabbing the top level hop payload: %+v, nil custom records? %t\n",
		h, h.CustomRecords() == nil)
	// IMPORTANT NOTE(10/23/22): Every time this method is called we peel
	// off a layer of the onion and our hop iterator contains one less hop!
	r.hops = r.hops[1:]
	return h, nil
}

func (r *mockHopIterator) IsExitHop() bool {
	fmt.Println("[mockHopIterator.IsExitHop()]: length of hop iterator: ", len(r.hops))
	// When the last hop parses its TLV payload via call to HopPayload(),
	// it will leave us with an empty hop iterator.
	// We are relying on this method being called AFTER HopPayload().
	// If this method is called BEFORE parsing the TLV payload then it will
	// NOT correctly report that we are the final hop!
	return len(r.hops) == 0
}

func (r *mockHopIterator) ExtraOnionBlob() []byte {
	return nil
}

func (r *mockHopIterator) ExtractErrorEncrypter(
	extracter hop.ErrorEncrypterExtracter) (hop.ErrorEncrypter,
	lnwire.FailCode) {

	return extracter(nil)
}

// This function implies it encodes a single hop, but in actuality it
// encodes all hops in the route?
func (r *mockHopIterator) EncodeNextHop(w io.Writer) error {
	var hopLength [4]byte
	binary.BigEndian.PutUint32(hopLength[:], uint32(len(r.hops)))

	if _, err := w.Write(hopLength[:]); err != nil {
		return err
	}

	// NOTE(10/22/22): We encode unencrypted hop.ForwardingInfo into the
	// onion blob here!!!
	for i, hop := range r.hops {
		fwdInfo := hop.ForwardingInfo()
		if err := encodeFwdInfo(w, &fwdInfo); err != nil {
			return err
		}
		fmt.Printf("[EncodeNextHop]: hop forward info "+
			"present! %+v\n", fwdInfo)
		fmt.Printf("[EncodeNextHop]: %dth hop: %+v\n", i, hop)

		// NOTE(10/23/22): We could make a decision about whether to
		// encode a normal or blind hop right here depending on whether
		// the hop.RouteBlindingEncryptedData field is present!
		if hop.RouteBlindingEncryptedData != nil {
			fmt.Printf("[EncodeNextHop]: route blinding payload "+
				"present! %v\n", hop.RouteBlindingEncryptedData)
			encodeBlindHop(w, hop)
		}

		// NOTE(10/28/22): Add a (few) sentinel byte(s) in order to mark
		// the end of the serialization for each hop.
		// This allows us to distinguish between normal and blind
		// hops (ie: those with a route blinding payload) during
		// deserialization/decoding.
		encodeHopBoundaryMarker(w)
	}

	return nil
}

func encodeHopBoundaryMarker(w io.Writer) error {
	fmt.Println("[encodeHopBoundaryMarker]: adding sentinel value to delineate the end of this hop!")
	// QUESTION(10/28/22): What is a good sentinel value?
	// Does it need to be a byte sequence we would never see?
	if _, err := w.Write([]byte{0xff, 0xff, 0xff, 0xff}); err != nil {
		return err
	}

	return nil
}

func encodeHopPayload(w io.Writer, hop *hop.Payload) error {

	fwdInfo := hop.ForwardingInfo()
	if err := encodeFwdInfo(w, &fwdInfo); err != nil {
		return err
	}
	fmt.Printf("[EncodeNextHop]: hop forward info "+
		"present! %+v\n", fwdInfo)

	return nil
}

func encodeFwdInfo(w io.Writer, f *hop.ForwardingInfo) error {
	if _, err := w.Write([]byte{byte(f.Network)}); err != nil {
		return err
	}

	if err := binary.Write(w, binary.BigEndian, f.NextHop); err != nil {
		return err
	}

	if err := binary.Write(w, binary.BigEndian, f.AmountToForward); err != nil {
		return err
	}

	if err := binary.Write(w, binary.BigEndian, f.OutgoingCTLV); err != nil {
		return err
	}

	return nil
}

func encodeBlindHop(w io.Writer, p *hop.Payload) error {

	// NOTE(10/25/22): We write the length of the route blinding payload
	// so that the variable length payload can be properly decoded.
	// We recreate the "LV" in TLV here!
	var blindPayloadLength [4]byte
	binary.BigEndian.PutUint32(blindPayloadLength[:], uint32(len(p.RouteBlindingEncryptedData)))
	fmt.Printf("[encodeBlindHop]: encoded route blinding payload length: %v\n", blindPayloadLength)

	n, err := w.Write(blindPayloadLength[:])
	if err != nil {
		return err
	}
	fmt.Printf("[encodeBlindHop]: wrote the value %d in %d bytes for payload length\n", len(p.RouteBlindingEncryptedData), n)

	if err := binary.Write(w, binary.BigEndian, p.RouteBlindingEncryptedData); err != nil {
		return err
	}

	// if p.BlindingPoint != nil {
	// 	if err := binary.Write(w, binary.BigEndian, p.BlindingPoint); err != nil {
	// 		return err
	// 	}
	// }

	return nil
}

var _ hop.Iterator = (*mockHopIterator)(nil)

// mockObfuscator mock implementation of the failure obfuscator which only
// encodes the failure and do not makes any onion obfuscation.
type mockObfuscator struct {
	ogPacket *sphinx.OnionPacket
	failure  lnwire.FailureMessage
}

// NewMockObfuscator initializes a dummy mockObfuscator used for testing.
func NewMockObfuscator() hop.ErrorEncrypter {
	return &mockObfuscator{}
}

func (o *mockObfuscator) OnionPacket() *sphinx.OnionPacket {
	return o.ogPacket
}

func (o *mockObfuscator) Type() hop.EncrypterType {
	return hop.EncrypterTypeMock
}

func (o *mockObfuscator) Encode(w io.Writer) error {
	return nil
}

func (o *mockObfuscator) Decode(r io.Reader) error {
	return nil
}

func (o *mockObfuscator) Reextract(
	extracter hop.ErrorEncrypterExtracter) error {

	return nil
}

func (o *mockObfuscator) EncryptFirstHop(failure lnwire.FailureMessage) (
	lnwire.OpaqueReason, error) {

	o.failure = failure

	var b bytes.Buffer
	if err := lnwire.EncodeFailure(&b, failure, 0); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (o *mockObfuscator) IntermediateEncrypt(reason lnwire.OpaqueReason) lnwire.OpaqueReason {
	return reason
}

func (o *mockObfuscator) EncryptMalformedError(reason lnwire.OpaqueReason) lnwire.OpaqueReason {
	return reason
}

// mockDeobfuscator mock implementation of the failure deobfuscator which
// only decodes the failure do not makes any onion obfuscation.
type mockDeobfuscator struct{}

func newMockDeobfuscator() ErrorDecrypter {
	return &mockDeobfuscator{}
}

func (o *mockDeobfuscator) DecryptError(reason lnwire.OpaqueReason) (*ForwardingError, error) {

	r := bytes.NewReader(reason)
	failure, err := lnwire.DecodeFailure(r, 0)
	if err != nil {
		return nil, err
	}

	return NewForwardingError(failure, 1), nil
}

var _ ErrorDecrypter = (*mockDeobfuscator)(nil)

// TODO(9/22/22): Will this need updating to support decoding blinded hops?

// NOTE(10/22/22): Pay attention to this for testing that the link handles
// blind hops!
// mockIteratorDecoder test version of hop iterator decoder which decodes the
// encoded array of hops.
type mockIteratorDecoder struct {
	mu sync.RWMutex

	responses map[[32]byte][]hop.DecodeHopIteratorResponse

	decodeFail bool
}

func newMockIteratorDecoder() *mockIteratorDecoder {
	return &mockIteratorDecoder{
		responses: make(map[[32]byte][]hop.DecodeHopIteratorResponse),
	}
}

func (p *mockIteratorDecoder) DecodeHopIterator(r io.Reader, rHash []byte,
	cltv uint32, blindingPoint *btcec.PublicKey) (hop.Iterator, lnwire.FailCode) {

	var b [4]byte
	_, err := r.Read(b[:])
	if err != nil {
		return nil, lnwire.CodeTemporaryChannelFailure
	}
	hopLength := binary.BigEndian.Uint32(b[:])
	// fmt.Println("[DecodeHopIterator]: hop length: ", hopLength)

	hops := make([]*hop.Payload, hopLength)
	for i := uint32(0); i < hopLength; i++ {
		// var f hop.ForwardingInfo
		// if err := decodeFwdInfo(r, &f); err != nil {
		// 	return nil, lnwire.CodeTemporaryChannelFailure
		// }
		// fmt.Printf("[DecodeHopIterator]: hop forward info: "+
		// 	"%+v\n", f)

		// // NOTE(10/23/22): We could make a decision about whether to
		// // decode a normal or blind hop right here depending on whether
		// // the blindingPoint is present!
		// if blindingPoint != nil {
		// 	fmt.Printf("[DecodeHopIterator]: blinding point (%x) "+
		// 		"present! decoding blind hop info\n",
		// 		blindingPoint.SerializeCompressed()[:10])
		// 	decodeBlindHop(r, hops[i])
		// }
		// // NOTE(10/26/22): If we provide a constructor for TLV hop
		// // payloads we can ensure that the custom records map is
		// // non-nil there so we pass the invoice registry check.
		// // var p *hop.Payload
		// // p := &hop.Payload{
		// // 	FwdInfo:       hop.ForwardingInfo{},
		// // 	customRecords: make(record.CustomSet),
		// // }
		p := hop.NewTLVPayload()
		if err := decodeHopPayload(r, p); err != nil {
			return nil, lnwire.CodeTemporaryChannelFailure
		}
		// fmt.Printf("[DecodeHopIterator]: route blinding payload "+
		// 	"present! %v\n", p.RouteBlindingEncryptedData)

		var f hop.ForwardingInfo = p.ForwardingInfo()
		var nextHopBytes [8]byte
		binary.BigEndian.PutUint64(nextHopBytes[:], f.NextHop.ToUint64())

		// NOTE(10/22/22): We still only ever use legacy onion payloads.
		// We should create a new version of this function or update
		// this one to use the now required TLV onion hop payload!
		// NOTE(10/26/22): This call to create a legacy payload
		// creates the map for custom records so that we avoid some
		// check by the invoice registry that the field is set.
		// customRecords: make(record.CustomSet),
		// hops[i] = hop.NewLegacyPayload(&sphinx.HopData{
		// 	Realm:         [1]byte{}, // hop.BitcoinNetwork
		// 	NextAddress:   nextHopBytes,
		// 	ForwardAmount: uint64(f.AmountToForward),
		// 	OutgoingCltv:  f.OutgoingCTLV,
		// })
		hops[i] = p
	}

	return newMockHopIterator(hops...), lnwire.CodeNone
}

// NOTE(10/22/22): DecodeHopIteratorRequest's will have a non-nil ephemeral
// BlindingPoint for blind hops. In real implementation this will be used by
// the underlying Sphinx library to decrypt the onion. For testing, it can
// probably be ignored as we just pass the public key through to the Sphinx
// impelmentation, but we are not dealing with encrypted data for Link testing.
func (p *mockIteratorDecoder) DecodeHopIterators(id []byte,
	reqs []hop.DecodeHopIteratorRequest) (
	[]hop.DecodeHopIteratorResponse, error) {

	idHash := sha256.Sum256(id)

	p.mu.RLock()
	if resps, ok := p.responses[idHash]; ok {
		p.mu.RUnlock()
		return resps, nil
	}
	p.mu.RUnlock()

	batchSize := len(reqs)

	resps := make([]hop.DecodeHopIteratorResponse, 0, batchSize)
	for _, req := range reqs {
		iterator, failcode := p.DecodeHopIterator(
			req.OnionReader, req.RHash, req.IncomingCltv, req.BlindingPoint,
		)

		if p.decodeFail {
			failcode = lnwire.CodeTemporaryChannelFailure
		}

		resp := hop.DecodeHopIteratorResponse{
			HopIterator: iterator,
			FailCode:    failcode,
		}
		resps = append(resps, resp)
	}

	p.mu.Lock()
	p.responses[idHash] = resps
	p.mu.Unlock()

	return resps, nil
}

// func decodeHopBoundaryMarker(w io.Writer) error {
// 	fmt.Println("[encodeHopBoundaryMarker]: adding sentinel value to delineate the end of this hop!")
// 	// QUESTION(10/28/22): What is a good sentinel value?
// 	// Does it need to be a byte sequence we would never see?
// 	if _, err := w.Write([]byte{0xff, 0xff, 0xff, 0xff}); err != nil {
// 		return err
// 	}

// 	return nil
// }

func isHopBoundary(b []byte) bool {
	fmt.Println("[isHopBoundary]: determining if we should deserialize route blinding payload.")
	sentinel := []byte{0xff, 0xff, 0xff, 0xff}
	return bytes.Equal(sentinel, b)
}

func decodeHopPayload(r io.Reader, p *hop.Payload) error {
	if err := decodeFwdInfo(r, &p.FwdInfo); err != nil {
		return err
	}
	fmt.Printf("[decodeHopPayload]: hop forward info: "+
		"%+v\n", p.FwdInfo)

	// fmt.Printf("[DecodeHopIterator]: blinding point (%x) "+
	// 	"present! decoding blind hop info\n",
	// 	blindingPoint.SerializeCompressed()[:10])

	// We will duplicate the bytes in our reader so that we may
	// read from the stream twice. This allows us to "peek" bytes.
	// without disturbing the original stream.
	// var buf bytes.Buffer
	// tee := io.TeeReader(r, &buf)

	// NOTE(10/28/22): Bytes, once read, from an io.Reader cannot be read
	// again! If we begin reading additional bytes in an effort to
	// deserialize a route blinding payload we may overstep the boundary
	// of bytes meant to encode this hop. This leads to mistakenly
	// decoded/parsed payloads.
	// NOTE(10/28/22): We need a signalling method for when we should
	// deserialize and interpret bytes as a route blinding payload.
	if err := decodeBlindHop(r, p); err != nil {
		return err
	}
	// fmt.Printf("[decodeHopPayload]: route blinding payload: "+
	// 	"%+v\n", p.RouteBlindingEncryptedData)

	return nil
}

func decodeFwdInfo(r io.Reader, f *hop.ForwardingInfo) error {
	var net [1]byte
	if _, err := r.Read(net[:]); err != nil {
		return err
	}
	f.Network = hop.Network(net[0])
	fmt.Printf("[decodeFwdInfo]: network: %v\n", net)

	if err := binary.Read(r, binary.BigEndian, &f.NextHop); err != nil {
		return err
	}
	fmt.Printf("[decodeFwdInfo]: nextHop: %v\n", f.NextHop)

	if err := binary.Read(r, binary.BigEndian, &f.AmountToForward); err != nil {
		return err
	}
	fmt.Printf("[decodeFwdInfo]: amount to forward: %v\n", f.AmountToForward)

	if err := binary.Read(r, binary.BigEndian, &f.OutgoingCTLV); err != nil {
		return err
	}
	fmt.Printf("[decodeFwdInfo]: outgoing timelock: %v\n", f.OutgoingCTLV)

	return nil
}

func trimSentinel(r io.Reader) {
	fmt.Println("[trimSentinel]: removing bytes marking end of hop!")
	var b [4]byte
	r.Read(b[:])
}

func decodeBlindHop(r io.Reader, p *hop.Payload) error {
	// if err := binary.Read(r, binary.BigEndian, &p.FwdInfo.NextHop); err != nil {
	// 	return err
	// }
	// fmt.Printf("[decodeBlindHop]: next hop: %+v\n", &p.FwdInfo.NextHop)

	// TODO(10/25/22): Figure out how to handle decoding of variable length
	// byte slice. We use TLV in the real implementation.
	// if err := binary.Read(r, binary.BigEndian, &p.RouteBlindingEncryptedData); err != nil {
	// 	return err
	// }

	// NOTE(10/26/22): I think we run into the problem here! If we read these
	// 4 bytes to determine whether we should parse the route blinding payload
	// and this is not a blind hop, then we are eating 4 bytes that ought
	// to have been decoded/interpeted differently. This leads to mistakenly
	// decoded/parsed payloads.
	var b [4]byte
	_, err := r.Read(b[:])
	if err != nil {
		return err
	}

	// Check for hop boundary sentinel. If we are at a hop boundary,
	// then we should bail early without reading any more bytes.
	// If this is not the hop boundary, then we should interpret the bytes
	// just read as the length of the route blinding payload.
	if ok := isHopBoundary(b[:]); ok {
		fmt.Println("[decodeBlindHop]: at hop boundary. will not read route blinding payload.")
		return nil
	}
	// Don't forget to trim off the sentinel, so that any hops after
	// this one are parsed correctly.
	defer func() {
		trimSentinel(r)
	}()

	// NOTE(10/28/22): We need a signalling method for when we should
	// deserialize and interpret bytes as a route blinding payload.
	// - Check for sentinel byte value which delineates the byte boundary
	// between serialized hops. Without this or something like TLV we do
	// not have a way to know if we should deserialize a route blinding
	// payload.
	// - Higher level signal whereby our iterator magically knows that a
	// hop is blinded.
	payloadLength := binary.BigEndian.Uint32(b[:])
	fmt.Println("[decodeBlindHop]: route blinding payload length: ", payloadLength)

	// fmt.Println("[decodeBlindHop]: trying to decode route blinding payload!")
	buf := make([]byte, payloadLength)
	// if err := binary.Read(r, binary.BigEndian, &b); err != nil {
	// 	return err
	// }
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return err
	}
	fmt.Printf("[decodeBlindHop]: read %d bytes for payload: %v\n", n, buf)
	// p.RouteBlindingEncryptedData = buf

	// Only set the route blinding payload if it exits. Otherwise, leave
	// the slice nil so we do not incorrectly believe the hop to be blind.
	if n != 0 {
		p.RouteBlindingEncryptedData = buf
	}

	// fmt.Printf("[decodeBlindHop]: route blinding payload: %v\n",
	// p.RouteBlindingEncryptedData)
	// if _, err := io.ReadFull(r, p.RouteBlindingEncryptedData); err != nil {
	// 	return err
	// }

	// var blindingPoint [33]byte
	// if _, err := r.Read(blindingPoint[:]); err != nil {
	// 	return err
	// }

	// temp, err := btcec.ParsePubKey(blindingPoint[:])
	// if err != nil {
	// 	return err
	// }
	// p.BlindingPoint = temp
	// if p.BlindingPoint, err := btcec.ParsePubKey(blindingPoint[:]); err != nil {
	// 	return err
	// }
	// if err := binary.Read(r, binary.BigEndian, &p.BlindingPoint); err != nil {
	// 	return err
	// }

	return nil
}

type mockBlindHopProcessor struct{}

func (b *mockBlindHopProcessor) DecryptBlindedPayload(nodeID keychain.SingleKeyECDH, blindingPoint *btcec.PublicKey,
	payload []byte) ([]byte, error) {

	fmt.Println("[mockBlindHopProcessor]: decrypting route blinding TLV payload.")
	// For the sake of testing, assume that the payload is already decrypted
	// The sphinx package will already have tested that the decryption works.
	// No need to test that again here?
	// From the perspective of the link, we expect this function implementation
	// (sphinx, test, or otherwise) to deliver us a proper serialized route blinding
	// payload, which we can then parse into a BlindHopPayload{}
	// NOTE(10/5/22): This parsing will be unit tested so I don't think we need to
	// test that either?
	return payload, nil
}

func (b *mockBlindHopProcessor) NextBlindingPoint(sessionKey keychain.SingleKeyECDH, blindingPoint *btcec.PublicKey) (
	*btcec.PublicKey, error) {

	fmt.Println("[mockBlindHopProcessor]: computing next ephemeral blinding point.")

	// NOTE(10/5/22): Again, the link does not need to care about the implementation
	// of this function. It only cares that it is given a new blinding point to pass
	// to the next hop.
	return blindingPoint, nil
}

type brokenBlindHopProcessor struct {
	// errOnDecrypt is a flag which informs the broken blind hop processor
	// whether it should fail during an attempt to decrypt a route blinding
	// payload or while computing the next blinding point.
	// This provides control over how the blind hop processor should fail.
	errOnDecrypt bool
}

func (b *brokenBlindHopProcessor) DecryptBlindedPayload(nodeID keychain.SingleKeyECDH, blindingPoint *btcec.PublicKey,
	payload []byte) ([]byte, error) {

	// Simulate an error during decryption of the route blinding TLV payload.
	if b.errOnDecrypt {
		fmt.Println("[brokenBlindHopProcessor]: encountered error " +
			"attempting to decrypt route blinding TLV payload.")
		return nil, errors.New("unable to decrypt route blinding TLV payload")
	}

	fmt.Println("[brokenBlindHopProcessor]: decrypting route blinding TLV payload.")

	// Otherwise, return successfully and allow failure to occur later.
	return payload, nil
}

func (b *brokenBlindHopProcessor) NextBlindingPoint(sessionKey keychain.SingleKeyECDH, blindingPoint *btcec.PublicKey) (
	*btcec.PublicKey, error) {

	fmt.Println("[brokenBlindHopProcessor]: computing next ephemeral blinding point.")

	// Simulate an error during computation of the epemeral blinding point
	// for the next hop in a blinded route.
	return nil, errors.New("unable to compute next ephemeral blinding point")
}

// messageInterceptor is function that handles the incoming peer messages and
// may decide should the peer skip the message or not.
type messageInterceptor func(m lnwire.Message) (bool, error)

// Record is used to set the function which will be triggered when new
// lnwire message was received.
func (s *mockServer) intersect(f messageInterceptor) {
	s.interceptorFuncs = append(s.interceptorFuncs, f)
}

func (s *mockServer) SendMessage(sync bool, msgs ...lnwire.Message) error {

	for _, msg := range msgs {
		select {
		case s.messages <- msg:
		case <-s.quit:
			return errors.New("server is stopped")
		}
	}

	return nil
}

func (s *mockServer) SendMessageLazy(sync bool, msgs ...lnwire.Message) error {
	panic("not implemented")
}

func (s *mockServer) readHandler(message lnwire.Message) error {
	var targetChan lnwire.ChannelID

	switch msg := message.(type) {
	case *lnwire.UpdateAddHTLC:
		targetChan = msg.ChanID
	case *lnwire.UpdateFulfillHTLC:
		targetChan = msg.ChanID
	case *lnwire.UpdateFailHTLC:
		targetChan = msg.ChanID
	case *lnwire.UpdateFailMalformedHTLC:
		targetChan = msg.ChanID
	case *lnwire.RevokeAndAck:
		targetChan = msg.ChanID
	case *lnwire.CommitSig:
		targetChan = msg.ChanID
	case *lnwire.FundingLocked:
		// Ignore
		return nil
	case *lnwire.ChannelReestablish:
		targetChan = msg.ChanID
	case *lnwire.UpdateFee:
		targetChan = msg.ChanID
	default:
		return fmt.Errorf("unknown message type: %T", msg)
	}

	// Dispatch the commitment update message to the proper channel link
	// dedicated to this channel. If the link is not found, we will discard
	// the message.
	link, err := s.htlcSwitch.GetLink(targetChan)
	if err != nil {
		return nil
	}

	// Create goroutine for this, in order to be able to properly stop
	// the server when handler stacked (server unavailable)
	link.HandleChannelUpdate(message)

	return nil
}

func (s *mockServer) PubKey() [33]byte {
	return s.id
}

func (s *mockServer) IdentityKey() *btcec.PublicKey {
	pubkey, _ := btcec.ParsePubKey(s.id[:])
	return pubkey
}

func (s *mockServer) Address() net.Addr {
	return nil
}

func (s *mockServer) AddNewChannel(channel *channeldb.OpenChannel,
	cancel <-chan struct{}) error {

	return nil
}

func (s *mockServer) WipeChannel(*wire.OutPoint) {}

func (s *mockServer) LocalFeatures() *lnwire.FeatureVector {
	return nil
}

func (s *mockServer) RemoteFeatures() *lnwire.FeatureVector {
	return nil
}

func (s *mockServer) Stop() error {
	if !atomic.CompareAndSwapInt32(&s.shutdown, 0, 1) {
		return nil
	}

	close(s.quit)
	s.wg.Wait()

	return nil
}

func (s *mockServer) String() string {
	return s.name
}

// TODO(10/22/22): How should this be modified to support blind
// hop processing? Look to eugene's zero conf changes for some inspiration.
type mockChannelLink struct {
	htlcSwitch *Switch

	shortChanID lnwire.ShortChannelID

	// Only used for zero-conf channels.
	realScid lnwire.ShortChannelID

	aliases []lnwire.ShortChannelID

	chanID lnwire.ChannelID

	peer lnpeer.Peer

	mailBox MailBox

	packets chan *htlcPacket

	eligible bool

	unadvertised bool

	zeroConf bool

	optionFeature bool

	htlcID uint64

	checkHtlcTransitResult *LinkError

	checkHtlcForwardResult *LinkError

	failAliasUpdate func(sid lnwire.ShortChannelID,
		incoming bool) *lnwire.ChannelUpdate

	confirmedZC bool
}

// completeCircuit is a helper method for adding the finalized payment circuit
// to the switch's circuit map. In testing, this should be executed after
// receiving an htlc from the downstream packets channel.
func (f *mockChannelLink) completeCircuit(pkt *htlcPacket) error {
	switch htlc := pkt.htlc.(type) {
	case *lnwire.UpdateAddHTLC:
		pkt.outgoingChanID = f.shortChanID
		pkt.outgoingHTLCID = f.htlcID
		htlc.ID = f.htlcID

		keystone := Keystone{pkt.inKey(), pkt.outKey()}
		err := f.htlcSwitch.circuits.OpenCircuits(keystone)
		if err != nil {
			return err
		}

		f.htlcID++

	case *lnwire.UpdateFulfillHTLC, *lnwire.UpdateFailHTLC:
		if pkt.circuit != nil {
			err := f.htlcSwitch.teardownCircuit(pkt)
			if err != nil {
				return err
			}
		}
	}

	f.mailBox.AckPacket(pkt.inKey())

	return nil
}

func (f *mockChannelLink) deleteCircuit(pkt *htlcPacket) error {
	return f.htlcSwitch.circuits.DeleteCircuits(pkt.inKey())
}

func newMockChannelLink(htlcSwitch *Switch, chanID lnwire.ChannelID,
	shortChanID, realScid lnwire.ShortChannelID, peer lnpeer.Peer,
	eligible, unadvertised, zeroConf, optionFeature bool,
) *mockChannelLink {

	aliases := make([]lnwire.ShortChannelID, 0)
	var realConfirmed bool

	if zeroConf {
		aliases = append(aliases, shortChanID)
	}

	if realScid != hop.Source {
		realConfirmed = true
	}

	return &mockChannelLink{
		htlcSwitch:    htlcSwitch,
		chanID:        chanID,
		shortChanID:   shortChanID,
		realScid:      realScid,
		peer:          peer,
		eligible:      eligible,
		unadvertised:  unadvertised,
		zeroConf:      zeroConf,
		optionFeature: optionFeature,
		aliases:       aliases,
		confirmedZC:   realConfirmed,
	}
}

// addAlias is not part of any interface method.
func (f *mockChannelLink) addAlias(alias lnwire.ShortChannelID) {
	f.aliases = append(f.aliases, alias)
}

func (f *mockChannelLink) handleSwitchPacket(pkt *htlcPacket) error {
	f.mailBox.AddPacket(pkt)
	return nil
}

func (f *mockChannelLink) getDustSum(remote bool) lnwire.MilliSatoshi {
	return 0
}

func (f *mockChannelLink) getFeeRate() chainfee.SatPerKWeight {
	return 0
}

func (f *mockChannelLink) getDustClosure() dustClosure {
	dustLimit := btcutil.Amount(400)
	return dustHelper(
		channeldb.SingleFunderTweaklessBit, dustLimit, dustLimit,
	)
}

func (f *mockChannelLink) HandleChannelUpdate(lnwire.Message) {
}

func (f *mockChannelLink) UpdateForwardingPolicy(_ ForwardingPolicy) {
}
func (f *mockChannelLink) CheckHtlcForward([32]byte, lnwire.MilliSatoshi,
	lnwire.MilliSatoshi, uint32, uint32, uint32,
	lnwire.ShortChannelID) *LinkError {

	return f.checkHtlcForwardResult
}

func (f *mockChannelLink) CheckHtlcTransit(payHash [32]byte,
	amt lnwire.MilliSatoshi, timeout uint32,
	heightNow uint32) *LinkError {

	return f.checkHtlcTransitResult
}

func (f *mockChannelLink) Stats() (uint64, lnwire.MilliSatoshi, lnwire.MilliSatoshi) {
	return 0, 0, 0
}

func (f *mockChannelLink) AttachMailBox(mailBox MailBox) {
	f.mailBox = mailBox
	f.packets = mailBox.PacketOutBox()
	mailBox.SetDustClosure(f.getDustClosure())
}

func (f *mockChannelLink) attachFailAliasUpdate(closure func(
	sid lnwire.ShortChannelID, incoming bool) *lnwire.ChannelUpdate) {

	f.failAliasUpdate = closure
}

func (f *mockChannelLink) getAliases() []lnwire.ShortChannelID {
	return f.aliases
}

func (f *mockChannelLink) isZeroConf() bool {
	return f.zeroConf
}

func (f *mockChannelLink) negotiatedAliasFeature() bool {
	return f.optionFeature
}

func (f *mockChannelLink) confirmedScid() lnwire.ShortChannelID {
	return f.realScid
}

func (f *mockChannelLink) zeroConfConfirmed() bool {
	return f.confirmedZC
}

func (f *mockChannelLink) Start() error {
	f.mailBox.ResetMessages()
	f.mailBox.ResetPackets()
	return nil
}

func (f *mockChannelLink) ChanID() lnwire.ChannelID                     { return f.chanID }
func (f *mockChannelLink) ShortChanID() lnwire.ShortChannelID           { return f.shortChanID }
func (f *mockChannelLink) Bandwidth() lnwire.MilliSatoshi               { return 99999999 }
func (f *mockChannelLink) Peer() lnpeer.Peer                            { return f.peer }
func (f *mockChannelLink) ChannelPoint() *wire.OutPoint                 { return &wire.OutPoint{} }
func (f *mockChannelLink) Stop()                                        {}
func (f *mockChannelLink) EligibleToForward() bool                      { return f.eligible }
func (f *mockChannelLink) MayAddOutgoingHtlc(lnwire.MilliSatoshi) error { return nil }
func (f *mockChannelLink) ShutdownIfChannelClean() error                { return nil }
func (f *mockChannelLink) setLiveShortChanID(sid lnwire.ShortChannelID) { f.shortChanID = sid }
func (f *mockChannelLink) IsUnadvertised() bool                         { return f.unadvertised }
func (f *mockChannelLink) UpdateShortChanID() (lnwire.ShortChannelID, error) {
	f.eligible = true
	return f.shortChanID, nil
}

var _ ChannelLink = (*mockChannelLink)(nil)

func newDB() (*channeldb.DB, func(), error) {
	// First, create a temporary directory to be used for the duration of
	// this test.
	tempDirName, err := ioutil.TempDir("", "channeldb")
	if err != nil {
		return nil, nil, err
	}

	// Next, create channeldb for the first time.
	cdb, err := channeldb.Open(tempDirName)
	if err != nil {
		os.RemoveAll(tempDirName)
		return nil, nil, err
	}

	cleanUp := func() {
		cdb.Close()
		os.RemoveAll(tempDirName)
	}

	return cdb, cleanUp, nil
}

const testInvoiceCltvExpiry = 6

type mockInvoiceRegistry struct {
	settleChan chan lntypes.Hash

	registry *invoices.InvoiceRegistry

	cleanup func()
}

type mockChainNotifier struct {
	chainntnfs.ChainNotifier
}

// RegisterBlockEpochNtfn mocks a successful call to register block
// notifications.
func (m *mockChainNotifier) RegisterBlockEpochNtfn(*chainntnfs.BlockEpoch) (
	*chainntnfs.BlockEpochEvent, error) {

	return &chainntnfs.BlockEpochEvent{
		Cancel: func() {},
	}, nil
}

func newMockRegistry(minDelta uint32) *mockInvoiceRegistry {
	cdb, cleanup, err := newDB()
	if err != nil {
		panic(err)
	}

	registry := invoices.NewRegistry(
		cdb,
		invoices.NewInvoiceExpiryWatcher(
			clock.NewDefaultClock(), 0, 0, nil,
			&mockChainNotifier{},
		),
		&invoices.RegistryConfig{
			FinalCltvRejectDelta: 5,
		},
	)
	registry.Start()

	return &mockInvoiceRegistry{
		registry: registry,
		cleanup:  cleanup,
	}
}

func (i *mockInvoiceRegistry) LookupInvoice(rHash lntypes.Hash) (
	channeldb.Invoice, error) {

	return i.registry.LookupInvoice(rHash)
}

func (i *mockInvoiceRegistry) SettleHodlInvoice(preimage lntypes.Preimage) error {
	return i.registry.SettleHodlInvoice(preimage)
}

func (i *mockInvoiceRegistry) NotifyExitHopHtlc(rhash lntypes.Hash,
	amt lnwire.MilliSatoshi, expiry uint32, currentHeight int32,
	circuitKey channeldb.CircuitKey, hodlChan chan<- interface{},
	payload invoices.Payload) (invoices.HtlcResolution, error) {

	event, err := i.registry.NotifyExitHopHtlc(
		rhash, amt, expiry, currentHeight, circuitKey, hodlChan,
		payload,
	)
	if err != nil {
		return nil, err
	}
	if i.settleChan != nil {
		i.settleChan <- rhash
	}

	return event, nil
}

func (i *mockInvoiceRegistry) CancelInvoice(payHash lntypes.Hash) error {
	return i.registry.CancelInvoice(payHash)
}

func (i *mockInvoiceRegistry) AddInvoice(invoice channeldb.Invoice,
	paymentHash lntypes.Hash) error {

	_, err := i.registry.AddInvoice(&invoice, paymentHash)
	return err
}

func (i *mockInvoiceRegistry) HodlUnsubscribeAll(subscriber chan<- interface{}) {
	i.registry.HodlUnsubscribeAll(subscriber)
}

var _ InvoiceDatabase = (*mockInvoiceRegistry)(nil)

type mockCircuitMap struct {
	lookup chan *PaymentCircuit
}

var _ CircuitMap = (*mockCircuitMap)(nil)

func (m *mockCircuitMap) OpenCircuits(...Keystone) error {
	return nil
}

func (m *mockCircuitMap) TrimOpenCircuits(chanID lnwire.ShortChannelID,
	start uint64) error {
	return nil
}

func (m *mockCircuitMap) DeleteCircuits(inKeys ...CircuitKey) error {
	return nil
}

func (m *mockCircuitMap) CommitCircuits(
	circuit ...*PaymentCircuit) (*CircuitFwdActions, error) {

	return nil, nil
}

func (m *mockCircuitMap) CloseCircuit(outKey CircuitKey) (*PaymentCircuit,
	error) {
	return nil, nil
}

func (m *mockCircuitMap) FailCircuit(inKey CircuitKey) (*PaymentCircuit,
	error) {
	return nil, nil
}

func (m *mockCircuitMap) LookupCircuit(inKey CircuitKey) *PaymentCircuit {
	return <-m.lookup
}

func (m *mockCircuitMap) LookupOpenCircuit(outKey CircuitKey) *PaymentCircuit {
	return nil
}

func (m *mockCircuitMap) LookupByPaymentHash(hash [32]byte) []*PaymentCircuit {
	return nil
}

func (m *mockCircuitMap) NumPending() int {
	return 0
}

func (m *mockCircuitMap) NumOpen() int {
	return 0
}

type mockOnionErrorDecryptor struct {
	sourceIdx int
	message   []byte
	err       error
}

func (m *mockOnionErrorDecryptor) DecryptError(encryptedData []byte) (
	*sphinx.DecryptedError, error) {

	return &sphinx.DecryptedError{
		SenderIdx: m.sourceIdx,
		Message:   m.message,
	}, m.err
}

var _ htlcNotifier = (*mockHTLCNotifier)(nil)

type mockHTLCNotifier struct{}

func (h *mockHTLCNotifier) NotifyForwardingEvent(key HtlcKey, info HtlcInfo,
	eventType HtlcEventType) { // nolint:whitespace
}

func (h *mockHTLCNotifier) NotifyLinkFailEvent(key HtlcKey, info HtlcInfo,
	eventType HtlcEventType, linkErr *LinkError,
	incoming bool) { // nolint:whitespace
}

func (h *mockHTLCNotifier) NotifyForwardingFailEvent(key HtlcKey,
	eventType HtlcEventType) { // nolint:whitespace
}

func (h *mockHTLCNotifier) NotifySettleEvent(key HtlcKey,
	preimage lntypes.Preimage, eventType HtlcEventType) { // nolint:whitespace
}
