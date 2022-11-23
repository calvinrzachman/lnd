package routerrpc

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/record"
	"github.com/lightningnetwork/lnd/routing"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/stretchr/testify/require"
)

const (
	destKey       = "0286098b97bc843372b4426d4b276cea9aa2f48f0428d6f5b66ae101befc14f8b4"
	ignoreNodeKey = "02f274f48f3c0d590449a6776e3ce8825076ac376e470e992246eebc565ef8bb2a"
	hintNodeKey   = "0274e7fb33eafd74fe1acb6db7680bb4aa78e9c839a6e954e38abfad680f645ef7"

	testMissionControlProb = 0.5
)

var (
	sourceKey = route.Vertex{1, 2, 3}

	node1 = route.Vertex{10}

	node2 = route.Vertex{11}
)

// TestQueryRoutes asserts that query routes rpc parameters are properly parsed
// and passed onto path finding.
//
// TODO(7/24/22): Add tests for querying routes with non-self source node.
// Also this tests makes minimal checks to ensure correctness of QueryRoutes.
// We lose the information on who is source in Marshal/Unmarshal, lnrpc.Route{} does not contain that information.
func TestQueryRoutes(t *testing.T) {
	t.Run("no mission control", func(t *testing.T) {
		testQueryRoutes(t, false, false, true)
	})
	t.Run("no mission control and msat", func(t *testing.T) {
		testQueryRoutes(t, false, true, true)
	})
	t.Run("with mission control", func(t *testing.T) {
		testQueryRoutes(t, true, false, true)
	})
	t.Run("no mission control bad cltv limit", func(t *testing.T) {
		testQueryRoutes(t, false, false, false)
	})
}

func TestUnmarshalRoute(t *testing.T) {
	/*
		Setup a simple test network for querying arbitrary routes
		NOTE: The heavy lifting here might be done by findRoute()

				scid: 0					  scid: 1
		self <-----------> destination <-----------> arbitrarySource

	*/

	// NOTE: We should not be assuming that the router's
	// "self node" is the source of all routes we create.
	// While this generally will be true (is a sane default),
	// it will not hold when using blinded routes, where we may
	// be building/handling a route from an arbitrary source node
	// (introduction node) to ourselves.
	self := route.Vertex{1, 2, 3}
	destination := route.Vertex{4, 5, 6}
	arbitrarySource := route.Vertex{7, 8, 9}

	backend := &RouterBackend{
		SelfNode: self,
		// We consult the channel graph if the hop structs we
		// are (un)marshalling do not contain a public key.
		FetchChannelEndpoints: func(chanID uint64) (route.Vertex,
			route.Vertex, error) {

			switch chanID {
			case 0:
				// Channel between self <--> destination
				return self, destination, nil
			case 1:
				// Channel between arbitrarySource <--> destination
				return arbitrarySource, destination, nil
			default:
				return route.Vertex{}, route.Vertex{}, fmt.Errorf("channel with ID %d does not exist", chanID)
			}

		},
	}

	testCases := []struct {
		name        string
		source      string
		hops        []*lnrpc.Hop
		expectedErr bool
	}{
		{
			name:   "1",
			source: self.String(),
			hops: []*lnrpc.Hop{
				{
					ChanId: 0, // Channel between self <--> destination
				},
			},
			expectedErr: false,
		},
		{
			name:   "2",
			source: arbitrarySource.String(),
			hops: []*lnrpc.Hop{
				{
					ChanId: 1, // Channel between arbitrarySource <--> destination
				},
			},
			expectedErr: false,
		},
		{
			name:   "3",
			source: self.String(),
			hops: []*lnrpc.Hop{
				{
					ChanId: 1, // Channel between arbitrarySource <--> destination
				},
			},
			expectedErr: true,
		},
		{
			name:   "4",
			source: arbitrarySource.String(),
			hops: []*lnrpc.Hop{
				{
					ChanId: 0, // Channel between self <--> destination
				},
			},
			expectedErr: true,
		},
	}

	for _, tc := range testCases {
		route, err := backend.UnmarshallRoute(&lnrpc.Route{
			SourcePubKey: tc.source,
			Hops:         tc.hops,
		})

		if tc.expectedErr && err == nil {
			t.Fatalf("unexpected success when unmarshalling route")
		}

		if !tc.expectedErr && err != nil {
			t.Fatalf("unable to unmarshal route: %v", err)
		}

		if err == nil && !tc.expectedErr {
			// The route.Route{} will only be successfully unmarshalled
			// if we encounter no error.
			if route.SourcePubKey.String() != tc.source {
				t.Fatalf("unexected route source. want: %s, got: %s", tc.source, route.SourcePubKey)
			}
		}

	}

	// Should default to setting the source node to ourselves.
	route, err := backend.UnmarshallRoute(&lnrpc.Route{
		Hops: []*lnrpc.Hop{
			{
				ChanId: 0, // Channel between self <--> destination
			},
		},
	})
	if err != nil {
		t.Fatalf("unable to unmarshal route: %v", err)
	}
	if route.SourcePubKey != self {
		t.Fatalf("unexected route source. want: %s, got: %s", self, route.SourcePubKey)
	}

	// Now verify that we can unmarshall a route using any
	// arbitrary node as the route's source.
	route, err = backend.UnmarshallRoute(&lnrpc.Route{
		SourcePubKey: arbitrarySource.String(),
		Hops: []*lnrpc.Hop{
			{
				ChanId: 1, // Channel between arbitrarySource <--> destination
			},
		},
	})
	if err != nil {
		t.Fatalf("unable to unmarshal route: %v", err)
	}
	if route.SourcePubKey != arbitrarySource {
		t.Fatalf("unexected route source. want: %s, got: %s", arbitrarySource.String(), route.SourcePubKey)
	}

	// Attempting to unmarshall a route for which we are the source,
	// but whose first hop uses a channel which is not ours should fail.
	route, err = backend.UnmarshallRoute(&lnrpc.Route{
		// SourcePubKey: self // implicit
		Hops: []*lnrpc.Hop{
			{
				ChanId: 1, // Channel between arbitrarySource <--> destination
			},
		},
	})
	if err == nil {
		t.Fatal("should not be able to unmarshall route")
	}

	// Attempting to unmarshall a route with an arbitrary source,
	// but using our channel as the first hop should fail.
	route, err = backend.UnmarshallRoute(&lnrpc.Route{
		SourcePubKey: arbitrarySource.String(),
		Hops: []*lnrpc.Hop{
			{
				ChanId: 0, // Channel between self <--> destination
			},
		},
	})
	if err == nil {
		t.Fatal("should not be able to unmarshall route")
	}
}
func TestMarshalRoute(t *testing.T) {

	// NOTE: We should not be assuming that the router's
	// "self node" is the source of all routes we create.
	// While this generally will be true (is a sane default),
	// it will not hold when using blinded routes, where we may
	// be building/handling a route from an arbitrary source node
	// (introduction node) to ourselves.
	self := route.Vertex{1, 2, 3}
	backend := &RouterBackend{
		SelfNode: self,
	}

	// Should default to setting the source node to ourselves.
	rpcRoute, err := backend.MarshallRoute(&route.Route{
		Hops: []*route.Hop{},
	})
	if err != nil {
		t.Fatal("unable to marshal route")
	}
	if rpcRoute.SourcePubKey != self.String() {
		t.Fatalf("unexected route source. want: %s, got: %s", self.String(), rpcRoute.SourcePubKey)
	}

	// Now verify that we can marshal a route using any
	// arbitrary node as the route's source.
	arbitrarySource := route.Vertex{4, 5, 6}
	rpcRoute, err = backend.MarshallRoute(&route.Route{
		SourcePubKey: arbitrarySource,
		Hops:         []*route.Hop{},
	})
	if err != nil {
		t.Fatal("unable to marshal route")
	}
	if rpcRoute.SourcePubKey != arbitrarySource.String() {
		t.Fatalf("unexected route source. want: %s, got: %s", arbitrarySource.String(), rpcRoute.SourcePubKey)
	}
}

// TestQueryRouteWithArbitrarySource asserts that we can query routes
// beginning at an arbitrary source node rather than assuming that the
// source of a route is always ourselves.
func TestQueryRouteWithArbitrarySource(t *testing.T) {
	/*
		Setup a simple test network for querying arbitrary routes
		NOTE: The heavy lifting here might be done by findRoute()

				scid: 0					  scid: 1
		self <-----------> destination <-----------> arbitrarySource

	*/

	expectedRouteSource := node1.String()
	request := &lnrpc.QueryRoutesRequest{
		PubKey:            destKey,
		FinalCltvDelta:    100,
		UseMissionControl: false,
		// NOTE: The point of this test to verify that the requested
		// route source is respected by the ChannelRouter.
		SourcePubKey: expectedRouteSource,
	}

	findRoute := func(source, target route.Vertex,
		amt lnwire.MilliSatoshi, timePref float64,
		restrictions *routing.RestrictParams,
		destCustomRecords record.CustomSet,
		routeHints map[route.Vertex][]*channeldb.CachedEdgePolicy,
		finalExpiry uint16) (*route.Route, error) {

		hops := []*route.Hop{{}}
		return route.NewRouteFromHops(amt, 144, source, hops)
	}

	backend := &RouterBackend{
		FindRoute: findRoute,
		SelfNode:  sourceKey,
		FetchChannelCapacity: func(chanID uint64) (
			btcutil.Amount, error) {

			return 1, nil
		},
		MissionControl: &mockMissionControl{},
	}

	ctxt, _ := context.WithTimeout(context.Background(), 20*time.Second)
	resp, err := backend.QueryRoutes(ctxt, request)
	if err != nil {
		t.Fatal(err)
	}

	// Check that the route has the proper source node.
	r := resp.Routes[0]
	if r.SourcePubKey != expectedRouteSource {
		t.Fatalf("unexpected route source. want: %s , got: %s", expectedRouteSource, r.SourcePubKey)
	}
}

func testQueryRoutes(t *testing.T, useMissionControl bool, useMsat bool,
	setTimelock bool) {

	ignoreNodeBytes, err := hex.DecodeString(ignoreNodeKey)
	if err != nil {
		t.Fatal(err)
	}

	var ignoreNodeVertex route.Vertex
	copy(ignoreNodeVertex[:], ignoreNodeBytes)

	destNodeBytes, err := hex.DecodeString(destKey)
	if err != nil {
		t.Fatal(err)
	}

	var (
		lastHop      = route.Vertex{64}
		outgoingChan = uint64(383322)
	)

	hintNode, err := route.NewVertexFromStr(hintNodeKey)
	if err != nil {
		t.Fatal(err)
	}

	rpcRouteHints := []*lnrpc.RouteHint{
		{
			HopHints: []*lnrpc.HopHint{
				{
					ChanId: 38484,
					NodeId: hintNodeKey,
				},
			},
		},
	}

	request := &lnrpc.QueryRoutesRequest{
		PubKey:         destKey,
		FinalCltvDelta: 100,
		IgnoredNodes:   [][]byte{ignoreNodeBytes},
		IgnoredEdges: []*lnrpc.EdgeLocator{{
			ChannelId:        555,
			DirectionReverse: true,
		}},
		IgnoredPairs: []*lnrpc.NodePair{{
			From: node1[:],
			To:   node2[:],
		}},
		UseMissionControl: useMissionControl,
		LastHopPubkey:     lastHop[:],
		OutgoingChanId:    outgoingChan,
		DestFeatures:      []lnrpc.FeatureBit{lnrpc.FeatureBit_MPP_OPT},
		RouteHints:        rpcRouteHints,
	}

	amtSat := int64(100000)
	if useMsat {
		request.AmtMsat = amtSat * 1000
		request.FeeLimit = &lnrpc.FeeLimit{
			Limit: &lnrpc.FeeLimit_FixedMsat{
				FixedMsat: 250000,
			},
		}
	} else {
		request.Amt = amtSat
		request.FeeLimit = &lnrpc.FeeLimit{
			Limit: &lnrpc.FeeLimit_Fixed{
				Fixed: 250,
			},
		}
	}

	findRoute := func(source, target route.Vertex,
		amt lnwire.MilliSatoshi, _ float64,
		restrictions *routing.RestrictParams, _ record.CustomSet,
		routeHints map[route.Vertex][]*channeldb.CachedEdgePolicy,
		finalExpiry uint16) (*route.Route, error) {

		if int64(amt) != amtSat*1000 {
			t.Fatal("unexpected amount")
		}

		if source != sourceKey {
			t.Fatal("unexpected source key")
		}

		if !bytes.Equal(target[:], destNodeBytes) {
			t.Fatal("unexpected target key")
		}

		if restrictions.FeeLimit != 250*1000 {
			t.Fatal("unexpected fee limit")
		}

		if restrictions.ProbabilitySource(route.Vertex{2},
			route.Vertex{1}, 0,
		) != 0 {
			t.Fatal("expecting 0% probability for ignored edge")
		}

		if restrictions.ProbabilitySource(ignoreNodeVertex,
			route.Vertex{6}, 0,
		) != 0 {
			t.Fatal("expecting 0% probability for ignored node")
		}

		if restrictions.ProbabilitySource(node1, node2, 0) != 0 {
			t.Fatal("expecting 0% probability for ignored pair")
		}

		if *restrictions.LastHop != lastHop {
			t.Fatal("unexpected last hop")
		}

		if restrictions.OutgoingChannelIDs[0] != outgoingChan {
			t.Fatal("unexpected outgoing channel id")
		}

		if !restrictions.DestFeatures.HasFeature(lnwire.MPPOptional) {
			t.Fatal("unexpected dest features")
		}

		if _, ok := routeHints[hintNode]; !ok {
			t.Fatal("expected route hint")
		}

		expectedProb := 1.0
		if useMissionControl {
			expectedProb = testMissionControlProb
		}
		if restrictions.ProbabilitySource(route.Vertex{4},
			route.Vertex{5}, 0,
		) != expectedProb {
			t.Fatal("expecting 100% probability")
		}

		hops := []*route.Hop{{}}
		return route.NewRouteFromHops(amt, 144, source, hops)
	}

	backend := &RouterBackend{
		FindRoute: findRoute,
		SelfNode:  sourceKey,
		FetchChannelCapacity: func(chanID uint64) (
			btcutil.Amount, error) {

			return 1, nil
		},
		MissionControl: &mockMissionControl{},
		FetchChannelEndpoints: func(chanID uint64) (route.Vertex,
			route.Vertex, error) {

			if chanID != 555 {
				t.Fatalf("expected endpoints to be fetched for "+
					"channel 555, but got %v instead",
					chanID)
			}
			return route.Vertex{1}, route.Vertex{2}, nil
		},
	}

	// If this is set, we'll populate MaxTotalTimelock. If this is not set,
	// the test will fail as CltvLimit will be 0.
	if setTimelock {
		backend.MaxTotalTimelock = 1000
	}

	resp, err := backend.QueryRoutes(context.Background(), request)

	// If no MaxTotalTimelock was set for the QueryRoutes request, make
	// sure an error was returned.
	if !setTimelock {
		require.NotEmpty(t, err)
		return
	}

	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Routes) != 1 {
		t.Fatal("expected a single route response")
	}
}

type mockMissionControl struct {
	MissionControl
}

func (m *mockMissionControl) GetProbability(fromNode, toNode route.Vertex,
	amt lnwire.MilliSatoshi) float64 {

	return testMissionControlProb
}

func (m *mockMissionControl) ResetHistory() error {
	return nil
}

func (m *mockMissionControl) GetHistorySnapshot() *routing.MissionControlSnapshot {
	return nil
}

func (m *mockMissionControl) GetPairHistorySnapshot(fromNode,
	toNode route.Vertex) routing.TimedPairResult {

	return routing.TimedPairResult{}
}

type recordParseOutcome byte

const (
	valid recordParseOutcome = iota
	invalid
	norecord
)

type unmarshalMPPTest struct {
	name    string
	mpp     *lnrpc.MPPRecord
	outcome recordParseOutcome
}

// TestUnmarshalMPP checks both positive and negative cases of UnmarshalMPP to
// assert that an MPP record is only returned when both fields are properly
// specified. It also asserts that zero-values for both inputs is also valid,
// but returns a nil record.
func TestUnmarshalMPP(t *testing.T) {
	tests := []unmarshalMPPTest{
		{
			name:    "nil record",
			mpp:     nil,
			outcome: norecord,
		},
		{
			name: "invalid total or addr",
			mpp: &lnrpc.MPPRecord{
				PaymentAddr:  nil,
				TotalAmtMsat: 0,
			},
			outcome: invalid,
		},
		{
			name: "valid total only",
			mpp: &lnrpc.MPPRecord{
				PaymentAddr:  nil,
				TotalAmtMsat: 8,
			},
			outcome: invalid,
		},
		{
			name: "valid addr only",
			mpp: &lnrpc.MPPRecord{
				PaymentAddr:  bytes.Repeat([]byte{0x02}, 32),
				TotalAmtMsat: 0,
			},
			outcome: invalid,
		},
		{
			name: "valid total and invalid addr",
			mpp: &lnrpc.MPPRecord{
				PaymentAddr:  []byte{0x02},
				TotalAmtMsat: 8,
			},
			outcome: invalid,
		},
		{
			name: "valid total and valid addr",
			mpp: &lnrpc.MPPRecord{
				PaymentAddr:  bytes.Repeat([]byte{0x02}, 32),
				TotalAmtMsat: 8,
			},
			outcome: valid,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			testUnmarshalMPP(t, test)
		})
	}
}

func testUnmarshalMPP(t *testing.T, test unmarshalMPPTest) {
	mpp, err := UnmarshalMPP(test.mpp)
	switch test.outcome {
	// Valid arguments should result in no error, a non-nil MPP record, and
	// the fields should be set correctly.
	case valid:
		if err != nil {
			t.Fatalf("unable to parse mpp record: %v", err)
		}
		if mpp == nil {
			t.Fatalf("mpp payload should be non-nil")
		}
		if int64(mpp.TotalMsat()) != test.mpp.TotalAmtMsat {
			t.Fatalf("incorrect total msat")
		}
		addr := mpp.PaymentAddr()
		if !bytes.Equal(addr[:], test.mpp.PaymentAddr) {
			t.Fatalf("incorrect payment addr")
		}

	// Invalid arguments should produce a failure and nil MPP record.
	case invalid:
		if err == nil {
			t.Fatalf("expected failure for invalid mpp")
		}
		if mpp != nil {
			t.Fatalf("mpp payload should be nil for failure")
		}

	// Arguments that produce no MPP field should return no error and no MPP
	// record.
	case norecord:
		if err != nil {
			t.Fatalf("failure for args resulting for no-mpp")
		}
		if mpp != nil {
			t.Fatalf("mpp payload should be nil for no-mpp")
		}

	default:
		t.Fatalf("test case has non-standard outcome")
	}
}

type unmarshalAMPTest struct {
	name    string
	amp     *lnrpc.AMPRecord
	outcome recordParseOutcome
}

// TestUnmarshalAMP asserts the behavior of decoding an RPC AMPRecord.
func TestUnmarshalAMP(t *testing.T) {
	rootShare := bytes.Repeat([]byte{0x01}, 32)
	setID := bytes.Repeat([]byte{0x02}, 32)

	// All child indexes are valid.
	childIndex := uint32(3)

	tests := []unmarshalAMPTest{
		{
			name:    "nil record",
			amp:     nil,
			outcome: norecord,
		},
		{
			name: "invalid root share invalid set id",
			amp: &lnrpc.AMPRecord{
				RootShare:  []byte{0x01},
				SetId:      []byte{0x02},
				ChildIndex: childIndex,
			},
			outcome: invalid,
		},
		{
			name: "valid root share invalid set id",
			amp: &lnrpc.AMPRecord{
				RootShare:  rootShare,
				SetId:      []byte{0x02},
				ChildIndex: childIndex,
			},
			outcome: invalid,
		},
		{
			name: "invalid root share valid set id",
			amp: &lnrpc.AMPRecord{
				RootShare:  []byte{0x01},
				SetId:      setID,
				ChildIndex: childIndex,
			},
			outcome: invalid,
		},
		{
			name: "valid root share valid set id",
			amp: &lnrpc.AMPRecord{
				RootShare:  rootShare,
				SetId:      setID,
				ChildIndex: childIndex,
			},
			outcome: valid,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			testUnmarshalAMP(t, test)
		})
	}
}

func testUnmarshalAMP(t *testing.T, test unmarshalAMPTest) {
	amp, err := UnmarshalAMP(test.amp)
	switch test.outcome {
	case valid:
		require.NoError(t, err)
		require.NotNil(t, amp)

		rootShare := amp.RootShare()
		setID := amp.SetID()
		require.Equal(t, test.amp.RootShare, rootShare[:])
		require.Equal(t, test.amp.SetId, setID[:])
		require.Equal(t, test.amp.ChildIndex, amp.ChildIndex())

	case invalid:
		require.Error(t, err)
		require.Nil(t, amp)

	case norecord:
		require.NoError(t, err)
		require.Nil(t, amp)

	default:
		t.Fatalf("test case has non-standard outcome")
	}
}
