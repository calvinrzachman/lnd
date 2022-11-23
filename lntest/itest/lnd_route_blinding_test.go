package itest

import (
	"context"
	"encoding/hex"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"

	sphinx "github.com/lightningnetwork/lightning-onion"
	"github.com/lightningnetwork/lnd/chainreg"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/routerrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
)

// func testMultiHopSendToBlindedRouteClean(net *lntest.NetworkHarness, t *harnessTest) {
// 	// ctxb := context.Background()
// 	t.Log("Route Blinding Test!")

// 	ctx := newMppTestContext(t, net)
// 	defer ctx.shutdownNodes()

// 	const (
// 		// NOTE: This test network setup does not configure wumbo channels.
// 		chanAmt    = btcutil.SatoshiPerBitcoin / 10
// 		paymentAmt = btcutil.Amount(1000)
// 	)

// 	// Set up a simple "linear" 4 node network.
// 	//
// 	// Alice <---> Bob <---> Carol <---> Dave
// 	//
// 	ctx.openChannel(ctx.alice, ctx.bob, chanAmt)
// 	ctx.openChannel(ctx.bob, ctx.carol, chanAmt)
// 	ctx.openChannel(ctx.carol, ctx.dave, chanAmt)
// 	defer ctx.closeChannels()

// 	ctx.waitForChannels()

// 	/*
// 		Method #2: Automatically build blinded route.

// 		- Given an introduction node, build the blinded route
// 		- Given nothing, find a suitable introduction node and
// 		  blinded route

// 	*/

// 	// Dave.BuildBlindRoute()
// 	// Dave.FindBlindRoute(amt)

// 	// lncli-dave buildblindroute —route
// 	// lncli-dave findblindroute —amt  —success-rate (?) —min-anon-set
// 	// lncli-alice sendpayment —amt < amount ? > —blind-route < Blind Route >
// 	// lncli-alice sendpayment --pay-req <LN Invoice> —blind-route < Blind Route > (eventually want to read blind route from invoice)

// }
// func testFinalHopDetermination(net *lntest.NetworkHarness, t *harnessTest) {
// 	ctxb := context.Background()
// 	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
// 	t.Log("Final Hop Determination!")

// 	// NOTE: There is a large difference between the "test context"
// 	// which provides all the functionality needed to create multi
// 	// node networks, create channels, etc. and the context from
// 	// Golang's standard library.
// 	ctx := newMppTestContext(t, net)
// 	defer ctx.shutdownNodes()

// 	// Channels are able to carry the exact size of the payment.
// 	const (
// 		// NOTE: This test network setup does not configure wumbo channels.
// 		chanAmt = btcutil.SatoshiPerBitcoin / 10
// 		// paymentAmt = chanAmt / 1000000
// 		paymentAmt = btcutil.Amount(1000)
// 	)

// 	// Set up a simple "linear" 4 node network.
// 	//
// 	// Alice <---> Bob <---> Carol <---> Dave
// 	//
// 	ctx.openChannel(ctx.alice, ctx.bob, chanAmt)
// 	ctx.openChannel(ctx.bob, ctx.carol, chanAmt)
// 	ctx.openChannel(ctx.carol, ctx.dave, chanAmt)
// 	defer ctx.closeChannels()

// 	ctx.waitForChannels()

// 	// For comparison's sake, build a normal route Alice --> Dave
// 	normalRouteReq := &lnrpc.QueryRoutesRequest{
// 		SourcePubKey:      ctx.alice.PubKeyStr, // implicit
// 		PubKey:            ctx.dave.PubKeyStr,
// 		Amt:               int64(paymentAmt),
// 		FinalCltvDelta:    chainreg.DefaultBitcoinTimeLockDelta,
// 		UseMissionControl: false,
// 	}

// 	rte, err := ctx.alice.QueryRoutes(ctxt, normalRouteReq)
// 	if err != nil {
// 		t.Fatalf("unable to build route: %v", err)
// 	}
// 	// br := routeResp.Route
// 	// There should only be one route to try, so take the first item.
// 	aliceToDave := rte.Routes[0]

// 	t.Logf("[Sender Computed]: Alice --> Dave lnrpc.Route{}: %+v, source: %s", aliceToDave, aliceToDave.SourcePubKey)
// 	t.Logf("[Sender Computed]: First Hop Pub Bytes: %+v", aliceToDave.Hops[0].PubKey)

// 	aliceRouterBackend := &routerrpc.RouterBackend{
// 		SelfNode: ctx.alice.PubKey,
// 		FetchChannelCapacity: func(chanID uint64) (btcutil.Amount, error) {
// 			return 0, nil
// 		},
// 	}

// 	rt, err := aliceRouterBackend.UnmarshallRoute(aliceToDave)
// 	if err != nil {
// 		t.Fatalf("unable to unmarshall route: %v", err)
// 	}

// 	// CRITICAL STEP: Set up an intermediate hop without a short_channel_id
// 	// of the next hop. NOTE: This says that hop #2 is not reachable by a
// 	// channel ID. This means that it is hop #1's payload which should be
// 	// missing short_channel_id.
// 	rt.Hops[1].ChannelID = 0

// 	// NOTE: A Sphinx "PaymentPath" is an array of "OnionHops" which themselves
// 	// are just a public key and a byte slice payload.
// 	paymentPath, err := rt.ToSphinxPath()
// 	if err != nil {
// 		t.Fatalf("unable to create sphinx path: %v", err)
// 	}

// 	// Next generate the onion routing packet which allows us to perform
// 	// privacy preserving source routing across the network.
// 	aliceSessionKeyBytes, _ := hex.DecodeString("e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734")
// 	aliceSessionKey, _ := btcec.PrivKeyFromBytes(aliceSessionKeyBytes)
// 	onionPkt, err := sphinx.NewOnionPacket(paymentPath, aliceSessionKey, nil, sphinx.DeterministicPacketFiller)
// 	if err != nil {
// 		t.Fatalf("unable to build onion packet: %v", err)
// 	}

// 	// Finally, encode Sphinx packet using its wire representation to be
// 	// included within the HTLC add packet.
// 	var onionBlob bytes.Buffer
// 	if err := onionPkt.Encode(&onionBlob); err != nil {
// 		t.Fatalf("unable to encode onion packet: %v", err)
// 	}

// 	// Craft an HTLC packet to send to the layer 2 switch. The
// 	// metadata within this packet will be used to route the
// 	// payment through the network, starting with the first-hop.
// 	htlcAdd := &lnwire.UpdateAddHTLC{
// 		Amount: rt.TotalAmount,
// 		Expiry: rt.TotalTimeLock,
// 		// PaymentHash: hash,
// 	}
// 	copy(htlcAdd.OnionBlob[:], onionBlob.Bytes())

// 	// // Configure our sphinx onion packet router with
// 	// // our node's key pair (p, P).
// 	// sphinxRouter := sphinx.NewRouter(
// 	// 	nodeKeyECDH, cfg.ActiveNetParams.Params, replayLog,
// 	// )

// 	// Send it to the Switch. When this method returns we assume
// 	// the Switch successfully has persisted the payment attempt,
// 	// such that we can resume waiting for the result after a
// 	// restart.
// 	ctx.alice.ChannelRouter.
// 	err := p.router.cfg.Payer.SendHTLC(
// 		firstHop, attempt.AttemptID, htlcAdd,
// 	)

// }

// Route Blinding
//
// NOTE: We can write a test which assumes the creation of a blinded route
// and verifies that Alice is able to use it to blindly pay Dave.
// We can alos write a test in which Dave creates a blinded route, shares it
// with Alice, and then Alice uses it to blindly pay Dave without learning
// his persistent network identifier.
func testMultiHopSendToBlindedRoute(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()
	t.Log("Route Blinding Test!")

	// NOTE: There is a large difference between the "test context"
	// which provides all the functionality needed to create multi
	// node networks, create channels, etc. and the context from
	// Golang's standard library.
	ctx := newMppTestContext(t, net)
	defer ctx.shutdownNodes()

	// Channels are able to carry the exact size of the payment.
	const (
		// NOTE: This test network setup does not configure wumbo channels.
		chanAmt = btcutil.SatoshiPerBitcoin / 10
		// paymentAmt = chanAmt / 1000000
		paymentAmt = btcutil.Amount(1000)
	)

	// Set up a simple "linear" 4 node network.
	//
	// Alice <---> Bob <---> Carol <---> Dave
	//
	ctx.openChannel(ctx.alice, ctx.bob, chanAmt)
	ctx.openChannel(ctx.bob, ctx.carol, chanAmt)
	ctx.openChannel(ctx.carol, ctx.dave, chanAmt)
	defer ctx.closeChannels()

	ctx.waitForChannels()

	// ctx.alice.LightningClient.UpdateChannelPolicy()

	// Make Dave create an invoice containing a
	// blinded route from bob to himself for Alice to pay.
	// payReqs, rHashes, invoices, err := createBlindedPayReqs(
	payReqs, rHashes, _, err := createPayReqs(
		ctx.dave, paymentAmt, 1,
	)
	if err != nil {
		t.Fatalf("unable to create pay reqs: %v", err)
	}

	// Reconstruct the payment address.
	var payAddr []byte
	for _, payReq := range payReqs {
		ctxt, _ := context.WithTimeout(
			context.Background(), defaultTimeout,
		)
		resp, err := ctx.dave.DecodePayReq(
			ctxt,
			&lnrpc.PayReqString{PayReq: payReq},
		)
		if err != nil {
			t.Fatalf("decode pay req: %v", err)
		}
		payAddr = resp.PaymentAddr
	}

	rHash := rHashes[0]
	// payReq := payReqs[0]

	// Construct a closure that will set MPP fields on the route, which
	// allows us to test MPP payments.
	setMPPFields := func(r *lnrpc.Route) {
		hop := r.Hops[len(r.Hops)-1]
		hop.TlvPayload = true
		hop.MppRecord = &lnrpc.MPPRecord{
			PaymentAddr:  payAddr,
			TotalAmtMsat: int64(paymentAmt) * 1000,
		}
		t.Logf("Final Hop & MPP Record: %+v, %+v", hop, hop.MppRecord)
	}

	// blindRoute, err := ctx.buildBlindedRoute(ctxb, paymentAmt, ctx.alice, routeToIntroNode)
	// if err != nil {
	// 	t.Fatalf("unable to build route: %v", err)
	// }

	// Method #1: Manually build blinded route.

	// completeRoute := rt.ExtendRouteWithHops(blindedRoute.Hops)
	// // completeRoute := rt.ExtendRouteWithHops(rt.Hops)
	// rpcRoute, _ := routerBackend.MarshallRoute(completeRoute)

	// route.NewRouteFromHops(amtToSend lnwire.MilliSatoshi, timeLock uint32, sourceVertex route.Vertex, hops []*route.Hop)

	// NOTE: Dave constructs the blinded route from Bob
	// to himself. Alice pays to the blinded route.
	// payload := bytes.Repeat([]byte("a"), 32)
	// realPayload := NewBlindHopPayload()
	alicePubKey, _ := btcec.ParsePubKey(ctx.alice.PubKey[:])
	bobPubKey, _ := btcec.ParsePubKey(ctx.bob.PubKey[:])
	carolPubKey, _ := btcec.ParsePubKey(ctx.carol.PubKey[:])
	davePubKey, _ := btcec.ParsePubKey(ctx.dave.PubKey[:])
	daveSessionKeyBytes, _ := hex.DecodeString("e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734")
	daveSessionKey, _ := btcec.PrivKeyFromBytes(daveSessionKeyBytes)

	t.Logf("Alice: %x - bytes: %v", alicePubKey.SerializeCompressed(), alicePubKey.SerializeCompressed())
	t.Logf("Bob: %x - bytes: %v", bobPubKey.SerializeCompressed(), bobPubKey.SerializeCompressed())
	t.Logf("Carol: %x - bytes: %v", carolPubKey.SerializeCompressed(), carolPubKey.SerializeCompressed())
	t.Logf("Dave: %x - bytes: %v", davePubKey.SerializeCompressed(), davePubKey.SerializeCompressed())

	// sendToNormalRouteReq := &routerrpc.SendToRouteRequest{
	// 	PaymentHash: rHash,
	// 	Route:       aliceToDave,
	// }

	// resp, err := ctx.alice.RouterClient.SendToRouteV2(ctxt, sendToNormalRouteReq)
	// if err != nil {
	// 	t.Fatalf("[Alice --> Dave]: unable to send normal payment: %v", err)
	// }
	// if resp.Failure != nil {
	// 	t.Fatalf("[Alice --> Dave]: received payment error: %v", resp.Failure)
	// }

	// Blinded Route Creation
	// introductionNode := FindIntroductionNode() // bob
	// route := FindRoute(introductionNode, myself) // NOTE: be sure to include introduction node, hop, …, myself
	routeFromIntroNodeToRecipient := []*lntest.HarnessNode{
		ctx.bob,
		ctx.carol,
		ctx.dave,
	}

	// Build a route for the specified hops.
	rpcHops := make([][]byte, 0, len(routeFromIntroNodeToRecipient))
	for _, hop := range routeFromIntroNodeToRecipient {
		k := hop.PubKeyStr
		pubkey, err := route.NewVertexFromStr(k)
		if err != nil {
			t.Fatalf("unable to construct build route request: %v", err)
		}
		rpcHops = append(rpcHops, pubkey[:])
	}

	// req := &routerrpc.BuildRouteRequest{
	// 	AmtMsat:        int64(paymentAmt * 1000),
	// 	FinalCltvDelta: chainreg.DefaultBitcoinTimeLockDelta,
	// 	HopPubkeys:     rpcHops,
	// }

	// routeBlindingRawFeatures := lnwire.NewRawFeatureVector(
	// 	lnwire.TLVOnionPayloadOptional,
	// 	lnwire.RouteBlindingOptional,
	// )

	// routeBlindingFeatures := lnwire.NewFeatureVector(
	// 	routeBlindingRawFeatures, lnwire.Features,
	// )

	// If no destination features were specified, we set
	// those necessary for AMP payments.
	routeBlindingFeatures := []lnrpc.FeatureBit{
		lnrpc.FeatureBit_TLV_ONION_OPT,
		lnrpc.FeatureBit_ROUTE_BLINDING_OPT,
	}

	// Query Dave's router for routes to pay from Bob to Dave.
	// Here we restrict our search to only nodes which support
	// route blinding. NOTE(8/27/22): May need to configure nodes with this.
	// ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	routesReq := &lnrpc.QueryRoutesRequest{
		SourcePubKey: ctx.bob.PubKeyStr,
		// SourcePubKey:      ctx.carol.PubKeyStr,
		PubKey:            ctx.dave.PubKeyStr,
		Amt:               int64(paymentAmt),
		FinalCltvDelta:    2 * chainreg.DefaultBitcoinTimeLockDelta,
		UseMissionControl: false,
		HopFeatures:       routeBlindingFeatures,
		DestFeatures:      routeBlindingFeatures,
	}

	// routeResp, err := ctx.dave.RouterClient.BuildRoute(ctxt, req)
	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	routes, err := ctx.dave.QueryRoutes(ctxt, routesReq)
	// routeResp, err := ctx.dave.RouterClient.FindRoute(ctxt, req)
	// br, err := ctx.buildRoute(ctxb, paymentAmt, ctx.dave, routeFromIntroNodeToRecipient)
	if err != nil {
		t.Fatalf("unable to build route: %v", err)
	}
	// br := routeResp.Route
	// There should only be one route to try, so take the first item.
	br := routes.Routes[0]

	t.Logf("[Recipient Computed]: Bob --> Dave lnrpc.Route{}: %+v, source: %s", br, br.SourcePubKey)
	t.Logf("[Recipient Computed]: First Hop Pub Bytes: %+v", br.Hops[0].PubKey)

	daveRouterBackend := &routerrpc.RouterBackend{
		SelfNode: ctx.dave.PubKey,
		FetchChannelCapacity: func(chanID uint64) (btcutil.Amount, error) {
			return 0, nil
		},
	}
	brt, err := daveRouterBackend.UnmarshallRoute(br)
	if err != nil {
		t.Fatalf("unable to unmarshall route: %v", err)
	}

	t.Logf("[Recipient Computed]: Bob --> Dave route.Route{}: %+v, source: %s", brt, brt.SourcePubKey)
	t.Logf("[Recipient Computed]: First Hop Pub Bytes: %+v", brt.Hops[0].PubKeyBytes)
	// t.Logf("To-be Blinded Route Source: %+v", brt.SourcePubKey)
	t.Logf("[Recipient Computed]: To-be Blinded Route Hops: %+v", brt.Hops)

	// brt.Blind()
	brt.FinalHop().BlindHopPayload.PathID = rHash

	// Compute the route blinding TLV payloads for each hop in this route.
	// routeBlindingPayloads, err := route.Blind()
	// These "hops to blinded" will each need a TLV route blinding payload.
	// The final hop should be us and will need a few extra fields set!
	// hopsToBeBlinded, aggregateRouteParams, err := brt.ToSphinxBlindPath()
	hopsToBeBlinded, err := brt.ToSphinxBlindPath()
	if err != nil {
		t.Fatalf("unable to prep the hops to be blinded: %v", err)
	}
	for i, hop := range hopsToBeBlinded {
		t.Logf("(Before blinding) Hop %d:", i)
		t.Logf("\tPublic Key: %+v", hop.NodePub.SerializeCompressed())
		t.Logf("\tRoute Blinding Payload: %+v", hop.Payload)
		// t.Logf("\tRoute Blinding Payload: %+v", hop.Payload)
		if i < len(brt.Hops) {
			t.Logf("\tNext Hop (BlindHopPayload struct): %+v\n", brt.Hops[i].BlindHopPayload.NextHop)
			t.Logf("\tNext Hop (Hop struct): %+v\n", brt.Hops[i].ChannelID)
		}
	}

	// Provide each persistent node ID public key in the route along with a
	// TLV route blinding payload to the route blinding constructor function
	// which will take care of blinding each public key and encrypting the
	// TLV route blinding payload.
	//
	// TODO(7/22/22): Construct proper TLV payloads for the route.
	blindRoute, err := sphinx.BuildBlindedPath(daveSessionKey, hopsToBeBlinded)
	// blindRoute, err := sphinx.BuildBlindedPath(daveSessionKey, []*sphinx.BlindedPathHop{
	// 	{
	// 		NodePub: bobPubKey,
	// 		Payload: payload,
	// 	},
	// 	{
	// 		NodePub: carolPubKey,
	// 		Payload: payload,
	// 	},
	// 	{
	// 		NodePub: davePubKey,
	// 		Payload: payload,
	// 	},
	// })
	// blindRoute, err := sphinx.NewBlindedRoute(daveSessionKey, []*btcec.PublicKey{
	// 	bobPubKey,
	// 	carolPubKey,
	// 	davePubKey,
	// }, [][]byte{
	// 	// TLV packed route blinding payloads
	// 	payload,
	// 	payload,
	// 	payload,
	// })
	if err != nil {
		t.Fatalf("unable to build blinded route: %v", err)
	}

	// for i, hop := range completeRoute.Hops {
	// 	t.Logf("Route Hop %d:", i)
	// 	pubBytes, err := hex.DecodeString(hop.PubKeyBytes.String())
	// 	if err != nil {
	// 		t.Fatalf("unable to translate hex string to bytes: %v", err)
	// 	}
	// 	t.Logf("\tHop ID Public Key: %+v", pubBytes)
	// 	if hop.BlindingPoint != nil {
	// 		t.Logf("\tEphemeral Blinding Point: %+v", hop.BlindingPoint.SerializeCompressed())
	// 	}
	// 	t.Logf("\tEncrypted Payload: %+v", hop.RecipientEncryptedData)
	// 	t.Logf("\tNext Channel ID: %+v", hop.ChannelID)
	// }

	t.Logf("Blinded Route Introduction Node: %+v", blindRoute.IntroductionPoint.SerializeCompressed())
	t.Logf("First Ephemeral Blinding Point: %+v", blindRoute.BlindingPoint.SerializeCompressed())
	t.Logf("Blinded Route Hops: %+v", blindRoute.BlindedHops)
	for i, hop := range blindRoute.BlindedHops {
		t.Logf("Blinded Hop %d:", i)
		t.Logf("\tBlinded ID Public Key: %+v", hop.SerializeCompressed())
		// t.Logf("\tEphemeral Blinding Point: %+v", hop.EphemeralBlindingPoint.SerializeCompressed())
		t.Logf("\tEncrypted Payload: %+v", blindRoute.EncryptedData[i])
	}

	// t.Logf("Blinded Route Introduction Node: %+v", blindRoute.IntroductionNode.PublicKey.SerializeCompressed())
	// t.Logf("Blinded Route Hops: %+v", blindRoute.BlindedNodes)
	// for i, hop := range blindRoute.BlindedNodes {
	// 	t.Logf("Blinded Hop %d:", i)
	// 	t.Logf("\tBlinded ID Public Key: %+v", hop.BlindedPublicKey.SerializeCompressed())
	// 	t.Logf("\tEphemeral Blinding Point: %+v", hop.EphemeralBlindingPoint.SerializeCompressed())
	// 	t.Logf("\tEncrypted Payload: %+v", hop.EncryptedData)
	// }

	// var blindedRoute *route.Route

	/*
		Now that Dave has built a blinded route to himself
		he can share it with Alice. Alice can then find a
		path from herself to the introduction node (Bob).

		NOTE: Alice does NOT know the amount forwarded/fees taken
		by each hop in the blinded portion of the route, nor does
		she know the worst case HTLC processing time (ctlv delta)
		for each hop in the blinded portion of the route.
		Instead Alice knows the aggregate/sum total of amount/fee & timelock
		across the blinded route as a whole.

		Alice MUST make use of the aggregate amt/fee & timelock parameters
		when building her route to the introduction node, otherwise
		the forwarding parameters will be malformed (discontinuous) at the
		boundary between normal and blinded portion of the route. In such a
		scenario Alice may not deliver sufficient funds to the introduction node,
		or she may not allow sufficient time for blinded forwarding nodes
		to process the HTLC safely according to the CLTV delta in their channel policy.

		Alice must ensure that the combined route (normal, blinded) is constructed
		such that each blinded forwarding node can:
		- claim a fee >= the fee it requires for routing.
		- give itself enough time (via its required CLTV delta) to process
		  the HTLC safely.

		To do this she must shift the TotalAmount and TotalCLTV for the route
		by the aggregate amount and timelock for the blinded portion of the route.

		In other words she knows how much she needs to deliver
		to the introduction node.

		Alice MUST:
		- Deliver the proper amount to the introduction node
		- Provide enough time for each node to meet its worst case HTLC processing time.

		Example of knowledge from Alice's perspective:
		- Pay 100 sats to blinded recipient
		- Deliver 120 sats to blinded route introduction node (Bob)
		- Permit the introduction node a cltv delta of X for the entire route
		  so that blinded forwarding nodes have time to process the HTLC safely.
		- Blinded route is 2 hops with 20 sats reserved for forwarding fees and
		  requires 200 blocks of worst case processing time

	*/

	// Alice will receive this information from the recipient.
	aggregateAmt := 40
	aggregateTimelock := 80

	// Alice will attempt to pay to the blinded route.
	// She will find/construct/use a route from herself to the introductory node
	// of the blinded route (Bob in this simple test case).
	// She will then extend this route with the blinded route information.
	routeToIntroNode := []*lntest.HarnessNode{
		ctx.alice, ctx.bob,
	}

	// Build a route for the specified hops.
	// r, err := ctx.buildRoute(ctxb, paymentAmt, ctx.alice, routeToIntroNode)
	r, err := ctx.buildRouteWithBlindedOffset(ctxb, paymentAmt+btcutil.Amount(aggregateAmt), int32(aggregateTimelock), ctx.alice, routeToIntroNode)
	if err != nil {
		t.Fatalf("unable to build route: %v", err)
	}
	t.Logf("[Sender Computed]: Alice --> Bob lnrpc.Route{}: %+v, source: %s", r, r.SourcePubKey)
	t.Logf("[Sender Computed]: First Hop Pub Bytes: %+v", r.Hops[0].PubKey)

	// NOTE(7/24/22): This is a pretty barebones router backend.
	// Is it sufficiently functional for our purposes?
	routerBackend := &routerrpc.RouterBackend{
		SelfNode: ctx.alice.PubKey,
		FetchChannelCapacity: func(chanID uint64) (btcutil.Amount, error) {
			return 0, nil
		},
	}
	rt, err := routerBackend.UnmarshallRoute(r)
	if err != nil {
		t.Fatalf("unable to unmarshall route: %v", err)
	}

	t.Logf("[Sender Computed]: route.Route{} Source: %+v", rt.SourcePubKey)
	t.Logf("[Sender Computed]: route.Route{} Hops: %+v", rt.Hops)

	// For comparison's sake, build a normal route Alice --> Dave
	normalRouteReq := &lnrpc.QueryRoutesRequest{
		SourcePubKey:      ctx.alice.PubKeyStr, // implicit
		PubKey:            ctx.dave.PubKeyStr,
		Amt:               int64(paymentAmt),
		FinalCltvDelta:    chainreg.DefaultBitcoinTimeLockDelta,
		UseMissionControl: false,
	}

	rte, err := ctx.alice.QueryRoutes(ctxt, normalRouteReq)
	if err != nil {
		t.Fatalf("unable to build route: %v", err)
	}
	// br := routeResp.Route
	// There should only be one route to try, so take the first item.
	aliceToDave := rte.Routes[0]

	t.Logf("[Sender Computed]: Alice --> Dave lnrpc.Route{}: %+v, source: %s", aliceToDave, aliceToDave.SourcePubKey)
	t.Logf("[Sender Computed]: First Hop Pub Bytes: %+v", aliceToDave.Hops[0].PubKey)

	// bRoute, err := route.FromSphinxRoute(blindRoute, 10, 0)
	// completeRoute, err := rt.ExtendRouteStrict(bRoute)

	// TODO(7/22/22): I think this is slightly off in that it double
	// counts the introduction node. Investigate.
	// TODO(9/11/22): Figure out how to properly pass timelock here
	// finalHopParams?
	// completeRoute, err := rt.AddBlindExtension(lnwire.MilliSatoshi(paymentAmt), 100, blindRoute)
	_, curHeight, _ := net.Miner.Client.GetBestBlock()
	expectedFinalCltv := curHeight + chainreg.DefaultBitcoinTimeLockDelta
	completeRoute, err := rt.AddBlindExtension(
		lnwire.NewMSatFromSatoshis(paymentAmt),
		uint32(expectedFinalCltv), blindRoute,
	)
	t.Logf("Complete Route Total Timelock: %d", completeRoute.TotalTimeLock)
	// ctx.dave.

	// bRoute, _ := route.FromSphinxRoute(blindRoute, paymentAmt, 0)
	// If our method instead accepts the pubkeys for each hop
	// bRoute, _ := route.New(blindRoute.Hops, paymentAmt, 0)
	// completeRoute := rt.ExtendRouteWithHops(bRoute.Hops)
	// completeRoute := rt.ExtendRoute(bRoute)
	// completeRoute, err := rt.ExtendRouteStrict(bRoute)
	if err != nil {
		t.Fatalf("unable to extend route with blinded route: %v", err)
	}
	t.Logf("Complete Route: %+v", completeRoute.Hops)
	t.Logf("Complete Route string: %+v", completeRoute.String())
	for i, hop := range completeRoute.Hops {
		t.Logf("Route Hop %d:", i)
		pubBytes, err := hex.DecodeString(hop.PubKeyBytes.String())
		if err != nil {
			t.Fatalf("unable to translate hex string to bytes: %v", err)
		}
		t.Logf("\tHop ID Public Key: %+v", pubBytes)
		if hop.BlindingPoint != nil {
			t.Logf("\tEphemeral Blinding Point: %+v", hop.BlindingPoint.SerializeCompressed())
		}
		t.Logf("\tEncrypted Payload: %+v", hop.RouteBlindingEncryptedData)
		t.Logf("\tChannel ID: %+v", hop.ChannelID)
	}

	// NOTE (7/22/22): Ensure that we don't lose information when
	// converting from a route.Route{} to an lnrpc.Route{}
	lnrpcRoute, err := routerBackend.MarshallRoute(completeRoute)
	if err != nil {
		t.Fatalf("unable to marshal to lnrpc route: %v", err)
	}

	// NOTE(8/7/22): Recipients use "payment addresses" to prevent
	// probing. This is required for dave to accept the payment.
	setMPPFields(lnrpcRoute)

	// t.Logf("Route Blinding Info in lnrpc route: %+v", lnrpcRoute.Hops[0])
	t.Logf("After converting to an lnrpc.Route{}: %+v", lnrpcRoute)
	for i, hop := range lnrpcRoute.Hops {
		t.Logf("Route Hop %d:", i)
		pubBytes, err := hex.DecodeString(hop.PubKey)
		if err != nil {
			t.Fatalf("unable to translate hex string to bytes: %v", err)
		}
		t.Logf("\tHop ID Public Key: %+v", pubBytes)
		if hop.RouteBlindingRecord.BlindingPoint != "" {
			// if hop.RouteBlindingRecord.BlindingPoint != nil {
			bpBytes, err := hex.DecodeString(hop.RouteBlindingRecord.BlindingPoint)
			if err != nil {
				t.Fatalf("unable to translate hex string to bytes: %v", err)
			}
			bp, err := btcec.ParsePubKey(bpBytes)
			if err != nil {
				t.Fatalf("unable to translate hex string to bytes: %v", err)
			}
			t.Logf("\tEphemeral Blinding Point: %+v", bp.SerializeCompressed())
		}
		t.Logf("\tEncrypted Payload: %+v", hop.RouteBlindingRecord.EncryptedPayload)
		// t.Logf("\tNext Channel ID: %+v", hop.ChannelID)
	}

	// IntroEphemeralBlindingPoint PublicKey
	// BlindedHopIDs []PublicKey
	// Encrypted Payloads[][]byte

	// aliceSessionKey := daveSessionKey
	// NOTE: A Sphinx "PaymentPath" is an array of "OnionHops" which themselves
	// are just a public key and a byte slice payload.
	// paymentPath, err := completeRoute.ToSphinxPath()
	// sphinx.NewOnionPacket(nil, aliceSessionKey, nil, sphinx.DeterministicPacketFiller)

	// We can take the entire route (blinded or otherwise)
	// and set it up for Onion packet creation.
	// paymentPath, err := completeRoute.ToSphinxPath()
	// onionPkt, _ := sphinx.NewOnionPacket(paymentPath, &btcec.PrivateKey{}, []byte{}, nil)

	// bRoute, err := route.ParseRoute(nil)
	// rt.ExtendRouteWithHops(bRoute.Hops)
	// rt.ExtendRoute(bRoute)
	// rt.ExtendRouteStrict(bRoute)

	// If we create blinded routes in the Sphinx/Onion package then
	// we need some way to convert between that package and the routing
	// package? An interface?
	// rt.ExtendRoute(blindRoute.BlindedNodes)

	// // Build a route for the specified hops.
	// route, err := ctx.buildRoute(ctxb, paymentAmt, ctx.alice, routeToIntroNode)
	// if err != nil {
	// 	t.Fatalf("unable to build route: %v", err)
	// }

	// METHOD #2: Obtain blinded route from invoice
	//
	// TODO (4/17/22): Learn more about invoice structure. Where is the
	// blinded route included?
	//
	// NOTE: This part might be useful when we're ready to read blinded route
	// information from invoices. Until then we will manually create
	// blinded hops and have Alice add them as an extension to her route.
	// // Alice, having received a blinded route from Dave's invoice
	// // Alice is not able to construct a route directly to Dave.
	// // Rather she constructs a route from herself to the  Bob for each of the invoices
	// // created above.  We set FinalCltvDelta to 40 since by default
	// // QueryRoutes returns the last hop with a final cltv delta of 9 where
	// // as the default in htlcswitch is 40.
	// routesReq := &lnrpc.QueryRoutesRequest{
	// 	PubKey:         bob.PubKeyStr,
	// 	Amt:            paymentAmt,
	// 	FinalCltvDelta: chainreg.DefaultBitcoinTimeLockDelta,
	// }
	// ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	// routes, err := alice.QueryRoutes(ctxt, routesReq)
	// if err != nil {
	// 	t.Fatalf("unable to get route: %v", err)
	// }

	// We need to use our blinded route here!!
	sendReq := &routerrpc.SendToRouteRequest{
		PaymentHash: rHash,
		Route:       lnrpcRoute,
	}

	sendToRouteAndAssertSuccess(t, ctx.alice, sendReq)

	// ctxt, _ = context.WithTimeout(ctxb, defaultTimeout)

	// // // // METHOD 2 (cont.): Pay to Blinded Route from Invoice
	// // // // resp, err := ctx.alice.RouterClient.SendPaymentV2(ctxt, &routerrpc.SendPaymentRequest{
	// // // // 	PaymentRequest: "payment request with route blinding",
	// // // // })
	// resp, err := ctx.alice.RouterClient.SendToRouteV2(ctxt, sendReq)
	// if err != nil {
	// 	t.Fatalf("unable to send payment: %v", err)
	// }

	// if resp.Failure != nil {
	// 	t.Fatalf("received payment error: %v", resp.Failure)
	// }

	t.Log("Successfully sent payment to blinded route!")
	// ctx.dave.WalletBalance(ctx context.Context, in *lnrpc.WalletBalanceRequest, opts ...grpc.CallOption)

	// TODO(8/14/22):
	// - Cleanup this file
	// - Add tests in which a failure during blinded route processing occurs.
}
