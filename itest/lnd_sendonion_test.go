package itest

import (
	"context"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	sphinx "github.com/lightningnetwork/lightning-onion"
	"github.com/lightningnetwork/lnd/htlcswitch"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/routerrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
)

// const (
// 	defaultTimeout = 30 * time.Second
// )

func testSendOnion(ht *lntest.HarnessTest) {
	// Create a four-node context consisting of Alice, Bob and two new
	// nodes: Carol and Dave. This provides a 4 node, 3 channel topology.
	// Alice will make a channel with Bob, and Bob with Carol, and Carol
	// with Dave such that we arrive at the network topology:
	//     Alice -> Bob -> Carol -> Dave
	alice, bob := ht.Alice, ht.Bob
	carol := ht.NewNode("carol", nil)
	dave := ht.NewNode("dave", nil)

	// Connect nodes to ensure propagation of channels.
	ht.EnsureConnected(alice, bob)
	ht.EnsureConnected(bob, carol)
	ht.EnsureConnected(carol, dave)

	const chanAmt = btcutil.Amount(100000)

	// Open a channel with 100k satoshis between Alice and Bob with Alice
	// being the sole funder of the channel.
	chanPointAlice := ht.OpenChannel(
		alice, bob, lntest.OpenChannelParams{Amt: chanAmt},
	)
	defer ht.CloseChannel(alice, chanPointAlice)

	// We'll create Dave and establish a channel to Alice. Dave will be
	// running an older node that requires the legacy onion payload.
	ht.FundCoins(btcutil.SatoshiPerBitcoin, dave)
	chanPointBob := ht.OpenChannel(
		bob, carol, lntest.OpenChannelParams{Amt: chanAmt},
	)
	defer ht.CloseChannel(bob, chanPointBob)

	// Next, we'll create Carol and establish a channel to from her to
	// Dave.
	ht.FundCoins(btcutil.SatoshiPerBitcoin, carol)
	chanPointCarol := ht.OpenChannel(
		carol, dave, lntest.OpenChannelParams{Amt: chanAmt},
	)
	defer ht.CloseChannel(carol, chanPointCarol)

	// Make sure Alice knows the channel between Bob and Carol.
	ht.AssertTopologyChannelOpen(alice, chanPointBob)
	ht.AssertTopologyChannelOpen(alice, chanPointCarol)

	const (
		numPayments = 1
		paymentAmt  = 10000
	)

	// Request an invoice from Dave so he is expecting payment.
	_, rHashes, invoices := ht.CreatePayReqs(dave, paymentAmt, numPayments)
	var preimage lntypes.Preimage
	copy(preimage[:], invoices[0].RPreimage)

	// Query for routes to pay from Alice to Dave.
	routesReq := &lnrpc.QueryRoutesRequest{
		PubKey: dave.PubKeyStr,
		Amt:    paymentAmt,
		// AmtMsat: paymentAmt,
	}
	routes := alice.RPC.QueryRoutes(routesReq)
	route := routes.Routes[0]
	finalHop := route.Hops[len(route.Hops)-1]
	finalHop.MppRecord = &lnrpc.MPPRecord{
		PaymentAddr:  invoices[0].PaymentAddr,
		TotalAmtMsat: int64(lnwire.NewMSatFromSatoshis(paymentAmt)),
	}

	ht.Logf("Found route from Alice to Dave: %+v", route)

	// Construct an onion for the route from Alice to Dave.
	paymentHash := rHashes[0]
	onionReq := &routerrpc.BuildOnionRequest{
		Route:       route,
		PaymentHash: paymentHash,
	}
	onionResp := alice.RPC.BuildOnion(onionReq)
	ht.Logf("Constructed onion: %+v w/ key: %x", onionResp.OnionBlob,
		onionResp.SessionKey)

	// Dispatch a payment via the SendOnion RPC.
	firstHop := bob.PubKey
	sendReq := &routerrpc.SendOnionRequest{
		FirstHopPubkey: firstHop[:],
		Amount:         route.TotalAmtMsat,
		Timelock:       route.TotalTimeLock,
		PaymentHash:    paymentHash,
		OnionBlob:      onionResp.OnionBlob,
		AttemptId:      0,
	}
	ht.Logf("Sending onion w/ amt=%d (msat) to %x",
		sendReq.Amount, firstHop)

	// NOTE(calvin): We may want our wrapper RPC client to allow errors
	// through so that we can make some assertions about them in various
	// scenarios.
	// resp, err := alice.RPC.SendOnion(onionReq)
	// require.NoError(ht, err, "unable to send payment via onion")
	resp := alice.RPC.SendOnion(sendReq)
	ht.Logf("SendOnion response: %+v", resp)
	ht.Logf("Alice Pubkey: %x", alice.PubKey)
	ht.Logf("Bob Pubkey: %x", bob.PubKey)
	ht.Logf("Carol Pubkey: %x", carol.PubKey)
	ht.Logf("Dave Pubkey: %x", dave.PubKey)

	// Finally, check that the Alice's payment is correctly marked
	// succeeded.
	//
	// NOTE(calvin): We are not able to lookup the payment using normal
	// means currently. I think this is because we deliver the onion
	// directly to the switch without persisting any record via Control
	// Tower as is done by the ChannelRouter for other payments!
	// ht.AssertPaymentStatus(alice, preimage, lnrpc.Payment_SUCCEEDED)
	// ht.AssertAmountPaid()

	// Query for the result of the payment via onion!
	//
	// NOTE(calvin): This currently blocks until payment success/failure.
	trackReq := &routerrpc.TrackOnionRequest{
		AttemptId:   0,
		PaymentHash: paymentHash,
		SessionKey:  onionResp.SessionKey,
		HopPubkeys:  onionResp.HopPubkeys,
		// SharedSecrets: [][]byte,
	}
	trackResp := alice.RPC.TrackOnion(trackReq)
	ht.Logf("Tracked payment via onion: %+v", trackResp)
	require.Equal(ht, invoices[0].RPreimage, trackResp.Preimage)

	// The invoice should show as settled for Dave.
	ht.AssertInvoiceSettled(dave, invoices[0].PaymentAddr)

	// TODO(calvin): Other things to check:
	// - Error conditions/handling (server handles with decryptor or caller
	//   handles encrypted error blobs from server)
	// - That we successfully convert pubkey --> channel when there are
	//   multiple channels, some of which can carry the payment and other
	//   which cannot.
	// - Send the same onion again. Send the same onion again but mark it
	//   with a different attempt ID.
	//
	// If we send again, our node does forward the onion but the first hop
	// considers it a replayed onion.
	// 2024-05-01 15:54:18.364 [ERR] HSWC: unable to process onion packet: sphinx packet replay attempted
	// 2024-05-01 15:54:18.364 [ERR] HSWC: ChannelLink(a680b373941e2e056e7b98007cc8cee933331e28981474b34d4275bb94cd17fe:0): unable to decode onion hop iterator: InvalidOnionVersion
	// 2024-05-01 15:54:18.364 [DBG] PEER: Peer(0352f454dd5e09cd3e979cbace6fc6727cfa9a1eaa878a452ce63b221f51771a74): Sending UpdateFailMalformedHTLC(chan_id=fe17cd94bb75424db3741498281e3333e9cec87c00987b6e052e1e9473b380a6, id=1, fail_code=InvalidOnionVersion) to 0352f454dd5e09cd3e979cbace6fc6727cfa9a1eaa878a452ce63b221f51771a74@127.0.0.1:63567
	// If we randomize the payment hash, first hop says bad HMAC.
	//
	// - Send different onion but with same attempt ID.
}

func testTrackOnion(ht *lntest.HarnessTest) {
	// Create a four-node context consisting of Alice, Bob and two new
	// nodes: Carol and Dave. This will provide a 4 node, 3 channel topology.
	// Alice will make a  channel with Bob, and Bob with Carol, and Carol
	// with Dave such that we arrive at the network topology:
	//     Alice -> Bob -> Carol -> Dave
	alice, bob := ht.Alice, ht.Bob
	carol := ht.NewNode("carol", nil)
	dave := ht.NewNode("dave", nil)

	// Connect nodes to ensure propagation of channels.
	ht.EnsureConnected(alice, bob)
	ht.EnsureConnected(bob, carol)
	ht.EnsureConnected(carol, dave)

	const chanAmt = btcutil.Amount(100000)

	// Open a channel with 100k satoshis between Alice and Bob with Alice
	// being the sole funder of the channel.
	chanPointAlice := ht.OpenChannel(
		alice, bob, lntest.OpenChannelParams{Amt: chanAmt},
	)
	defer ht.CloseChannel(alice, chanPointAlice)

	// We'll create Dave and establish a channel to Alice. Dave will be
	// running an older node that requires the legacy onion payload.
	ht.FundCoins(btcutil.SatoshiPerBitcoin, dave)
	chanPointBob := ht.OpenChannel(
		bob, carol, lntest.OpenChannelParams{Amt: chanAmt},
	)
	defer ht.CloseChannel(bob, chanPointBob)

	// Next, we'll create Carol and establish a channel to from her to Dave.
	ht.FundCoins(btcutil.SatoshiPerBitcoin, carol)
	chanPointCarol := ht.OpenChannel(
		carol, dave, lntest.OpenChannelParams{Amt: chanAmt},
	)
	defer ht.CloseChannel(carol, chanPointCarol)

	// Make sure Alice knows the channel between Bob and Carol.
	ht.AssertTopologyChannelOpen(alice, chanPointBob)
	ht.AssertTopologyChannelOpen(alice, chanPointCarol)

	const paymentAmt = 10000

	// Query for routes to pay from Alice to Dave.
	routesReq := &lnrpc.QueryRoutesRequest{
		PubKey: dave.PubKeyStr,
		Amt:    paymentAmt,
	}
	routes := alice.RPC.QueryRoutes(routesReq)
	route := routes.Routes[0]

	finalHop := route.Hops[len(route.Hops)-1]
	finalHop.MppRecord = &lnrpc.MPPRecord{
		PaymentAddr:  ht.Random32Bytes(),
		TotalAmtMsat: int64(lnwire.NewMSatFromSatoshis(paymentAmt)),
	}

	ht.Logf("Found route from Alice to Dave: %+v", route)

	// Build the onion to use for our payment.
	paymentHash := ht.Random32Bytes()
	onionReq := &routerrpc.BuildOnionRequest{
		Route:       route,
		PaymentHash: paymentHash,
	}
	onionResp := alice.RPC.BuildOnion(onionReq)
	ht.Logf("Constructed onion: %+v w/ key: %x", onionResp.OnionBlob,
		onionResp.SessionKey)

	// Dispatch a payment via SendOnion.
	firstHop := bob.PubKey
	sendReq := &routerrpc.SendOnionRequest{
		FirstHopPubkey: firstHop[:],
		Amount:         route.TotalAmtMsat,
		Timelock:       route.TotalTimeLock,
		PaymentHash:    paymentHash,
		OnionBlob:      onionResp.OnionBlob,
		AttemptId:      1,
	}
	ht.Logf("Sending onion w/ amt=%d (msat) to %x",
		sendReq.Amount, firstHop)

	resp := alice.RPC.SendOnion(sendReq)
	ht.Logf("SendOnion response: %+v", resp)

	serverErrorStr := ""
	clientErrorStr := ""

	// Track the payment providing all necessary information to delegate
	// error decryption to the server.
	//
	// NOTE(calvin): We expect this to fail as Dave is not expecting payment.
	ctxt, _ := context.WithTimeout(context.Background(), defaultTimeout)
	trackReq := &routerrpc.TrackOnionRequest{
		AttemptId:   1,
		PaymentHash: paymentHash,
		SessionKey:  onionResp.SessionKey,
		HopPubkeys:  onionResp.HopPubkeys,
	}
	trackResp, clearErr := alice.RPC.Router.TrackOnion(ctxt, trackReq)
	if clearErr != nil {
		ht.Logf("Encountered error while tracking onion: %v", clearErr)
	}
	ht.Logf("Tracked payment via onion: %+v", trackResp)
	serverErrorStr = clearErr.Error()

	// Now we'll track the same payment attempt, but we'll specify that
	// we want to handle the error decryption ourselves client side.
	trackReq = &routerrpc.TrackOnionRequest{
		AttemptId:   1,
		PaymentHash: paymentHash,
	}
	trackResp, err := alice.RPC.Router.TrackOnion(ctxt, trackReq)
	if err != nil {
		ht.Logf("Encountered error while tracking onion: %v", err)
	}
	ht.Logf("Tracked payment via onion: %+v", trackResp)

	// Decrypt and inspect the error from the TrackOnion RPC response.
	sessionKey, _ := btcec.PrivKeyFromBytes(onionResp.SessionKey)
	var pubKeys []*btcec.PublicKey
	for _, keyBytes := range onionResp.HopPubkeys {
		pubKey, err := btcec.ParsePubKey(keyBytes)
		if err != nil {
			ht.Fatalf("Failed to parse public key: %v", err)
		}
		pubKeys = append(pubKeys, pubKey)
	}

	// Construct the circuit to create the error decryptor
	circuit := reconstructCircuit(sessionKey, pubKeys)
	errorDecryptor := &htlcswitch.SphinxErrorDecrypter{
		OnionErrorDecrypter: sphinx.NewOnionErrorDecrypter(circuit),
	}

	// Simulate an RPC client decrypting the onion error.
	encryptedError := lnwire.OpaqueReason(trackResp.EncryptedError)
	forwardingError, err := errorDecryptor.DecryptError(encryptedError)
	require.Nil(ht, err, "unable to decrypt error")

	ht.Logf("Decrypted error: %+v", forwardingError)
	clientErrorStr = forwardingError.Error()

	ht.Logf("Server-side decrypted error: %s", serverErrorStr)
	ht.Logf("Client-side decrypted error: %s", clientErrorStr)
}

func reconstructCircuit(sessionKey *btcec.PrivateKey,
	pubKeys []*btcec.PublicKey) *sphinx.Circuit {

	return &sphinx.Circuit{
		SessionKey:  sessionKey,
		PaymentPath: pubKeys,
	}
}
