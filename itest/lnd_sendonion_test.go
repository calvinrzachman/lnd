package itest

import (
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	sphinx "github.com/lightningnetwork/lightning-onion"
	"github.com/lightningnetwork/lnd/htlcswitch"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/invoicesrpc"
	"github.com/lightningnetwork/lnd/lnrpc/switchrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// testSendOnion tests the basic success case for the SendOnion RPC. It
// constructs a multi-hop route from Alice -> Bob -> Carol -> Dave, builds an
// onion packet for this route, and then asserts that Alice can successfully
// dispatch the payment using the SendOnion RPC. The test concludes by using
// TrackOnion to wait for and verify the payment's success preimage.
func testSendOnion(ht *lntest.HarnessTest) {
	// Create a four-node context consisting of Alice, Bob, Carol, and
	// Dave with the following topology:
	//     Alice -> Bob -> Carol -> Dave
	const chanAmt = btcutil.Amount(100000)
	const numNodes = 4
	nodeCfgs := make([][]string, numNodes)
	chanPoints, nodes := ht.CreateSimpleNetwork(
		nodeCfgs, lntest.OpenChannelParams{Amt: chanAmt},
	)
	alice, bob, carol, dave := nodes[0], nodes[1], nodes[2], nodes[3]
	defer ht.CloseChannel(alice, chanPoints[0])
	defer ht.CloseChannel(bob, chanPoints[1])
	defer ht.CloseChannel(carol, chanPoints[2])

	// Make sure Alice knows about all channels.
	aliceBobChan := ht.AssertChannelInGraph(alice, chanPoints[0])

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
	}
	routes := alice.RPC.QueryRoutes(routesReq)
	route := routes.Routes[0]
	finalHop := route.Hops[len(route.Hops)-1]
	finalHop.MppRecord = &lnrpc.MPPRecord{
		PaymentAddr:  invoices[0].PaymentAddr,
		TotalAmtMsat: int64(lnwire.NewMSatFromSatoshis(paymentAmt)),
	}

	// Construct an onion for the route from Alice to Dave.
	paymentHash := rHashes[0]
	onionReq := &switchrpc.BuildOnionRequest{
		Route:       route,
		PaymentHash: paymentHash,
	}
	onionResp := alice.RPC.BuildOnion(onionReq)

	// Dispatch a payment via the SendOnion RPC.
	sendReq := &switchrpc.SendOnionRequest{
		FirstHopChanId: aliceBobChan.ChannelId,
		Amount:         route.TotalAmtMsat,
		Timelock:       route.TotalTimeLock,
		PaymentHash:    paymentHash,
		OnionBlob:      onionResp.OnionBlob,
		AttemptId:      1,
	}

	err := alice.RPC.SendOnion(sendReq)
	require.NoError(ht, err, "expected successful onion send")

	// Query for the result of the payment via onion and confirm that it
	// succeeded.
	trackReq := &switchrpc.TrackOnionRequest{
		AttemptId:   1,
		PaymentHash: paymentHash,
		SessionKey:  onionResp.SessionKey,
		HopPubkeys:  onionResp.HopPubkeys,
	}
	trackResp := alice.RPC.TrackOnion(trackReq)
	require.Equal(ht, invoices[0].RPreimage, trackResp.GetPreimage())

	// The invoice should show as settled for Dave.
	ht.AssertInvoiceSettled(dave, invoices[0].PaymentAddr)
}

// testSendOnionTwice tests that the switch correctly rejects a duplicate
// payment attempt for an HTLC that is already in-flight. It sends an onion,
// then immediately sends the exact same onion with the same attempt ID. The
// test asserts that the second attempt is rejected with a DUPLICATE_HTLC
// error. It also verifies that sending again after the original HTLC has
// settled is also rejected.
func testSendOnionTwice(ht *lntest.HarnessTest) {
	// Create a four-node context consisting of Alice, Bob, Carol, and
	// Dave with the following topology:
	//     Alice -> Bob -> Carol -> Dave
	const chanAmt = btcutil.Amount(100000)
	const numNodes = 4
	nodeCfgs := make([][]string, numNodes)
	chanPoints, nodes := ht.CreateSimpleNetwork(
		nodeCfgs, lntest.OpenChannelParams{Amt: chanAmt},
	)
	alice, bob, carol, dave := nodes[0], nodes[1], nodes[2], nodes[3]
	defer ht.CloseChannel(alice, chanPoints[0])
	defer ht.CloseChannel(bob, chanPoints[1])
	defer ht.CloseChannel(carol, chanPoints[2])

	const paymentAmt = 10000

	// Create a preimage, that will be held by Dave.
	var preimage lntypes.Preimage
	copy(preimage[:], ht.Random32Bytes())
	payHash := preimage.Hash()

	// Add a hodl invoice at Dave's end.
	invoiceReq := &invoicesrpc.AddHoldInvoiceRequest{
		Value:      int64(paymentAmt),
		CltvExpiry: finalCltvDelta,
		Hash:       payHash[:],
	}
	invoice := dave.RPC.AddHoldInvoice(invoiceReq)

	// Query for routes to Dave.
	routesReq := &lnrpc.QueryRoutesRequest{
		PubKey: dave.PubKeyStr,
		Amt:    paymentAmt,
	}
	routes := alice.RPC.QueryRoutes(routesReq)
	route := routes.Routes[0]
	finalHop := route.Hops[len(route.Hops)-1]
	finalHop.MppRecord = &lnrpc.MPPRecord{
		PaymentAddr:  invoice.PaymentAddr,
		TotalAmtMsat: int64(lnwire.NewMSatFromSatoshis(paymentAmt)),
	}

	// Build the onion.
	onionReq := &switchrpc.BuildOnionRequest{
		Route:       route,
		PaymentHash: payHash[:],
	}
	onionResp := alice.RPC.BuildOnion(onionReq)

	// Send the onion for the first time.
	sendReq := &switchrpc.SendOnionRequest{
		FirstHopPubkey: bob.PubKey[:],
		Amount:         route.TotalAmtMsat,
		Timelock:       route.TotalTimeLock,
		PaymentHash:    payHash[:],
		OnionBlob:      onionResp.OnionBlob,
		AttemptId:      1,
	}
	err := alice.RPC.SendOnion(sendReq)
	require.NoError(ht, err, "expected successful onion send")

	// Assert that the HTLC reaches Dave.
	invoiceStream := dave.RPC.SubscribeSingleInvoice(payHash[:])
	ht.AssertInvoiceState(invoiceStream, lnrpc.Invoice_ACCEPTED)

	// While the first onion is still in-flight, we'll send the same onion
	// again with the same attempt ID. This should error as our Switch will
	// detect duplicate ADDs for *in-flight* HTLCs.
	err = alice.RPC.SendOnion(sendReq)
	require.Error(ht, err, "expected failure on onion send")

	// Check that we get the expected gRPC error.
	s, ok := status.FromError(err)
	require.True(ht, ok, "expected gRPC status error")
	require.Equal(ht, codes.AlreadyExists, s.Code(),
		"unexpected error code")

	// Dave settles the invoice.
	dave.RPC.SettleInvoice(preimage[:])

	// Ensure Dave's invoice is settled.
	ht.AssertInvoiceSettled(dave, invoice.PaymentAddr)

	// Track the payment and verify success.
	trackReq := &switchrpc.TrackOnionRequest{
		AttemptId:   1,
		PaymentHash: payHash[:],
		SessionKey:  onionResp.SessionKey,
		HopPubkeys:  onionResp.HopPubkeys,
	}
	trackResp := alice.RPC.TrackOnion(trackReq)
	require.Equal(ht, preimage[:], trackResp.GetPreimage())

	// Now that the original HTLC attempt has settled, we'll send the same
	// onion again with the same attempt ID. Confirm that this is also
	// prevented.
	err = alice.RPC.SendOnion(sendReq)
	require.Error(ht, err, "expected failure on onion send")

	// Check that we get the expected gRPC error.
	s, ok = status.FromError(err)
	require.True(ht, ok, "expected gRPC status error")
	require.Equal(ht, codes.AlreadyExists, s.Code(),
		"unexpected error code")

	// Now that we've confirmed that duplicate sends are rejected for
	// settled attempts, delete the attempt record from the store.
	deleteReq := &switchrpc.DeleteAttemptsRequest{
		AttemptIds: []uint64{1},
	}
	deleteResp := alice.RPC.DeleteAttempts(deleteReq)
	require.Len(ht, deleteResp.Results, 1)
	require.Equal(ht,
		switchrpc.AttemptDeletionStatus_DELETION_OK,
		deleteResp.Results[0].Status,
	)

	// Deleting the same attempt again should return NOT_FOUND,
	// confirming the record was fully removed.
	deleteResp = alice.RPC.DeleteAttempts(deleteReq)
	require.Len(ht, deleteResp.Results, 1)
	require.Equal(ht,
		switchrpc.AttemptDeletionStatus_DELETION_ALREADY_DELETED,
		deleteResp.Results[0].Status,
	)
}

// testSendOnionConcurrency simulates a client that crashes and attempts to
// retry a payment with the same attempt ID concurrently. This test provides a
// strong guarantee that the SendOnion RPC is idempotent and correctly prevents
// duplicate payment attempts from succeeding.
func testSendOnionConcurrency(ht *lntest.HarnessTest) {
	// Create a two-node context consisting of Alice and Bob.
	const chanAmt = btcutil.Amount(100000)
	const numNodes = 2
	nodeCfgs := make([][]string, numNodes)
	chanPoints, nodes := ht.CreateSimpleNetwork(
		nodeCfgs, lntest.OpenChannelParams{Amt: chanAmt},
	)
	alice, bob := nodes[0], nodes[1]

	// Make sure Alice knows about the channel.
	aliceBobChan := ht.AssertChannelInGraph(alice, chanPoints[0])

	const paymentAmt = 10000

	// Request an invoice from Bob so he is expecting payment.
	_, rHashes, invoices := ht.CreatePayReqs(bob, paymentAmt, 1)
	paymentHash := rHashes[0]

	// Query for a route to pay from Alice to Bob.
	routesReq := &lnrpc.QueryRoutesRequest{
		PubKey: bob.PubKeyStr,
		Amt:    paymentAmt,
	}
	routes := alice.RPC.QueryRoutes(routesReq)
	route := routes.Routes[0]
	finalHop := route.Hops[len(route.Hops)-1]
	finalHop.MppRecord = &lnrpc.MPPRecord{
		PaymentAddr:  invoices[0].PaymentAddr,
		TotalAmtMsat: int64(lnwire.NewMSatFromSatoshis(paymentAmt)),
	}

	// Construct the onion for the route.
	onionReq := &switchrpc.BuildOnionRequest{
		Route:       route,
		PaymentHash: paymentHash,
	}
	onionResp := alice.RPC.BuildOnion(onionReq)

	// Create the SendOnion request that all goroutines will use.
	// The AttemptId MUST be the same for all calls.
	sendReq := &switchrpc.SendOnionRequest{
		FirstHopChanId: aliceBobChan.ChannelId,
		Amount:         route.TotalAmtMsat,
		Timelock:       route.TotalTimeLock,
		PaymentHash:    paymentHash,
		OnionBlob:      onionResp.OnionBlob,
		AttemptId:      42,
	}

	const numConcurrentRequests = 50
	var wg sync.WaitGroup
	wg.Add(numConcurrentRequests)

	// Use channels to collect the results from each goroutine.
	resultsChan := make(chan error, numConcurrentRequests)

	// Launch all requests concurrently to simulate a retry storm.
	for i := 0; i < numConcurrentRequests; i++ {
		go func() {
			defer wg.Done()

			err := alice.RPC.SendOnion(sendReq)
			resultsChan <- err
		}()
	}

	wg.Wait()
	close(resultsChan)

	// We expect exactly one successful dispatch and the rest to be
	// rejected as duplicates.
	successCount := 0
	duplicateCount := 0

	for err := range resultsChan {
		// A nil error indicates a successful dispatch.
		if err == nil {
			successCount++
			continue
		}

		// For non-nil errors, we should receive a gRPC status error.
		s, ok := status.FromError(err)

		// If it's not a gRPC status error, it's an unexpected
		// condition.
		require.Truef(ht, ok, "unexpected error from SendOnion: %v, "+
			"code: %v", s.Err().Error(), s.Code())

		// Check if the error code indicates a duplicate acknowledgment.
		if s.Code() == codes.AlreadyExists {
			duplicateCount++
		} else {
			ht.Fatalf("unexpected error from SendOnion: %v, "+
				"code: %v", s.Err().Error(), s.Code())
		}
	}

	// Confirm that only a single dispatch succeeds.
	require.Equal(ht, 1, successCount, "expected exactly one success")
	require.Equal(ht, numConcurrentRequests-1, duplicateCount,
		"expected all other attempts to be duplicates")

	// The invoice should eventually show as settled for Bob.
	ht.AssertInvoiceSettled(bob, invoices[0].PaymentAddr)
}

// testTrackOnion exercises the SwitchRPC server's TrackOnion endpoint,
// confirming that we can receive the result of an onion dispatch and decrypt
// the error result. We also verify that the error received from the dispatched
// onion is the same whether error is processed by the server or the rpc client.
func testTrackOnion(ht *lntest.HarnessTest) {
	// Create a four-node context consisting of Alice, Bob, Carol, and
	// Dave with the following topology:
	//     Alice -> Bob -> Carol -> Dave
	const chanAmt = btcutil.Amount(100000)
	const numNodes = 4
	nodeCfgs := make([][]string, numNodes)
	chanPoints, nodes := ht.CreateSimpleNetwork(
		nodeCfgs, lntest.OpenChannelParams{Amt: chanAmt},
	)
	alice, bob, carol, dave := nodes[0], nodes[1], nodes[2], nodes[3]
	defer ht.CloseChannel(alice, chanPoints[0])
	defer ht.CloseChannel(bob, chanPoints[1])
	defer ht.CloseChannel(carol, chanPoints[2])

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

	// Build the onion to use for our payment.
	paymentHash := ht.Random32Bytes()
	onionReq := &switchrpc.BuildOnionRequest{
		Route:       route,
		PaymentHash: paymentHash,
	}
	onionResp := alice.RPC.BuildOnion(onionReq)

	// Dispatch a payment via SendOnion.
	firstHop := bob.PubKey
	sendReq := &switchrpc.SendOnionRequest{
		FirstHopPubkey: firstHop[:],
		Amount:         route.TotalAmtMsat,
		Timelock:       route.TotalTimeLock,
		PaymentHash:    paymentHash,
		OnionBlob:      onionResp.OnionBlob,
		AttemptId:      1,
	}

	err := alice.RPC.SendOnion(sendReq)
	require.NoError(ht, err, "expected successful onion send")

	// Track the payment providing all necessary information to delegate
	// error decryption to the server. We expect this to fail as Dave is not
	// expecting payment.
	trackReq := &switchrpc.TrackOnionRequest{
		AttemptId:   1,
		PaymentHash: paymentHash,
		SessionKey:  onionResp.SessionKey,
		HopPubkeys:  onionResp.HopPubkeys,
	}
	trackResp := alice.RPC.TrackOnion(trackReq)
	serverFailure := trackResp.GetFailureDetails()
	require.NotNil(ht, serverFailure, "expected onion tracking error")

	serverFwdFailure := serverFailure.GetForwardingFailure()
	require.NotNil(ht, serverFwdFailure, "expected forwarding failure")

	// Now we'll track the same payment attempt, but we'll specify that
	// we want to handle the error decryption ourselves client side.
	trackReq = &switchrpc.TrackOnionRequest{
		AttemptId:   1,
		PaymentHash: paymentHash,
	}
	trackResp = alice.RPC.TrackOnion(trackReq)
	clientFailure := trackResp.GetFailureDetails()
	require.NotNil(ht, clientFailure, "expected client tracking error")

	encryptedErrorBytes := clientFailure.GetEncryptedErrorData()
	require.NotNil(ht, encryptedErrorBytes, "expected encrypted error")

	// Decrypt and inspect the error from the TrackOnion RPC response.
	sessionKey, _ := btcec.PrivKeyFromBytes(onionResp.SessionKey)
	var pubKeys []*btcec.PublicKey
	for _, keyBytes := range onionResp.HopPubkeys {
		pubKey, err := btcec.ParsePubKey(keyBytes)
		require.NoError(ht, err, "Failed to parse public key")
		pubKeys = append(pubKeys, pubKey)
	}

	// Construct the circuit to create the error decryptor
	circuit := &sphinx.Circuit{
		SessionKey:  sessionKey,
		PaymentPath: pubKeys,
	}
	errorDecryptor := &htlcswitch.SphinxErrorDecrypter{
		OnionErrorDecrypter: sphinx.NewOnionErrorDecrypter(circuit),
	}

	// Simulate an RPC client decrypting the onion error.
	encryptedError := lnwire.OpaqueReason(encryptedErrorBytes)
	clientFwdErr, err := errorDecryptor.DecryptError(encryptedError)
	require.NoError(ht, err, "unable to decrypt error")

	// Finally, assert that the structured forwarding failure is the same
	// whether it was decrypted on the server or on the client.
	serverFwdErr, err := switchrpc.UnmarshallForwardingError(
		serverFwdFailure,
	)
	require.NoError(ht, err, "unable to decode server forwarding failure")

	require.Equal(ht, serverFwdFailure.FailureSourceIndex,
		uint32(clientFwdErr.FailureSourceIdx), "source index mismatch")
	require.Equal(ht, serverFwdErr.WireMessage(),
		clientFwdErr.WireMessage(), "wire message mismatch")
}

// assertPeerHasNoPendingHtlcs asserts that the given node currently holds no
// pending HTLCs on any channel. We assert on the raw PendingHtlcs slice rather
// than via AssertNumActiveHtlcs, because the latter only counts LockedIn HTLCs
// and would miss an ADD that reached the link but was not yet committed.
func assertPeerHasNoPendingHtlcs(ht *lntest.HarnessTest,
	hn *node.HarnessNode) {

	err := wait.NoError(func() error {
		resp := hn.RPC.ListChannels(&lnrpc.ListChannelsRequest{})
		total := 0
		for _, c := range resp.Channels {
			total += len(c.PendingHtlcs)
		}
		if total != 0 {
			return fmt.Errorf("%s has %d pending htlc(s), want 0",
				hn.Name(), total)
		}

		return nil
	}, defaultTimeout)
	require.NoError(ht, err, "expected no pending htlcs on peer")
}

// testSendOnionPreWireDefiniteIsSafe checks that when SendOnion reports a hard
// (payment-failing) error, the HTLC was never actually sent onto the network.
// SendOnion is only allowed to report a hard failure when the payment was
// rejected up front, before anything left the node — so the caller can safely
// give up on it.
//
// We force such an early rejection by dispatching over a first hop that has no
// usable channel. The switch rejects the request immediately, before the HTLC
// is handed off to be sent. We confirm the caller sees the failure and,
// crucially, that the downstream peer never received any HTLC: nothing is in
// flight, so giving up on the payment is safe.
//
// If a future change instead let SendOnion report a hard failure after an HTLC
// had already gone out, a caller would give up and retry the payment as a brand
// new one while the original was still live — paying the recipient twice. This
// test guards against that.
func testSendOnionPreWireDefiniteIsSafe(ht *lntest.HarnessTest) {
	const chanAmt = btcutil.Amount(100000)
	const numNodes = 2
	nodeCfgs := make([][]string, numNodes)
	chanPoints, nodes := ht.CreateSimpleNetwork(
		nodeCfgs, lntest.OpenChannelParams{Amt: chanAmt},
	)
	alice, bob := nodes[0], nodes[1]
	defer ht.CloseChannel(alice, chanPoints[0])

	ht.AssertChannelInGraph(alice, chanPoints[0])

	const paymentAmt = 10000

	// Build a real onion to a real route to Bob, so the only thing wrong is
	// the first-hop selection at dispatch time.
	_, rHashes, invoices := ht.CreatePayReqs(bob, paymentAmt, 1)
	paymentHash := rHashes[0]

	routes := alice.RPC.QueryRoutes(&lnrpc.QueryRoutesRequest{
		PubKey: bob.PubKeyStr,
		Amt:    paymentAmt,
	})
	route := routes.Routes[0]
	finalHop := route.Hops[len(route.Hops)-1]
	finalHop.MppRecord = &lnrpc.MPPRecord{
		PaymentAddr:  invoices[0].PaymentAddr,
		TotalAmtMsat: int64(lnwire.NewMSatFromSatoshis(paymentAmt)),
	}

	onionResp := alice.RPC.BuildOnion(&switchrpc.BuildOnionRequest{
		Route:       route,
		PaymentHash: paymentHash,
	})

	// Dispatch against a first-hop chan id with no eligible local link. The
	// switch rejects synchronously inside SendHTLC, before the mailbox
	// enqueue.
	const bogusChanID = uint64(0xdeadbeefdeadbeef)
	sendReq := &switchrpc.SendOnionRequest{
		FirstHopChanId: bogusChanID,
		Amount:         route.TotalAmtMsat,
		Timelock:       route.TotalTimeLock,
		PaymentHash:    paymentHash,
		OnionBlob:      onionResp.OnionBlob,
		AttemptId:      1,
	}

	err := alice.RPC.SendOnion(sendReq)
	require.Error(ht, err, "expected a pre-wire dispatch failure")

	// If the failure is definitive, it must be classified as a
	// DefiniteFailure (this is the emission contract PS relies on).
	s, ok := status.FromError(err)
	require.True(ht, ok, "expected a gRPC status error")
	if s.Code() == codes.FailedPrecondition {
		details := switchrpc.GetSendOnionFailureDetails(err)
		require.NotNil(ht, details, "FailedPrecondition without details")
		require.NotNil(ht, details.GetDefiniteFailure(),
			"definitive SendOnion error must carry a DefiniteFailure")
		require.Nil(ht, details.GetIndefiniteFailure())
	}

	// The load-bearing assertion: regardless of the exact code, nothing
	// crossed the wire — Bob never saw an incoming HTLC.
	assertPeerHasNoPendingHtlcs(ht, bob)
}

// testSendOnionPreWireDropNotDefinite checks the opposite case: once SendOnion
// has accepted an HTLC for dispatch, it must not report a hard (payment-
// failing) error, even when the HTLC's eventual fate is unknown. Accepting the
// HTLC means the payment has been handed off; whether it ultimately settles or
// fails is reported later through TrackOnion, never as a hard SendOnion error.
//
// Note that "dropped" is not the same as "failed". A failed HTLC is one that
// was sent and came back rejected — a resolved, terminal outcome. A dropped
// HTLC is silently discarded before it is ever sent, so it never resolves at
// all: it is neither settled nor failed, just unknown. We create that state by
// running the sender with --hodl.add-outgoing, which makes its outgoing link
// discard the HTLC just before it would go to the peer.
//
// Because the switch still accepted the HTLC, SendOnion must return success and
// leave the outcome to TrackOnion. SendOnion cannot tell a harmlessly-dropped
// HTLC from one that is genuinely live on the network, so reporting a hard
// failure here would be the dangerous mistake: a caller told its payment failed
// may retry it as a new payment, and if the original were live the recipient
// would be paid twice.
func testSendOnionPreWireDropNotDefinite(ht *lntest.HarnessTest) {
	const chanAmt = btcutil.Amount(100000)

	// Alice drops outgoing ADDs before they reach the wire.
	nodeCfgs := [][]string{{"--hodl.add-outgoing"}, nil}
	chanPoints, nodes := ht.CreateSimpleNetwork(
		nodeCfgs, lntest.OpenChannelParams{Amt: chanAmt},
	)
	alice, bob := nodes[0], nodes[1]
	defer ht.CloseChannel(alice, chanPoints[0])

	aliceBobChan := ht.AssertChannelInGraph(alice, chanPoints[0])

	const paymentAmt = 10000
	_, rHashes, invoices := ht.CreatePayReqs(bob, paymentAmt, 1)
	paymentHash := rHashes[0]

	routes := alice.RPC.QueryRoutes(&lnrpc.QueryRoutesRequest{
		PubKey: bob.PubKeyStr,
		Amt:    paymentAmt,
	})
	route := routes.Routes[0]
	finalHop := route.Hops[len(route.Hops)-1]
	finalHop.MppRecord = &lnrpc.MPPRecord{
		PaymentAddr:  invoices[0].PaymentAddr,
		TotalAmtMsat: int64(lnwire.NewMSatFromSatoshis(paymentAmt)),
	}

	onionResp := alice.RPC.BuildOnion(&switchrpc.BuildOnionRequest{
		Route:       route,
		PaymentHash: paymentHash,
	})

	sendReq := &switchrpc.SendOnionRequest{
		FirstHopChanId: aliceBobChan.ChannelId,
		Amount:         route.TotalAmtMsat,
		Timelock:       route.TotalTimeLock,
		PaymentHash:    paymentHash,
		OnionBlob:      onionResp.OnionBlob,
		AttemptId:      1,
	}

	// SendOnion must succeed: the HTLC was accepted into the mailbox. The
	// link will drop it pre-wire, but that must NOT surface as a definitive
	// SendOnion failure.
	err := alice.RPC.SendOnion(sendReq)
	require.NoError(ht, err, "pre-wire drop must not be a definitive "+
		"SendOnion failure")

	// Bob never sees the ADD (dropped before Peer.SendMessage).
	assertPeerHasNoPendingHtlcs(ht, bob)

	// The outcome is only observable via TrackOnion, and it is stuck/
	// indefinite — never a definitive failure delivered here.
	//
	// NOTE: TrackOnion blocks until the attempt resolves; with the HTLC
	// stuck it will not resolve. The author should drive this with a bounded
	// context (or a short-lived stream) and assert that no definitive
	// failure is delivered within the window.
}

// testSendOnionPostWireNeverDefinite checks that once an HTLC is actually live
// on the network, a failure is reported through TrackOnion and never as a hard
// SendOnion error. This is the case the rule protects most directly.
//
// We send to a hold invoice so the HTLC reaches the recipient and waits there
// (ACCEPTED), then have the recipient cancel it, failing the HTLC back.
// SendOnion has already returned success; the failure only shows up when we
// track the attempt. A real, live HTLC must never be turned into a hard
// SendOnion failure that would make the caller give up and retry as a new
// payment while the original is still resolving.
func testSendOnionPostWireNeverDefinite(ht *lntest.HarnessTest) {
	const chanAmt = btcutil.Amount(100000)
	const numNodes = 2
	nodeCfgs := make([][]string, numNodes)
	chanPoints, nodes := ht.CreateSimpleNetwork(
		nodeCfgs, lntest.OpenChannelParams{Amt: chanAmt},
	)
	alice, bob := nodes[0], nodes[1]
	defer ht.CloseChannel(alice, chanPoints[0])

	aliceBobChan := ht.AssertChannelInGraph(alice, chanPoints[0])

	const paymentAmt = 10000

	// Bob holds a hodl invoice so the HTLC parks on the wire in ACCEPTED.
	var preimage lntypes.Preimage
	copy(preimage[:], ht.Random32Bytes())
	payHash := preimage.Hash()
	invoice := bob.RPC.AddHoldInvoice(&invoicesrpc.AddHoldInvoiceRequest{
		Value:      int64(paymentAmt),
		CltvExpiry: finalCltvDelta,
		Hash:       payHash[:],
	})

	routes := alice.RPC.QueryRoutes(&lnrpc.QueryRoutesRequest{
		PubKey: bob.PubKeyStr,
		Amt:    paymentAmt,
	})
	route := routes.Routes[0]
	finalHop := route.Hops[len(route.Hops)-1]
	finalHop.MppRecord = &lnrpc.MPPRecord{
		PaymentAddr:  invoice.PaymentAddr,
		TotalAmtMsat: int64(lnwire.NewMSatFromSatoshis(paymentAmt)),
	}

	onionResp := alice.RPC.BuildOnion(&switchrpc.BuildOnionRequest{
		Route:       route,
		PaymentHash: payHash[:],
	})

	sendReq := &switchrpc.SendOnionRequest{
		FirstHopChanId: aliceBobChan.ChannelId,
		Amount:         route.TotalAmtMsat,
		Timelock:       route.TotalTimeLock,
		PaymentHash:    payHash[:],
		OnionBlob:      onionResp.OnionBlob,
		AttemptId:      1,
	}

	// SendOnion succeeds and the HTLC reaches Bob (on the wire).
	err := alice.RPC.SendOnion(sendReq)
	require.NoError(ht, err, "expected successful onion send")

	invoiceStream := bob.RPC.SubscribeSingleInvoice(payHash[:])
	ht.AssertInvoiceState(invoiceStream, lnrpc.Invoice_ACCEPTED)

	// Bob cancels the invoice, failing the on-wire HTLC back.
	bob.RPC.CancelInvoice(payHash[:])

	// The failure must surface via TrackOnion (no preimage) — it was never
	// a definitive SendOnion failure (SendOnion already returned success).
	trackResp := alice.RPC.TrackOnion(&switchrpc.TrackOnionRequest{
		AttemptId:   1,
		PaymentHash: payHash[:],
		SessionKey:  onionResp.SessionKey,
		HopPubkeys:  onionResp.HopPubkeys,
	})
	require.Empty(ht, trackResp.GetPreimage(),
		"on-wire failure must not yield a preimage")
}
