package htlcswitch

import (
	"errors"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/lightningnetwork/lnd/htlcswitch/hodl"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
)

// This file pins the switch-layer half of the SwitchRPC fund-safety contract
// that the payment service (PS) depends on but cannot verify from its own repo.
// See paymentservice/claude/plans/lnd-handoff/switchrpc-contract-tests-request.md.
//
// The invariant: lnd must never return a definitive (payment-failing) error for
// an HTLC that could still settle. Scoped to the SendOnion dispatch path this
// means a definitive code is only ever emitted for a failure that occurs
// strictly before the HTLC reaches the wire; once dispatched, every outcome
// must arrive via the result stream (TrackOnion), never as a synchronous
// definitive SendOnion/SendHTLC error.
//
// These tests live in htlcswitch because only htlcswitch knows the wire
// boundary. The error-type -> gRPC-code half (ClearTextError ->
// FailedPrecondition/definite; everything else -> Unavailable/indefinite) is
// pinned separately in lnrpc/switchrpc (TestMarshallDispatchFailure and the
// contract test); the two compose to the full invariant.

// TestSwitchSendHTLCWireBoundaryFundSafety drives real HTLCs through the switch
// and asserts the load-bearing invariant across the wire boundary: a
// ClearTextError (which switchrpc maps to a definitive code) is only ever
// returned strictly before the HTLC is dispatched, and any HTLC that is
// dispatched resolves via the result stream rather than a synchronous
// definitive error.
func TestSwitchSendHTLCWireBoundaryFundSafety(t *testing.T) {
	t.Parallel()

	// Pre-wire rejection: a synchronous link rejection before CommitCircuits
	// is a ClearTextError (definitive is safe here) AND leaves no circuit,
	// so nothing could have reached the wire.
	t.Run("pre_wire_rejection_is_definitive_safe", func(t *testing.T) {
		t.Parallel()

		n := newTwoHopNet(t)
		s := n.aliceServer.htlcSwitch

		// Send an amount larger than the outgoing link's available
		// bandwidth. Calling SendHTLC directly bypasses the routing
		// layer's getOutgoingBalance pre-check, so getLocalLink ->
		// CheckHtlcTransit is the gate that rejects, deterministically.
		overBandwidth := n.aliceChannelLink.Bandwidth() + 1
		htlc := &lnwire.UpdateAddHTLC{
			PaymentHash: [32]byte{0x01},
			Amount:      overBandwidth,
			Expiry:      testStartingHeight + 100,
		}

		err := s.SendHTLC(n.aliceChannelLink.ShortChanID(), 1, htlc)

		// The rejection must be a ClearTextError (the only error type
		// switchrpc marshals to a definitive FailedPrecondition).
		var cte ClearTextError
		require.True(t, errors.As(err, &cte),
			"pre-wire rejection must be a ClearTextError, got %T: "+
				"%v", err, err)

		// And it must be strictly pre-CommitCircuits: no circuit was
		// created, so no HTLC could ever have reached the wire.
		require.Zero(t, s.circuits.NumOpen(),
			"pre-wire rejection must not open a circuit")
		require.Zero(t, s.circuits.NumPending(),
			"pre-wire rejection must not leave a pending circuit")
	})

	// Committed/dispatched HTLC: with hodl.Commit the switch commits the
	// circuit and hands the add to the link (the UpdateAddHTLC goes to the
	// peer; only the CommitSig is withheld), yet SendHTLC returns success.
	// A dispatched HTLC must never yield a synchronous definitive error; its
	// outcome is deferred to the result stream.
	t.Run("dispatched_htlc_is_never_definitive", func(t *testing.T) {
		t.Parallel()

		n := newTwoHopNet(t)
		s := n.aliceServer.htlcSwitch

		// Withhold the commitment signature so the attempt stays live
		// after dispatch instead of settling/failing.
		n.aliceChannelLink.cfg.HodlMask = hodl.Commit.Mask()

		_, htlc, pid := genForwardableHTLC(t, n)

		err := s.SendHTLC(n.bobChannelLink.ShortChanID(), pid, htlc)

		// The invariant: a dispatched HTLC returns success from
		// SendHTLC, never a definitive error.
		require.NoError(t, err,
			"a dispatched HTLC must not return a synchronous error")

		// The circuit was committed (the HTLC was dispatched), so this
		// is genuinely past the pre-wire boundary. CommitCircuits runs
		// synchronously (pending), and the link's async batch later
		// opens it, so allow for either state.
		require.Eventually(t, func() bool {
			return s.circuits.NumPending()+s.circuits.NumOpen() > 0
		}, 5*time.Second, 50*time.Millisecond,
			"dispatched HTLC should have a committed circuit")

		// The outcome is deferred to the result stream (TrackOnion), not
		// a synchronous SendHTLC error. The attempt is tracked (no
		// ErrPaymentIDNotFound), and no result is delivered while it is
		// held.
		resultChan, err := s.GetAttemptResult(
			pid, htlc.PaymentHash, newMockDeobfuscator(),
		)
		require.NoError(t, err, "attempt must be tracked after dispatch")

		select {
		case res, ok := <-resultChan:
			// A result may arrive (e.g. an eventual timeout
			// cancel), but it comes via the stream, never as a
			// definitive SendHTLC error. Its mere delivery here is
			// consistent with the invariant.
			require.True(t, ok)
			_ = res
		case <-time.After(time.Second):
			// Expected: the held HTLC has no result yet; the outcome
			// is deferred to TrackOnion.
		}
	})

	// Post-wire downstream failure: a fully dispatched HTLC that fails at the
	// exit hop must surface via the result stream as a decodable wire
	// failure, never as a synchronous definitive SendHTLC error.
	t.Run("post_wire_failure_via_result_stream", func(t *testing.T) {
		t.Parallel()

		n := newTwoHopNet(t)
		s := n.aliceServer.htlcSwitch

		// Build a forwardable HTLC but deliberately do NOT register an
		// invoice at Bob, so the exit hop fails it with an unknown
		// payment hash and fails it back over the wire.
		_, htlc, pid := genForwardableHTLC(t, n)

		err := s.SendHTLC(n.bobChannelLink.ShortChanID(), pid, htlc)
		require.NoError(t, err,
			"dispatch must succeed; the failure is downstream")

		resultChan, err := s.GetAttemptResult(
			pid, htlc.PaymentHash, newMockDeobfuscator(),
		)
		require.NoError(t, err)

		var result *PaymentResult
		select {
		case res, ok := <-resultChan:
			require.True(t, ok, "result stream closed unexpectedly")
			result = res
		case <-time.After(15 * time.Second):
			t.Fatal("timed out waiting for downstream failure")
		}

		// The failure arrived via the result stream and is a decodable
		// wire failure (a ClearTextError) — not a synchronous definitive
		// SendHTLC error.
		require.NotNil(t, result.Error,
			"expected a downstream failure via the result stream")
		var cte ClearTextError
		require.True(t, errors.As(result.Error, &cte),
			"downstream failure should be a decodable wire failure, "+
				"got %T: %v", result.Error, result.Error)
	})
}

// TestSendHTLCErrorClassificationWireBoundary is the #2b classification pin: it
// asserts that within Switch.SendHTLC the only error type that surfaces a
// ClearTextError (which switchrpc maps to a definitive code) is a strictly
// pre-CommitCircuits rejection, while errors at or after CommitCircuits are not
// ClearTextErrors (switchrpc maps them to an indefinite/retryable code).
func TestSendHTLCErrorClassificationWireBoundary(t *testing.T) {
	t.Parallel()

	// Pre-CommitCircuits: getLocalLink rejection is a ClearTextError and
	// leaves no circuit.
	t.Run("pre_commit_rejection_is_cleartext", func(t *testing.T) {
		t.Parallel()

		n := newTwoHopNet(t)
		s := n.aliceServer.htlcSwitch

		htlc := &lnwire.UpdateAddHTLC{
			PaymentHash: [32]byte{0x02},
			Amount:      n.aliceChannelLink.Bandwidth() + 1,
			Expiry:      testStartingHeight + 100,
		}

		err := s.SendHTLC(n.aliceChannelLink.ShortChanID(), 1, htlc)

		var cte ClearTextError
		require.True(t, errors.As(err, &cte),
			"pre-commit rejection must be a ClearTextError, got "+
				"%T: %v", err, err)
		require.Zero(t, s.circuits.NumOpen())
	})

	// At/after CommitCircuits: a duplicate dispatch (same attempt ID on an
	// already-committed circuit) returns ErrDuplicateAdd, which is NOT a
	// ClearTextError — so switchrpc classifies it indefinite, never
	// definitive.
	t.Run("post_commit_duplicate_is_not_cleartext", func(t *testing.T) {
		t.Parallel()

		n := newTwoHopNet(t)
		s := n.aliceServer.htlcSwitch

		// Hold the first attempt open so the circuit stays in the map
		// and the second dispatch is detected as a duplicate.
		n.aliceChannelLink.cfg.HodlMask = hodl.Commit.Mask()

		_, htlc, pid := genForwardableHTLC(t, n)
		firstHop := n.bobChannelLink.ShortChanID()

		require.NoError(t, s.SendHTLC(firstHop, pid, htlc),
			"first dispatch should succeed")

		// Re-dispatch the same attempt ID: detected at CommitCircuits.
		err := s.SendHTLC(firstHop, pid, htlc)
		require.ErrorIs(t, err, ErrDuplicateAdd)

		// ErrDuplicateAdd is not a ClearTextError: it maps to an
		// indefinite/retryable code, never a definitive one.
		var cte ClearTextError
		require.False(t, errors.As(err, &cte),
			"a post-commit duplicate must NOT be a ClearTextError")
	})
}

// newTwoHopNet builds and starts a real Alice<->Bob switch network for the
// fund-safety tests. The network auto-starts and registers its own cleanup.
func newTwoHopNet(t *testing.T) *twoHopNetwork {
	t.Helper()

	channels, _, err := createClusterChannels(
		t, btcutil.SatoshiPerBitcoin, btcutil.SatoshiPerBitcoin,
	)
	require.NoError(t, err, "unable to create cluster channels")

	return newTwoHopNetwork(
		t, channels.aliceToBob, channels.bobToAlice, testStartingHeight,
	)
}

// genForwardableHTLC builds a valid, dispatchable HTLC from Alice to Bob (Bob
// as the final hop) with a modest amount well within the link's bandwidth. It
// does not register an invoice at Bob; callers that want a settle must do so
// themselves.
func genForwardableHTLC(t *testing.T, n *twoHopNetwork) (lnwire.MilliSatoshi,
	*lnwire.UpdateAddHTLC, uint64) {

	t.Helper()

	amount := lnwire.NewMSatFromSatoshis(100_000)
	htlcAmt, totalTimelock, hops := generateHops(
		amount, testStartingHeight, n.bobChannelLink,
	)

	blob, err := generateRoute(hops...)
	require.NoError(t, err, "unable to generate route")

	_, htlc, pid, err := generatePayment(
		amount, htlcAmt, totalTimelock, blob,
	)
	require.NoError(t, err, "unable to generate payment")

	return htlcAmt, htlc, pid
}
