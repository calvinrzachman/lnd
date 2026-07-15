package htlcswitch

import (
	"errors"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/lightningnetwork/lnd/htlcswitch/hodl"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
)

// These tests pin the wire boundary of Switch.SendHTLC that its callers rely on
// to decide whether an attempt may be retried elsewhere. A ClearTextError is
// only returned before the switch commits a circuit, so no HTLC can exist for
// the attempt. A dispatched HTLC never returns a synchronous error; its outcome
// arrives through the attempt result instead.

// TestSwitchSendHTLCWireBoundaryFundSafety drives real HTLCs through the switch
// on both sides of the wire boundary.
func TestSwitchSendHTLCWireBoundaryFundSafety(t *testing.T) {
	t.Parallel()

	// A link rejection before CommitCircuits is a ClearTextError and leaves
	// no circuit, so nothing could have reached the wire.
	t.Run("pre_wire_rejection_is_cleartext", func(t *testing.T) {
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

		var cte ClearTextError
		require.True(t, errors.As(err, &cte),
			"pre-wire rejection must be a ClearTextError, got %T: "+
				"%v", err, err)

		require.Zero(t, s.circuits.NumOpen(),
			"pre-wire rejection must not open a circuit")
		require.Zero(t, s.circuits.NumPending(),
			"pre-wire rejection must not leave a pending circuit")
	})

	// With hodl.Commit the switch commits the circuit and hands the add to
	// the link, withholding only the CommitSig. SendHTLC must return
	// success, leaving the outcome to the attempt result.
	t.Run("dispatched_htlc_returns_no_error", func(t *testing.T) {
		t.Parallel()

		n := newTwoHopNet(t)
		s := n.aliceServer.htlcSwitch

		// Withhold the commitment signature so the attempt stays live
		// after dispatch instead of settling/failing.
		n.aliceChannelLink.cfg.HodlMask = hodl.Commit.Mask()

		_, htlc, pid := genForwardableHTLC(t, n)

		err := s.SendHTLC(n.bobChannelLink.ShortChanID(), pid, htlc)

		require.NoError(t, err,
			"a dispatched HTLC must not return a synchronous error")

		// CommitCircuits leaves the circuit pending and the link opens
		// it asynchronously, so accept either state.
		require.Eventually(t, func() bool {
			return s.circuits.NumPending()+s.circuits.NumOpen() > 0
		}, 5*time.Second, 50*time.Millisecond,
			"dispatched HTLC should have a committed circuit")

		// The attempt is tracked, and its outcome comes through the
		// result channel.
		resultChan, err := s.GetAttemptResult(
			pid, htlc.PaymentHash, newMockDeobfuscator(),
		)
		require.NoError(t, err,
			"attempt must be tracked after dispatch")

		select {
		case res, ok := <-resultChan:
			// A result may arrive, for example a timeout, and it
			// still comes through the result channel.
			require.True(t, ok)
			_ = res
		case <-time.After(time.Second):
			// Expected: the held HTLC has no result yet.
		}
	})

	// A dispatched HTLC that fails at the exit hop surfaces through the
	// attempt result as a decodable wire failure.
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

		require.NotNil(t, result.Error,
			"expected a downstream failure via the result stream")
		var cte ClearTextError
		require.True(t, errors.As(result.Error, &cte),
			"downstream failure should be a decodable wire "+
				"failure, got %T: %v", result.Error,
			result.Error)
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
