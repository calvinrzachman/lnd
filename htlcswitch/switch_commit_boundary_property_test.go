package htlcswitch

import (
	"errors"
	"testing"

	"github.com/lightningnetwork/lnd/htlcswitch/hodl"
	"github.com/lightningnetwork/lnd/htlcswitch/hop"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// TestSendHTLCCommitBoundaryProperty asserts, over generated HTLCs, that
// SendHTLC returns a ClearTextError if and only if the switch did not commit a
// circuit for the attempt.
//
// Callers rely on this to decide whether an attempt can be safely failed and
// rerouted. Reporting a ClearTextError for an attempt the switch has committed
// invites a duplicate payment; returning an opaque error for one it never
// committed makes callers treat a routine rejection as terminal.
//
// This suits a property test because the oracle is observable: the circuit map
// says whether ownership was taken, so each generated case supplies its own
// expected result.
//
// Two limits worth knowing. The fee exposure rejection is not exercised, since
// dust is measured against a commitment that a held link never advances. And
// errors that need a failing database or a restart are out of reach of input
// generation, so they are covered by unit tests instead.
func TestSendHTLCCommitBoundaryProperty(t *testing.T) {
	t.Parallel()

	// Built once and reused: the property must hold whatever state the
	// switch has accumulated, so letting cases share a link is a feature.
	n := newTwoHopNet(t)
	s := n.aliceServer.htlcSwitch

	// Hold the outgoing link so dispatched HTLCs stay in flight rather than
	// settling and freeing their circuits mid-run.
	n.aliceChannelLink.cfg.HodlMask = hodl.Commit.Mask()

	// Generated HTLCs reuse a real onion. The switch does not inspect it
	// here, but a dispatch that succeeds reaches the receiving link, which
	// will try to decode it.
	_, template, _ := genForwardableHTLC(t, n)

	aliceSCID := n.aliceChannelLink.ShortChanID()
	bobSCID := n.bobChannelLink.ShortChanID()

	// bogusSCID resolves to no link at all, which exercises the
	// unknown_next_peer rejection.
	bogusSCID := lnwire.NewShortChanIDFromInt(0xdeadbeef)

	// attemptID hands out a fresh id per case. Reuse is exercised
	// explicitly below rather than by collision.
	var attemptID uint64

	rapid.Check(t, func(rt *rapid.T) {
		scid := rapid.SampledFrom([]lnwire.ShortChannelID{
			aliceSCID, bobSCID, bogusSCID,
		}).Draw(rt, "first_hop")

		// Span zero, dust, ordinary, and beyond-capacity amounts.
		amount := lnwire.MilliSatoshi(rapid.Uint64Range(
			0, uint64(n.aliceChannelLink.Bandwidth())*2,
		).Draw(rt, "amount_msat"))

		// Span expired, current, and far-future timelocks.
		expiry := uint32(rapid.IntRange(
			testStartingHeight-10, testStartingHeight+1000,
		).Draw(rt, "expiry"))

		var payHash [32]byte
		copy(payHash[:], rapid.SliceOfN(
			rapid.Byte(), 32, 32,
		).Draw(rt, "payment_hash"))

		// Fresh ids only. Callers are responsible for not reusing one
		// while its HTLC is live, so a reused id is out of scope here.
		attemptID++
		id := attemptID

		htlc := &lnwire.UpdateAddHTLC{
			PaymentHash: payHash,
			Amount:      amount,
			Expiry:      expiry,
			OnionBlob:   template.OnionBlob,
		}

		// Look up the circuit rather than counting open ones: NumOpen
		// tracks keystoned circuits, so a committed but not yet
		// keystoned attempt would wrongly read as absent.
		inKey := CircuitKey{ChanID: hop.Source, HtlcID: id}

		err := s.SendHTLC(scid, id, htlc)

		tookOwnership := s.circuits.LookupCircuit(inKey) != nil

		var cte ClearTextError
		saysNotDispatched := errors.As(err, &cte)

		if saysNotDispatched == tookOwnership {
			rt.Fatalf("boundary violated: scid=%v amount=%v "+
				"expiry=%v id=%v err=%T(%v) -- the switch %s "+
				"the attempt but %s a local rejection",
				scid, amount, expiry, id, err, err,
				ownershipDesc(tookOwnership),
				reportDesc(saysNotDispatched))
		}

		// A rejection the caller cannot act on is not a rejection it
		// can use: the router needs a wire failure to penalise with,
		// and one that arrives empty kills the payment instead of the
		// attempt.
		if saysNotDispatched && cte.WireMessage() == nil {
			rt.Fatalf("rejection for id=%v carried no wire "+
				"failure: err=%T(%v)", id, err, err)
		}
	})
}

// ownershipDesc renders the oracle's answer for a failure message.
func ownershipDesc(tookOwnership bool) string {
	if tookOwnership {
		return "TOOK OWNERSHIP of"
	}

	return "did NOT take ownership of"
}

// reportDesc renders what the switch reported, for a failure message.
func reportDesc(saysNotDispatched bool) string {
	if saysNotDispatched {
		return "reported"
	}

	return "did not report"
}

// TestSendHTLCDuplicateAddIsNotALocalRejection asserts that a duplicate add is
// not reported as a ClearTextError.
//
// ErrDuplicateAdd means the switch may already hold an HTLC for the attempt.
// Reporting it as a local rejection would tell the caller nothing was
// dispatched, and acting on that could put a second HTLC on the wire.
func TestSendHTLCDuplicateAddIsNotALocalRejection(t *testing.T) {
	t.Parallel()

	n := newTwoHopNet(t)
	s := n.aliceServer.htlcSwitch
	n.aliceChannelLink.cfg.HodlMask = hodl.Commit.Mask()

	_, htlc, pid := genForwardableHTLC(t, n)
	firstHop := n.bobChannelLink.ShortChanID()

	require.NoError(t, s.SendHTLC(firstHop, pid, htlc))

	inKey := CircuitKey{ChanID: hop.Source, HtlcID: pid}
	require.NotNil(t, s.circuits.LookupCircuit(inKey),
		"the first dispatch should have committed a circuit")

	err := s.SendHTLC(firstHop, pid, htlc)
	require.ErrorIs(t, err, ErrDuplicateAdd)

	var cte ClearTextError
	require.False(t, errors.As(err, &cte),
		"a duplicate add must not be reported as a local rejection: "+
			"an HTLC for this attempt may already be in flight")
}
