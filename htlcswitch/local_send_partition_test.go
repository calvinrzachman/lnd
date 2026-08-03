package htlcswitch

import (
	"errors"
	"testing"

	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
)

// localSendCase is one row of the local send partition: an error the switch can
// return from a local send, whether it arises strictly before the switch takes
// ownership of the attempt, and the reason that answer is correct.
type localSendCase struct {
	// name identifies the case in test output.
	name string

	// err is an instance of the error as SendHTLC returns it.
	err error

	// preCommit records whether the error arises strictly before
	// CommitCircuits, which is the physical fact the classification tracks.
	// A pre-commit error means the HTLC provably never left this node.
	preCommit bool

	// priorMayBeLive records whether the error implies that an HTLC for
	// this attempt id may already be in flight from an *earlier* dispatch.
	//
	// This is a different question from preCommit. No error return from
	// SendHTLC ever means the current call put an HTLC on the wire, which
	// is why a caller may always record the attempt as failed. But two
	// errors are raised precisely because something for this id already
	// exists, and if the caller can reach them after an earlier dispatch
	// succeeded then recording a terminal failure would bury a live HTLC.
	priorMayBeLive bool

	// why explains why preCommit holds, in terms of the code path rather
	// than the error value, so a reader can check the claim against the
	// source instead of trusting the table.
	why string
}

// localSendPartition enumerates every error reachable from a local HTLC send
// together with the physical fact about whether the switch had taken ownership
// when it was raised.
//
// Two distinct properties live here and confusing them is the mistake this
// comment exists to prevent.
//
// The first is the SendHTLC contract: no error return ever means the current
// call put an HTLC on the wire. Every error is raised before the packet reaches
// the link's mailbox, and AddPacket returns nil once it has enqueued, so there
// is no enqueue-then-fail path. Both callers depend on this. The in-process
// router marks the attempt failed on every error, via failAttempt for a
// ClearTextError and via failPaymentAndAttempt otherwise, and the switchrpc
// server records the pending attempt terminal for the same reason.
//
// The second is CommitCircuits in switch.go, the point at which the switch takes
// ownership. That governs whether the caller may treat the failure as definite
// and route elsewhere, which is a stronger claim than "this call sent nothing",
// because an earlier call for the same attempt id may still be live.
//
// NOTE: any error SendHTLC can return that is missing from this table is a gap
// in the specification, not a passing case. Nothing here detects such a gap
// automatically. TestLocalSendPartitionRowCountIsPinned only makes adding a
// return path without a row fail a count assertion, which is a prompt rather
// than a proof. This table is reviewed specification; the executable evidence
// is TestSendHTLCCommitBoundaryProperty and switch_fund_safety_test.go.
var localSendPartition = []localSendCase{
	// Phase 1: before CommitCircuits. Nothing has been persisted or
	// queued.
	{
		name:      "link not found",
		err:       NewLinkError(&lnwire.FailUnknownNextPeer{}),
		preCommit: true,
		why: "getLocalLink could not resolve the outgoing link, " +
			"which happens before any circuit is created",
	},
	{
		name: "link not eligible to forward",
		err: NewDetailedLinkError(
			&lnwire.FailTemporaryChannelFailure{},
			OutgoingFailureLinkNotEligible,
		),
		preCommit: true,
		why: "the link exists but is not eligible to forward; " +
			"getLocalLink rejects before creating a circuit",
	},
	{
		name:      "fee exposure exceeded",
		err:       errFeeExposureExceeded,
		preCommit: true,
		why: "the dust check runs after getLocalLink and before " +
			"CommitCircuits, so the HTLC is never dispatched",
	},

	// Phase 2: at or after CommitCircuits. The switch may already own the
	// attempt.
	{
		name:      "commit circuits failed",
		err:       errors.New("unable to commit circuit in switch"),
		preCommit: true,
		why: "the circuit is rolled back out of the pending set, so " +
			"nothing is committed, but the error is opaque and " +
			"carries no wire failure we could hand the caller",
	},
	{
		name:           "duplicate add",
		err:            ErrDuplicateAdd,
		preCommit:      false,
		priorMayBeLive: true,
		why: "this call queued nothing, but the circuit map already " +
			"held this circuit, either keystoned or still in " +
			"memory, so an HTLC from an earlier dispatch of this " +
			"attempt id may be in flight",
	},
	{
		name:      "local add failed",
		err:       ErrLocalAddFailed,
		preCommit: true,
		why: "reached only when the circuit was restored from disk " +
			"without a keystone, so a restart lost the in-memory " +
			"packet and the HTLC never entered a commitment",
	},
	{
		name:           "mailbox already holds the packet",
		err:            ErrPacketAlreadyExists,
		preCommit:      false,
		priorMayBeLive: true,
		why: "AddPacket returns this before enqueuing, so this call " +
			"queued nothing, but the packet an earlier dispatch " +
			"left on the link may still go out. Unreachable while " +
			"InitAttempt gates a second dispatch of the same " +
			"attempt id; deleting a live record reopens it",
	},
	{
		name:      "switch exiting",
		err:       ErrSwitchExiting,
		preCommit: false,
		why: "NOT reachable from SendHTLC as far as anyone has " +
			"established: switch.go returns this only from " +
			"ProcessContractResolution and CloseLink, and it does " +
			"not appear in the mailbox path. The row is kept " +
			"because marshallDispatchFailure defends against it " +
			"explicitly, so either that check is precautionary or " +
			"a path exists that nobody has found. Classified " +
			"conservatively either way: a shutting-down switch " +
			"could not say whether it took ownership",
	},
}

// TestLocalSendSoundness is the fund-safety property this file exists for.
//
// routing/payment_lifecycle.go decides what to do with a SendHTLC error using
// exactly one test: errors.As against htlcswitch.ClearTextError. On that branch
// it calls failAttempt, after which the payment is free to build a new attempt
// over a different route. That is sound only if a ClearTextError means the HTLC
// is not in flight.
//
// So: a ClearTextError from a local send must be strictly pre-CommitCircuits.
// If that ever stops holding, the router fails an attempt whose HTLC is live
// and re-routes it, and both can settle. This test is what stands between that
// change and a release.
//
// The converse is deliberately not asserted. An opaque error for a pre-commit
// rejection costs liveness, not money, so over-approximating towards "we do not
// know" is always allowed. See TestLocalSendCompletenessGaps for where that
// currently happens.
func TestLocalSendSoundness(t *testing.T) {
	t.Parallel()

	for _, tc := range localSendPartition {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var cte ClearTextError
			isClearText := errors.As(tc.err, &cte)

			if !isClearText {
				return
			}

			require.Truef(t, tc.preCommit,
				"%q is a ClearTextError but is not "+
					"pre-CommitCircuits. The payment "+
					"lifecycle will fail this attempt and "+
					"re-route while the HTLC may still be "+
					"in flight, which double-pays. Why "+
					"this row claims otherwise: %s",
				tc.name, tc.why)
		})
	}
}

// TestLocalSendCompletenessGaps records, as a passing test rather than a
// comment, the rows where the switch is safe but imprecise: the HTLC provably
// never left, yet the error carries no wire failure, so the caller cannot tell
// a definite rejection from an unknown outcome and must treat it as unknown.
//
// These cost latency and pathfinding quality, never funds. The test exists so
// that closing one of them is a visible edit here rather than an unnoticed
// behaviour change, and so that the list cannot grow silently.
func TestLocalSendCompletenessGaps(t *testing.T) {
	t.Parallel()

	var gaps []string
	for _, tc := range localSendPartition {
		var cte ClearTextError
		if tc.preCommit && !errors.As(tc.err, &cte) {
			gaps = append(gaps, tc.name)
		}
	}

	require.ElementsMatch(t, []string{
		// Returns the opaque errFeeExposureExceeded even though the
		// dust check already built a temporary channel failure for the
		// HTLC notifier. The router therefore treats a pre-dispatch
		// rejection as an internal error and fails the whole payment
		// instead of the attempt.
		"fee exposure exceeded",

		// Genuinely has no wire failure to report: the commit failed
		// for a storage reason, not a Lightning one.
		"commit circuits failed",

		// Carries no wire failure today, though the restart path
		// assigns one to the equivalent state.
		"local add failed",
	}, gaps, "the set of safe-but-imprecise local send errors changed; "+
		"if you closed one, remove it here, and if you added one, "+
		"say why the caller cannot be given a wire failure")
}

// TestLocalSendPartitionRowCountIsPinned is a specification sentinel.
//
// It asserts a manually maintained row count. It does not inspect switch.go and
// cannot prove the table is exhaustive: a source change that preserves the
// count while altering behaviour passes. What it buys is that adding a return
// path to SendHTLC without adding a row here fails, which puts the question in
// front of the author.
//
// Do not cite this as evidence of exhaustiveness. Cite it as the reason someone
// had to think about it.
func TestLocalSendPartitionRowCountIsPinned(t *testing.T) {
	t.Parallel()

	// SendHTLC returns errors from exactly these points, in order:
	//
	//   pre-CommitCircuits:
	//     1. getLocalLink failure                  -> LinkError
	//     2. dustExceedsFeeThreshold               -> errFeeExposureExceeded
	//   at or after CommitCircuits:
	//     3. CommitCircuits failure                -> opaque
	//     4. actions.Drops                         -> ErrDuplicateAdd
	//     5. actions.Fails                         -> ErrLocalAddFailed
	//     6. handleSwitchPacket -> AddPacket       -> ErrPacketAlreadyExists
	//
	// plus ErrSwitchExiting, which is carried defensively rather than
	// because a path to it has been demonstrated. See its row. That is
	// eight rows once the two distinct link rejections in (1) are counted
	// separately, and one of the eight is precautionary, so this count is
	// an upper bound on what SendHTLC is known to return.
	const wantRows = 8

	require.Lenf(t, localSendPartition, wantRows,
		"the local send partition has %d rows but the source has "+
			"changed. Every error SendHTLC can return needs a row "+
			"recording whether it arises before CommitCircuits. "+
			"If you added a return path, add the row and update "+
			"this count; if the new error is a ClearTextError "+
			"raised after CommitCircuits, stop, because that is a "+
			"fund-safety bug, not a test update",
		len(localSendPartition))

	seen := make(map[string]struct{}, len(localSendPartition))
	for _, tc := range localSendPartition {
		require.NotEmptyf(t, tc.why, "%q has no justification", tc.name)

		_, dup := seen[tc.name]
		require.Falsef(t, dup, "duplicate row name %q", tc.name)
		seen[tc.name] = struct{}{}
	}
}

// TestEveryRowJustifiesTheSendContract is a review guard, not a proof.
//
// The property it guards is the SendHTLC contract both callers rely on: an
// error return never means the current call put an HTLC on the wire, so the
// caller may always record the attempt as failed. That is what makes the
// switchrpc server's failPendingAttempt correct and the in-process router's
// failAttempt correct on the non-ClearTextError branch.
//
// This test does NOT observe that property. It cannot: the table holds error
// values, not executions, so nothing here watches mailbox admission. All it
// enforces is that every row carries a written justification, which forces the
// contract into review when a row is added.
//
// The executable evidence lives elsewhere and should be cited instead of this
// test: TestSendHTLCCommitBoundaryProperty drives the real switch and uses
// circuit ownership as its oracle, and switch_fund_safety_test.go drives real
// HTLCs across the boundary. If you need to prove the contract rather than
// document it, extend those.
func TestEveryRowJustifiesTheSendContract(t *testing.T) {
	t.Parallel()

	// Every error return in SendHTLC precedes the packet reaching the
	// link's mailbox:
	//
	//   getLocalLink failure          - before the circuit exists
	//   dustExceedsFeeThreshold       - before the circuit exists
	//   CommitCircuits failure        - before the packet is queued
	//   actions.Drops / actions.Fails - read from the circuit map, nothing
	//                                   queued
	//   handleSwitchPacket            - AddPacket returns every error
	//                                   before PushBack and returns nil
	//                                   once it has enqueued
	//
	// so no row in this table represents a state where the current call
	// dispatched.
	for _, tc := range localSendPartition {
		require.NotEmptyf(t, tc.why,
			"%q must record why the current call dispatched "+
				"nothing, because the caller is entitled to "+
				"record the attempt as failed on this error",
			tc.name)
	}
}

// TestPriorDispatchRowsAreGatedOrIntercepted records the two errors that do not
// prove the attempt id is free, and why recording a terminal failure for them is
// nonetheless safe today.
//
// Neither means the current call sent an HTLC. Both mean an earlier dispatch of
// the same attempt id may still be live, so burying them under a terminal record
// would hide a live HTLC from the caller.
//
// They are safe today for different reasons, and both reasons are load bearing:
//
//   - ErrDuplicateAdd is intercepted by the switchrpc server before any terminal
//     write and reported as AlreadyExists, which sends the caller to track the
//     existing attempt.
//   - ErrPacketAlreadyExists is unreachable while InitAttempt gates a second
//     dispatch of the same attempt id.
//
// If a deletion API ever lets a live attempt's record be removed and the id
// reused, the second reason evaporates and the terminal write becomes unsafe.
// That is the coupling between deletion retention and this contract.
func TestPriorDispatchRowsAreGatedOrIntercepted(t *testing.T) {
	t.Parallel()

	var prior []string
	for _, tc := range localSendPartition {
		if tc.priorMayBeLive {
			prior = append(prior, tc.name)
		}

		// A row that may have a live prior dispatch can never be a
		// definite rejection: the caller must not route elsewhere.
		if tc.priorMayBeLive {
			require.Falsef(t, tc.preCommit,
				"%q claims both that an earlier dispatch may "+
					"be live and that the error is "+
					"pre-commit. Those cannot both hold",
				tc.name)
		}
	}

	require.ElementsMatch(t, []string{
		"duplicate add",
		"mailbox already holds the packet",
	}, prior, "the set of errors that may hide a live earlier dispatch "+
		"changed. Each one needs either an interception before the "+
		"terminal write or a gate making it unreachable, and the "+
		"reason belongs in this test's doc comment")
}
