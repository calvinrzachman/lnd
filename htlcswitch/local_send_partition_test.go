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

	// preCommit records whether the error arises before CommitCircuits, in
	// which case the HTLC provably never left this node.
	preCommit bool

	// priorMayBeLive records whether the error implies that an HTLC from
	// an earlier dispatch of this attempt id may be in flight. The current
	// call never sent anything, but recording the attempt as failed would
	// then hide a live HTLC.
	priorMayBeLive bool

	// why explains preCommit in terms of the code path, so a reader can
	// check it against the source.
	why string
}

// localSendPartition lists every error SendHTLC can return for a local send.
//
// Two properties are recorded. First, no error means the current call put an
// HTLC on the wire: every error is raised before the packet reaches the link's
// mailbox, which is why both callers may record the attempt as failed. Second,
// preCommit says whether the error arises before CommitCircuits, the point at
// which the switch takes ownership. Only then may a caller route elsewhere,
// because otherwise an earlier dispatch of the same attempt id may be live.
//
// The table is reviewed specification and cannot detect a missing row. The
// executable evidence is TestSendHTLCCommitBoundaryProperty and
// switch_fund_safety_test.go.
var localSendPartition = []localSendCase{
	// Before CommitCircuits: nothing has been persisted or queued.
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

	// At or after CommitCircuits: the switch may already own the attempt.
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
			"left on the link may still go out. Unreachable " +
			"while InitAttempt gates a second dispatch of the " +
			"same attempt id; deleting a live record reopens it",
	},
	{
		name:      "switch exiting",
		err:       ErrSwitchExiting,
		preCommit: false,
		why: "not known to be reachable from SendHTLC: switch.go " +
			"returns it only from ProcessContractResolution and " +
			"CloseLink. Kept as a conservative row, since a " +
			"shutting-down switch could not say whether it took " +
			"ownership",
	},
}

// TestLocalSendSoundness asserts that every ClearTextError a local send can
// return arises before CommitCircuits. Callers treat a ClearTextError as proof
// the HTLC is not in flight and may route a new attempt, so a post-commit one
// could pay twice. The converse is not required: an opaque error for a
// pre-commit rejection only costs a retry.
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

// TestLocalSendCompletenessGaps lists the pre-commit errors that carry no wire
// failure, so callers must treat them as unknown although the HTLC never left.
// They cost a retry, never funds; the list keeps them from changing silently.
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

// TestLocalSendPartitionRowCountIsPinned pins the row count by hand, so that
// adding a return path to SendHTLC prompts a new row. It does not prove the
// table is exhaustive.
func TestLocalSendPartitionRowCountIsPinned(t *testing.T) {
	t.Parallel()

	// SendHTLC returns errors from exactly these points, in order:
	//
	//   pre-CommitCircuits:
	//     1. getLocalLink failure      -> LinkError
	//     2. dustExceedsFeeThreshold   -> errFeeExposureExceeded
	//   at or after CommitCircuits:
	//     3. CommitCircuits failure    -> opaque
	//     4. actions.Drops             -> ErrDuplicateAdd
	//     5. actions.Fails             -> ErrLocalAddFailed
	//     6. AddPacket                 -> ErrPacketAlreadyExists
	//
	// plus the conservative ErrSwitchExiting row. Counting the two link
	// rejections in (1) separately gives eight rows.
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

// TestEveryRowJustifiesTheSendContract requires every row to explain why the
// current call dispatched nothing, which callers rely on to record the attempt
// as failed. It is a review guard; the executable evidence is
// TestSendHTLCCommitBoundaryProperty and switch_fund_safety_test.go.
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

// TestPriorDispatchRowsAreGatedOrIntercepted lists the two errors that mean an
// earlier dispatch of the attempt id may be live, where recording a failure
// would hide a live HTLC. Each is safe today for its own reason:
//
//   - ErrDuplicateAdd is intercepted by the switchrpc server before any
//     failure is recorded, and reported as an acknowledgement of the existing
//     attempt.
//   - ErrPacketAlreadyExists is unreachable while InitAttempt gates a second
//     dispatch of the same attempt id. Deleting a live attempt's record would
//     reopen it.
func TestPriorDispatchRowsAreGatedOrIntercepted(t *testing.T) {
	t.Parallel()

	var prior []string
	for _, tc := range localSendPartition {
		if tc.priorMayBeLive {
			prior = append(prior, tc.name)
		}

		// A possibly live earlier dispatch rules out a pre-commit
		// rejection.
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
