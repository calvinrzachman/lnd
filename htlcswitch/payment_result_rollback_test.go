package htlcswitch

import (
	"testing"

	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/kvdb"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
)

// markerPresent reports whether the external-lifecycle marker bucket exists.
func markerPresent(t *testing.T, db kvdb.Backend) bool {
	t.Helper()

	var marked bool
	err := db.View(func(tx kvdb.RTx) error {
		marked = tx.ReadBucket(externalLifecycleMarkerBucket) != nil

		return nil
	}, func() {
		marked = false
	})
	require.NoError(t, err)

	return marked
}

// TestRollbackRoundTrip pins the image-rollback path as a single property
// rather than as two separately verified halves.
//
// TestMarkerCollision proves a local-mode store refuses to open while the
// marker is set. TestDisableRemoteRouter proves DisableRemoteRouter removes the
// marker. Neither proves the composition, which is the step an operator
// actually performs: convert to a switchrpc build, then later clear the marker
// and boot the no-switchrpc image. Verifying two steps separately is not the
// same as verifying that the second leaves the first recoverable, and this
// property is currently asserted in runbooks rather than in code.
//
// IMPORTANT, and the reason this test does not claim rollback is safe:
// DisableRemoteRouter samples an instant. It does not stop the switchrpc
// subserver and does not latch anything, so between DRR returning and the image
// swap completing the node still serves SendOnion with the marker already gone.
// A dispatch in that window writes a real HTLC and a real store entry, and the
// swap then succeeds anyway because local mode checks only marker presence,
// never store contents. See
// @claude/plans/pr-review/disable-local-router-10178/guard-and-rollback-findings.md
// section 6. This test pins the mechanism, not the operational guarantee.
//
// Note also that only a *custom* no-switchrpc build performs this check.
// Stock lnd v0.21.1-beta contains neither validateLifecycleMode nor the marker
// bucket, so it boots regardless of marker state. Rolling to stock skips every
// check; the no-switchrpc image is the thing that gates you.
func TestRollbackRoundTrip(t *testing.T) {
	t.Parallel()

	t.Run("empty store clears and reopens local", func(t *testing.T) {
		t.Parallel()

		db := channeldb.OpenForTesting(t, t.TempDir())

		// Convert: an external-mode store writes the marker.
		external, err := newNetworkResultStore(db, true)
		require.NoError(t, err)
		require.True(t, markerPresent(t, db), "external mode must "+
			"write the lifecycle marker")

		// While marked, the no-switchrpc image cannot boot. This is
		// the precondition that makes the clear step necessary.
		_, err = newNetworkResultStore(db, false)
		require.Error(t, err, "local mode must refuse while marked")

		// Clear the marker with an empty store, as the runbook's
		// rollback step does.
		require.NoError(t, external.DisableRemoteRouter())
		require.False(t, markerPresent(t, db), "DisableRemoteRouter "+
			"must remove the marker")

		// The composition under test: the no-switchrpc image now boots
		// clean. If a future change added a second gate on some other
		// persisted state, this is the assertion that would catch it.
		_, err = newNetworkResultStore(db, false)
		require.NoError(t, err, "local mode must open cleanly once "+
			"the marker is cleared")
	})

	t.Run("non-empty store blocks the rollback", func(t *testing.T) {
		t.Parallel()

		db := channeldb.OpenForTesting(t, t.TempDir())

		external, err := newNetworkResultStore(db, true)
		require.NoError(t, err)

		// A single result is enough to hold the marker in place.
		require.NoError(t, external.storeResult(0, &networkResult{
			msg: &lnwire.UpdateAddHTLC{},
		}))

		require.ErrorIs(
			t, external.DisableRemoteRouter(),
			ErrAttemptEntriesExist,
		)
		require.True(t, markerPresent(t, db), "a refused clear must "+
			"leave the marker in place")

		// And so the rollback image still cannot boot. This is the
		// operationally important half: a gateway whose store is not
		// empty has no cheap way back, which is why the conversion
		// procedure drains the store before converting rather than
		// after.
		_, err = newNetworkResultStore(db, false)
		require.Error(t, err, "local mode must still refuse while the "+
			"store holds entries and the marker stands")
	})
}
