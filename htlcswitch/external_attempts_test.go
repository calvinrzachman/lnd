package htlcswitch

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/kvdb"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
)

// testIDSource returns a nextID function that counts up from start, and a
// counter of how many times it was called.
func testIDSource(start uint64) (func() (uint64, error), *atomic.Int64) {
	var (
		next  atomic.Uint64
		calls atomic.Int64
	)
	next.Store(start)

	return func() (uint64, error) {
		calls.Add(1)

		return next.Add(1) - 1, nil
	}, &calls
}

// newTestExternalStore creates a result store backed by a fresh database.
func newTestExternalStore(t *testing.T) (*networkResultStore,
	*channeldb.DB) {

	t.Helper()

	db := channeldb.OpenForTesting(t, t.TempDir())
	store := newNetworkResultStore(db)

	return store, db
}

// settleAttempt stores a settle result for the internal attempt ID.
func settleAttempt(t *testing.T, store *networkResultStore, id uint64) {
	t.Helper()

	require.NoError(t, store.StoreResult(id, &networkResult{
		msg:         &lnwire.UpdateFulfillHTLC{},
		unencrypted: true,
	}))
}

// TestInitAttempt checks registration of an external key: a new key
// allocates an internal ID, a repeat with the same fingerprint returns that ID
// as a duplicate, and a repeat with a different fingerprint is refused.
func TestInitAttempt(t *testing.T) {
	t.Parallel()

	store, _ := newTestExternalStore(t)
	nextID, calls := testIDSource(100)

	key := []byte("payment-a/attempt-1")
	fp := [32]byte{1}

	// A new key allocates an internal ID and writes a pending
	// placeholder for it.
	id, err := store.InitAttempt(key, fp, nextID)
	require.NoError(t, err)
	require.EqualValues(t, 100, id)
	require.EqualValues(t, 1, calls.Load())

	_, err = store.GetResult(id)
	require.ErrorIs(t, err, ErrAttemptResultPending)

	got, err := store.LookupAttempt(key)
	require.NoError(t, err)
	require.Equal(t, id, got)

	// The same key with the same fingerprint is a duplicate. It returns
	// the original internal ID and allocates nothing.
	dupID, err := store.InitAttempt(key, fp, nextID)
	require.ErrorIs(t, err, ErrPaymentIDAlreadyExists)
	require.Equal(t, id, dupID)
	require.EqualValues(t, 1, calls.Load())

	// The same key with a different fingerprint is refused.
	_, err = store.InitAttempt(key, [32]byte{2}, nextID)
	require.ErrorIs(t, err, ErrAttemptFingerprintMismatch)
	require.EqualValues(t, 1, calls.Load())

	// A different key gets a different internal ID.
	otherID, err := store.InitAttempt(
		[]byte("payment-b/attempt-1"), fp, nextID,
	)
	require.NoError(t, err)
	require.NotEqual(t, id, otherID)

	// An empty key is rejected.
	_, err = store.InitAttempt(nil, fp, nextID)
	require.ErrorIs(t, err, ErrEmptyExternalKey)
}

// TestInitAttemptAllocationError checks that a failure to allocate an
// internal ID is reported as ambiguous and leaves no index entry behind.
func TestInitAttemptAllocationError(t *testing.T) {
	t.Parallel()

	store, _ := newTestExternalStore(t)
	failing := func() (uint64, error) {
		return 0, errors.New("sequencer unavailable")
	}

	key := []byte("key")
	_, err := store.InitAttempt(key, [32]byte{}, failing)
	require.ErrorIs(t, err, ErrAmbiguousAttemptInit)

	_, err = store.LookupAttempt(key)
	require.ErrorIs(t, err, ErrPaymentIDNotFound)
}

// TestInitAttemptUsedID checks that an allocated internal ID which
// already has a record is never overwritten: the registration is reported as
// ambiguous, nothing is written, and a retry allocates the next ID.
func TestInitAttemptUsedID(t *testing.T) {
	t.Parallel()

	store, _ := newTestExternalStore(t)

	// A record under ID 5, which the sequencer hands out next.
	settleAttempt(t, store, 5)

	key := []byte("key")
	nextID, calls := testIDSource(5)
	_, err := store.InitAttempt(key, [32]byte{}, nextID)
	require.ErrorIs(t, err, ErrAmbiguousAttemptInit)
	require.ErrorIs(t, err, errInternalIDInUse)
	require.EqualValues(t, 1, calls.Load())

	// The existing record is untouched and the key is not registered.
	result, err := store.GetResult(5)
	require.NoError(t, err)
	require.IsType(t, &lnwire.UpdateFulfillHTLC{}, result.msg)
	_, err = store.LookupAttempt(key)
	require.ErrorIs(t, err, ErrPaymentIDNotFound)

	id, err := store.InitAttempt(key, [32]byte{}, nextID)
	require.NoError(t, err)
	require.EqualValues(t, 6, id)
}

// TestInitAttemptConcurrent checks that concurrent registrations of
// the same key yield exactly one internal ID.
func TestInitAttemptConcurrent(t *testing.T) {
	t.Parallel()

	store, _ := newTestExternalStore(t)
	nextID, calls := testIDSource(1)

	const workers = 16
	var (
		wg       sync.WaitGroup
		ids      = make([]uint64, workers)
		errs     = make([]error, workers)
		key      = []byte("same-key")
		fp       = [32]byte{7}
		startSig = make(chan struct{})
	)
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-startSig
			ids[i], errs[i] = store.InitAttempt(
				key, fp, nextID,
			)
		}()
	}
	close(startSig)
	wg.Wait()

	var fresh int
	for i := range workers {
		switch {
		case errs[i] == nil:
			fresh++
		default:
			require.ErrorIs(t, errs[i], ErrPaymentIDAlreadyExists)
		}
		require.Equal(t, ids[0], ids[i])
	}
	require.Equal(t, 1, fresh)
	require.EqualValues(t, 1, calls.Load())
}

// TestDeleteAttempts checks that terminal attempts are deleted
// together with their index entries, pending attempts are kept, and statuses
// follow the order of the requested keys.
func TestDeleteAttempts(t *testing.T) {
	t.Parallel()

	store, _ := newTestExternalStore(t)
	nextID, _ := testIDSource(1)

	pendingKey := []byte("pending")
	settledKey := []byte("settled")
	unknownKey := []byte("unknown")

	_, err := store.InitAttempt(pendingKey, [32]byte{}, nextID)
	require.NoError(t, err)

	settledID, err := store.InitAttempt(
		settledKey, [32]byte{}, nextID,
	)
	require.NoError(t, err)
	settleAttempt(t, store, settledID)

	statuses, err := store.DeleteAttempts(
		[][]byte{settledKey, unknownKey, pendingKey},
	)
	require.NoError(t, err)
	require.Equal(t, []DeletionStatus{
		DeletionOK, DeletionNotFound, DeletionPending,
	}, statuses)

	// The settled attempt's record and index entry are both gone.
	_, err = store.LookupAttempt(settledKey)
	require.ErrorIs(t, err, ErrPaymentIDNotFound)
	_, err = store.GetResult(settledID)
	require.ErrorIs(t, err, ErrPaymentIDNotFound)

	// The pending attempt is untouched.
	pendingID, err := store.LookupAttempt(pendingKey)
	require.NoError(t, err)
	_, err = store.GetResult(pendingID)
	require.ErrorIs(t, err, ErrAttemptResultPending)

	// Registering a deleted key again allocates a new internal ID.
	newID, err := store.InitAttempt(settledKey, [32]byte{}, nextID)
	require.NoError(t, err)
	require.NotEqual(t, settledID, newID)

	// Duplicate keys in one request are rejected.
	_, err = store.DeleteAttempts([][]byte{pendingKey, pendingKey})
	require.Error(t, err)

	// An empty request is a no-op.
	statuses, err = store.DeleteAttempts(nil)
	require.NoError(t, err)
	require.Empty(t, statuses)
}

// TestExternalAttemptFailedPending checks that an attempt failed in place, as
// orphan cleanup does on restart, stays reachable through its key and can then
// be deleted.
func TestExternalAttemptFailedPending(t *testing.T) {
	t.Parallel()

	store, db := newTestExternalStore(t)
	nextID, _ := testIDSource(1)

	key := []byte("key")
	id, err := store.InitAttempt(key, [32]byte{}, nextID)
	require.NoError(t, err)

	require.NoError(t, store.FailPendingAttempt(
		id, NewLinkError(&lnwire.FailTemporaryNodeFailure{}),
	))

	// A store reopened on the same database still resolves the key to
	// the failed record.
	reopened := newNetworkResultStore(db)

	got, err := reopened.LookupAttempt(key)
	require.NoError(t, err)
	require.Equal(t, id, got)

	result, err := reopened.GetResult(id)
	require.NoError(t, err)
	require.IsType(t, &lnwire.UpdateFailHTLC{}, result.msg)

	statuses, err := reopened.DeleteAttempts([][]byte{key})
	require.NoError(t, err)
	require.Equal(t, []DeletionStatus{DeletionOK}, statuses)
}

// requireRecord asserts whether a record exists for the internal attempt ID.
func requireRecord(t *testing.T, store *networkResultStore, id uint64,
	want bool) {

	t.Helper()

	var exists bool
	err := kvdb.View(store.backend, func(tx kvdb.RTx) error {
		exists = resultExists(tx, id)

		return nil
	}, func() {})
	require.NoError(t, err)
	require.Equal(t, want, exists, "record for attempt %d", id)
}

// TestCleanStoreOwnerAware checks that CleanStore never removes an attempt
// named in the external attempt index, while it still removes unindexed
// results that are not in the keep set.
func TestCleanStoreOwnerAware(t *testing.T) {
	t.Parallel()

	store, _ := newTestExternalStore(t)
	nextID, _ := testIDSource(100)

	// Register two external attempts, one left pending and one settled.
	pendingID, err := store.InitAttempt(
		[]byte("ext-pending"), [32]byte{1}, nextID,
	)
	require.NoError(t, err)

	settledID, err := store.InitAttempt(
		[]byte("ext-settled"), [32]byte{2}, nextID,
	)
	require.NoError(t, err)
	settleAttempt(t, store, settledID)

	// Write two results for the local router, with no index entry.
	const (
		routerStale uint64 = 5
		routerKept  uint64 = 6
	)
	settleAttempt(t, store, routerStale)
	settleAttempt(t, store, routerKept)

	// With an empty keep set, only the indexed attempts survive.
	require.NoError(t, store.CleanStore(map[uint64]struct{}{}))
	requireRecord(t, store, pendingID, true)
	requireRecord(t, store, settledID, true)
	requireRecord(t, store, routerStale, false)
	requireRecord(t, store, routerKept, false)

	// A keep-listed result survives alongside the indexed attempts, while
	// an unlisted one is removed.
	settleAttempt(t, store, routerStale)
	settleAttempt(t, store, routerKept)
	require.NoError(t, store.CleanStore(map[uint64]struct{}{
		routerKept: {},
	}))
	requireRecord(t, store, pendingID, true)
	requireRecord(t, store, settledID, true)
	requireRecord(t, store, routerStale, false)
	requireRecord(t, store, routerKept, true)

	// The index itself is untouched, so both keys still resolve.
	for _, key := range []string{"ext-pending", "ext-settled"} {
		_, err := store.LookupAttempt([]byte(key))
		require.NoError(t, err)
	}
}

// TestCleanStoreAfterExternalDelete checks that deleting an external attempt
// by key removes its index entry, so it no longer protects anything and a
// later CleanStore may remove whatever is left.
func TestCleanStoreAfterExternalDelete(t *testing.T) {
	t.Parallel()

	store, _ := newTestExternalStore(t)
	nextID, _ := testIDSource(100)

	key := []byte("ext-settled")
	id, err := store.InitAttempt(key, [32]byte{1}, nextID)
	require.NoError(t, err)
	settleAttempt(t, store, id)

	statuses, err := store.DeleteAttempts([][]byte{key})
	require.NoError(t, err)
	require.Equal(t, []DeletionStatus{DeletionOK}, statuses)

	_, err = store.LookupAttempt(key)
	require.ErrorIs(t, err, ErrPaymentIDNotFound)

	var indexed map[uint64]struct{}
	err = kvdb.View(store.backend, func(tx kvdb.RTx) error {
		indexed, err = fetchIndexedAttemptIDs(tx)

		return err
	}, func() {})
	require.NoError(t, err)
	require.Empty(t, indexed)

	// A result written under the freed ID, with no index entry, is no
	// longer protected and is removed.
	settleAttempt(t, store, id)
	require.NoError(t, store.CleanStore(map[uint64]struct{}{}))
	requireRecord(t, store, id, false)
}

// TestCleanStoreUnreadableIndex checks that CleanStore removes nothing when
// an index entry cannot be decoded, since the attempt it protects is unknown.
func TestCleanStoreUnreadableIndex(t *testing.T) {
	t.Parallel()

	store, _ := newTestExternalStore(t)

	const routerStale uint64 = 5
	settleAttempt(t, store, routerStale)

	err := kvdb.Update(store.backend, func(tx kvdb.RwTx) error {
		index, err := tx.CreateTopLevelBucket(
			externalAttemptIndexBucketKey,
		)
		if err != nil {
			return err
		}

		return index.Put([]byte("corrupt"), []byte{0xff})
	}, func() {})
	require.NoError(t, err)

	require.NoError(t, store.CleanStore(map[uint64]struct{}{}))
	requireRecord(t, store, routerStale, true)
}
