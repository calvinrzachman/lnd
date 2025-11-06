package htlcswitch

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
)

// TestSwitchSendHTLCSyncRollback tests that if SendHTLC fails after the
// attempt has been initialized, a final failure result is synchronously
// stored in the attempt store. This is critical to prevent callers of
// GetAttemptResult from hanging indefinitely.
func TestSwitchSendHTLCSyncRollback(t *testing.T) {
	t.Parallel()

	// Create a new switch with a persistent attempt store. We can use the
	// unexported helper from switch_test.go since we are in the same
	// package.
	s, err := initSwitchWithTempDB(t, 0)
	require.NoError(t, err)
	require.NoError(t, s.Start())
	t.Cleanup(func() { require.NoError(t, s.Stop()) })

	// We will attempt to send an HTLC to a non-existent channel. This will
	// cause SendHTLC to fail after the attempt has been initialized.
	invalidScid := lnwire.NewShortChanIDFromInt(123)
	attemptID := uint64(1)
	htlc := &lnwire.UpdateAddHTLC{}

	// The call to SendHTLC should fail.
	err = s.SendHTLC(invalidScid, attemptID, htlc)
	require.Error(t, err)

	// Now, we check the attempt store for the result. We expect to find a
	// final FAILED result, not ErrPaymentIDNotFound or
	// ErrAttemptResultNotAvailable.
	result, err := s.attemptStore.GetResult(attemptID)
	require.NoError(t, err, "expected to find a final result")
	require.NotNil(t, result, "result should not be nil")

	// The result should be a failure message.
	failMsg, ok := result.msg.(*lnwire.UpdateFailHTLC)
	require.True(t, ok, "expected an UpdateFailHTLC message")

	// Since this was a local failure, the reason should be an unencrypted
	// failure message that we can decode.
	require.True(t, result.unencrypted, "expected unencrypted failure")
	reason, err := lnwire.DecodeFailure(
		bytes.NewReader(failMsg.Reason), 0,
	)
	require.NoError(t, err, "unable to decode failure reason")

	// We expect the specific failure to be an UnknownNextPeer error, since
	// that's what our SendHTLC call should have failed with.
	_, ok = reason.(*lnwire.FailUnknownNextPeer)
	require.True(t, ok, "expected unknown next peer failure")

	// Now, we'll call GetAttemptResult. Since the synchronous rollback
	// should have already stored a final result, we expect this call to
	// return immediately with a failed result.
	resChan, err := s.GetAttemptResult(attemptID, lntypes.Hash{}, nil)
	require.NoError(t, err, "GetAttemptResult should not fail")

	// We expect to receive a result immediately.
	select {
	case result := <-resChan:
		// The result should be a failure.
		require.Error(t, result.Error, "expected a failed result")

	case <-time.After(100 * time.Millisecond):
		t.Fatalf("GetAttemptResult should have returned immediately")
	}
}

// TestSwitchGetAttemptResultHangsOnOrphanedAttempt tests that a caller to
// GetAttemptResult will hang if an attempt is orphaned in the pending state,
// and that the synchronous rollback (`failAttempt`) fixes this.
func TestSwitchGetAttemptResultHangsOnOrphanedAttempt(t *testing.T) {
	t.Parallel()

	s, err := initSwitchWithTempDB(t, 0)
	require.NoError(t, err)
	require.NoError(t, s.Start())
	t.Cleanup(func() { require.NoError(t, s.Stop()) })

	// Manually initialize an attempt in the store. This simulates the "bad"
	// state where an attempt is pending but has no corresponding circuit,
	// which our SendHTLC changes are designed to prevent.
	attemptID := uint64(1)
	err = s.attemptStore.InitAttempt(attemptID)
	require.NoError(t, err, "unable to initialize attempt")

	// Now, call GetAttemptResult in a goroutine. This function returns a
	// channel that will deliver the result.
	resultCheckChan := make(chan *PaymentResult)
	errChan := make(chan error)
	go func() {
		resChan, err := s.GetAttemptResult(
			attemptID, lntypes.Hash{}, nil,
		)
		if err != nil {
			errChan <- err
			return
		}

		// Wait for the result to be delivered on the returned
		// channel. We add a timeout here to prevent the test
		// goroutine from leaking if something goes wrong.
		select {
		case result := <-resChan:
			// Once we receive the result, we forward it to our
			// test's result channel.
			resultCheckChan <- result
		case <-time.After(5 * time.Second):
			errChan <- errors.New("goroutine timed out")
		}
	}()

	// We expect the call to hang. We'll use a timeout to verify that no
	// result is received.
	select {
	case <-resultCheckChan:
		t.Fatalf("received result unexpectedly, should have hung")
	case err := <-errChan:
		t.Fatalf("received error unexpectedly: %v", err)
	case <-time.After(100 * time.Millisecond):
		// This is the expected path, the call has "hung" for 100ms.
	}

	// Now, simulate the fix by manually calling failAttempt. This is what
	// SendHTLC now does synchronously on failure.
	s.failAttempt(attemptID, NewLinkError(&lnwire.FailTemporaryNodeFailure{}))

	// The goroutine should now un-hang and deliver the final failed result.
	select {
	case result := <-resultCheckChan:
		// We expect a result with an error, indicating failure.
		require.Error(t, result.Error, "expected a failed result")
	case err := <-errChan:
		t.Fatalf("received unexpected error: %v", err)
	case <-time.After(1 * time.Second):
		t.Fatalf("did not receive result after manual failure")
	}
}

// TestSwitchOrphanedAttemptCleanup tests that the switch's startup procedure
// will correctly identify and clean up any orphaned attempts left in the
// 'pending' state. This can occur if the sync rollback of the initialization
// fails or we crash in between attempt initialization and commiting the attempt
// to the circuit map.
func TestSwitchOrphanedAttemptCleanup(t *testing.T) {
	t.Parallel()

	// Create a temporary database path that will persist across restarts.
	tempPath := t.TempDir()

	// First, we'll create a database and a switch instance.
	cdb1 := channeldb.OpenForTesting(t, tempPath)
	s1, err := initSwitchWithDB(0, cdb1)
	require.NoError(t, err)
	require.NoError(t, s1.Start())

	// Manually initialize an attempt to simulate the state of the database
	// if the node crashed after InitAttempt.
	attemptID := uint64(1)
	err = s1.attemptStore.InitAttempt(attemptID)
	require.NoError(t, err, "unable to initialize attempt")

	// We must stop the switch and close its database to ensure the state
	// is flushed to disk at tempPath.
	require.NoError(t, s1.Stop())
	require.NoError(t, cdb1.Close())

	// Now, we'll create a new database instance from the same path and a
	// new switch. This simulates a node restart.
	cdb2 := channeldb.OpenForTesting(t, tempPath)
	t.Cleanup(func() { cdb2.Close() })

	s2, err := initSwitchWithDB(0, cdb2)
	require.NoError(t, err)
	require.NoError(t, s2.Start())
	t.Cleanup(func() { require.NoError(t, s2.Stop()) })

	// After startup, we query the store for our orphaned attempt ID. We
	// expect to find a final FAILED result, as the janitor should have
	// cleaned it up.
	result, err := s2.attemptStore.GetResult(attemptID)
	require.NoError(t, err, "expected to find a final result")
	require.NotNil(t, result, "result should not be nil")

	// The result should be a failure message.
	failMsg, ok := result.msg.(*lnwire.UpdateFailHTLC)
	require.True(t, ok, "expected an UpdateFailHTLC message")

	// The janitor uses a generic failure reason, since it cannot know the
	// original cause.
	require.True(t, result.unencrypted, "expected unencrypted failure")
	reason, err := lnwire.DecodeFailure(
		bytes.NewReader(failMsg.Reason), 0,
	)
	require.NoError(t, err, "unable to decode failure reason")

	// We expect the specific failure to be a FailTemporaryNodeFailure.
	_, ok = reason.(*lnwire.FailTemporaryNodeFailure)
	require.True(t, ok, "expected temporary node failure")
}
