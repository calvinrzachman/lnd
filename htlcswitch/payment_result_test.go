package htlcswitch

import (
	"bytes"
	"math/rand"
	"reflect"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
)

// TestNetworkResultSerialization checks that NetworkResults are properly
// (de)serialized.
func TestNetworkResultSerialization(t *testing.T) {
	t.Parallel()

	var preimage lntypes.Preimage
	if _, err := rand.Read(preimage[:]); err != nil {
		t.Fatalf("unable gen rand preimag: %v", err)
	}

	var chanID lnwire.ChannelID
	if _, err := rand.Read(chanID[:]); err != nil {
		t.Fatalf("unable gen rand chanid: %v", err)
	}

	var reason [256]byte
	if _, err := rand.Read(reason[:]); err != nil {
		t.Fatalf("unable gen rand reason: %v", err)
	}

	settle := &lnwire.UpdateFulfillHTLC{
		ChanID:          chanID,
		ID:              2,
		PaymentPreimage: preimage,
	}

	fail := &lnwire.UpdateFailHTLC{
		ChanID:    chanID,
		ID:        1,
		Reason:    []byte{},
		ExtraData: make([]byte, 0),
	}

	fail2 := &lnwire.UpdateFailHTLC{
		ChanID:    chanID,
		ID:        1,
		Reason:    reason[:],
		ExtraData: make([]byte, 0),
	}

	testCases := []*networkResult{
		{
			msg: settle,
		},
		{
			msg:          fail,
			unencrypted:  false,
			isResolution: false,
		},
		{
			msg:          fail,
			unencrypted:  false,
			isResolution: true,
		},
		{
			msg:          fail2,
			unencrypted:  true,
			isResolution: false,
		},
	}

	for _, p := range testCases {
		var buf bytes.Buffer
		if err := serializeNetworkResult(&buf, p); err != nil {
			t.Fatalf("serialize failed: %v", err)
		}

		r := bytes.NewReader(buf.Bytes())
		p1, err := deserializeNetworkResult(r)
		if err != nil {
			t.Fatalf("unable to deserizlize: %v", err)
		}

		if !reflect.DeepEqual(p, p1) {
			t.Fatalf("not equal. %v vs %v", spew.Sdump(p),
				spew.Sdump(p1))
		}
	}
}

// TestNetworkResultStore tests that the networkResult store behaves as
// expected, and that we can store, get and subscribe to results.
func TestNetworkResultStore(t *testing.T) {
	t.Parallel()

	const numResults = 4

	db := channeldb.OpenForTesting(t, t.TempDir())

	store := newNetworkResultStore(db)

	var results []*networkResult
	for i := 0; i < numResults; i++ {
		n := &networkResult{
			msg:          &lnwire.UpdateAddHTLC{},
			unencrypted:  true,
			isResolution: true,
		}
		results = append(results, n)
	}

	// Subscribe to 2 of them.
	var subs []<-chan *networkResult
	for i := uint64(0); i < 2; i++ {
		sub, err := store.subscribeResult(i)
		if err != nil {
			t.Fatalf("unable to subscribe: %v", err)
		}
		subs = append(subs, sub)
	}

	// Store three of them.
	for i := uint64(0); i < 3; i++ {
		err := store.storeResult(i, results[i])
		if err != nil {
			t.Fatalf("unable to store result: %v", err)
		}
	}

	// The two subscribers should be notified.
	for _, sub := range subs {
		select {
		case <-sub:
		case <-time.After(1 * time.Second):
			t.Fatalf("no result received")
		}
	}

	// Let the third one subscribe now. THe result should be received
	// immediately.
	sub, err := store.subscribeResult(2)
	require.NoError(t, err, "unable to subscribe")
	select {
	case <-sub:
	case <-time.After(1 * time.Second):
		t.Fatalf("no result received")
	}

	// Try fetching the result directly for the non-stored one. This should
	// fail.
	_, err = store.getResult(3)
	if err != ErrPaymentIDNotFound {
		t.Fatalf("expected ErrPaymentIDNotFound, got %v", err)
	}

	// Add the result and try again.
	err = store.storeResult(3, results[3])
	require.NoError(t, err, "unable to store result")

	_, err = store.getResult(3)
	require.NoError(t, err, "unable to get result")

	// Since we don't delete results from the store (yet), make sure we
	// will get subscriptions for all of them.
	for i := uint64(0); i < numResults; i++ {
		sub, err := store.subscribeResult(i)
		if err != nil {
			t.Fatalf("unable to subscribe: %v", err)
		}

		select {
		case <-sub:
		case <-time.After(1 * time.Second):
			t.Fatalf("no result received")
		}
	}

	// Clean the store keeping the first two results.
	toKeep := map[uint64]struct{}{
		0: {},
		1: {},
	}
	// Finally, delete the result.
	err = store.cleanStore(toKeep)
	require.NoError(t, err)

	// Payment IDs 0 and 1 should be found, 2 and 3 should be deleted.
	for i := uint64(0); i < numResults; i++ {
		_, err = store.getResult(i)
		if i <= 1 {
			require.NoError(t, err, "unable to get result")
		}
		if i >= 2 && err != ErrPaymentIDNotFound {
			t.Fatalf("expected ErrPaymentIDNotFound, got %v", err)
		}
	}
}

func TestNamespacedIDEncoding(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		namespace  byte
		rawID      uint64
		expectFail bool
	}{
		{
			name:      "zero namespace, small raw ID",
			namespace: 0x00,
			rawID:     42,
		},
		{
			name:      "non-zero namespace, small raw ID",
			namespace: 0x1A,
			rawID:     12345,
		},
		{
			name:      "max raw ID, namespace 0xFF",
			namespace: 0xFF,
			rawID:     maxRawAttemptID,
		},
		{
			name:       "raw ID exceeds 56-bit max",
			namespace:  0x01,
			rawID:      maxRawAttemptID + 1,
			expectFail: true,
		},
	}

	for _, tc := range testCases {
		tc := tc // capture range variable
		t.Run(tc.name, func(t *testing.T) {
			namespacedID, err := EncodeNamespacedID(tc.namespace, tc.rawID)

			if tc.expectFail {
				require.ErrorIs(t, err, ErrMaxIDSizeExceeded)
				return
			}

			require.NoError(t, err, "unexpected failure encoding ID")

			ns := DecodeNamespace(namespacedID)
			require.Equal(t, tc.namespace, ns, "namespace mismatch")

			raw := DecodeRawID(namespacedID)
			require.Equal(t, tc.rawID, raw, "raw ID mismatch")

			// Ensure the ID does not exceed 64 bits.
			require.LessOrEqual(t, namespacedID, uint64(^uint64(0)))
		})
	}
}
