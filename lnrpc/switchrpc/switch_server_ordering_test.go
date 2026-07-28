//go:build switchrpc
// +build switchrpc

package switchrpc

import (
	"testing"

	"github.com/lightningnetwork/lnd/htlcswitch"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestInitAttemptPrecedesValidation asserts that the idempotency gate runs
// before request validation.
//
// Callers read an InvalidArgument error as proof that nothing was dispatched.
// That is only sound because InitAttempt answers first, so a retry of an
// attempt the server already knows about is accepted as already registered and
// never fails validation. If validation moved ahead of the gate, retrying a
// live attempt with a request the server disliked would return InvalidArgument
// for an HTLC that is on the wire, and the caller would fail it and reroute.
//
// The ordering is not otherwise visible: both orderings compile, both pass the
// individual validation tests, and they differ only for a request that is at
// once already-known and malformed.
func TestInitAttemptPrecedesValidation(t *testing.T) {
	t.Parallel()

	// The payment hash is the wrong length, so validation would reject it.
	// That makes the two possible orderings give different answers.
	makeReq := func() *SendOnionRequest {
		return &SendOnionRequest{
			OnionBlob:      make([]byte, lnwire.OnionPacketSize),
			PaymentHash:    []byte{0x01},
			AttemptId:      1,
			Amount:         1000,
			FirstHopChanId: 12345,
		}
	}

	t.Run("known attempt", func(t *testing.T) {
		t.Parallel()

		// A store reporting this attempt is already registered,
		// standing in for one whose HTLC may be in flight.
		store := &mockAttemptStore{
			initErr: htlcswitch.ErrPaymentIDAlreadyExists,
		}
		server, _, err := New(&Config{
			HtlcDispatcher: &mockPayer{},
			AttemptStore:   store,
		})
		require.NoError(t, err)

		resp, err := server.SendOnion(t.Context(), makeReq())
		require.NoError(t, err, "validation ran before the "+
			"idempotency gate: a caller reads this error as not "+
			"dispatched and may reroute an HTLC already on the "+
			"wire")

		accepted := resp.GetAccepted()
		require.NotNil(t, accepted, "want accepted, got %v",
			resp.Outcome)
		require.True(t, accepted.AlreadyRegistered)

		// The known attempt must be left as it was.
		require.Zero(t, store.failCalls)
	})

	t.Run("fresh attempt", func(t *testing.T) {
		t.Parallel()

		// The same request for an attempt the server has not seen is
		// a malformed call: an RPC error, with the attempt recorded
		// failed so that tracking it does not hang.
		store := &mockAttemptStore{}
		server, _, err := New(&Config{
			HtlcDispatcher: &mockPayer{},
			AttemptStore:   store,
		})
		require.NoError(t, err)

		_, err = server.SendOnion(t.Context(), makeReq())
		require.Error(t, err)

		st, ok := status.FromError(err)
		require.True(t, ok, "expected a gRPC status error")
		require.Equal(t, codes.InvalidArgument, st.Code())
		require.Equal(t, 1, store.failCalls)
	})
}
