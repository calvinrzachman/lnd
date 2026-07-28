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
// Callers treat InvalidArgument as definite, meaning no HTLC was dispatched.
// That is only sound because InitAttempt answers first, so a retry of an
// attempt the server already knows about comes back as AlreadyExists and never
// as a validation failure. If validation moved ahead of the gate, retrying a
// live attempt with a request the server disliked would report definite for an
// HTLC that is on the wire, and the caller would fail it and reroute.
//
// The ordering is not otherwise visible: both orderings compile, both pass the
// individual validation tests, and they differ only for a request that is at
// once already-known and malformed.
func TestInitAttemptPrecedesValidation(t *testing.T) {
	t.Parallel()

	// A store reporting this attempt is already registered, standing in for
	// one whose HTLC may be in flight.
	server, _, err := New(&Config{
		HtlcDispatcher: &mockPayer{},
		AttemptStore: &mockAttemptStore{
			initErr: htlcswitch.ErrPaymentIDAlreadyExists,
		},
	})
	require.NoError(t, err)

	// The payment hash is the wrong length, so validation would reject it.
	// That makes the two possible orderings give different answers.
	req := &SendOnionRequest{
		OnionBlob:      make([]byte, lnwire.OnionPacketSize),
		PaymentHash:    []byte{0x01},
		AttemptId:      1,
		Amount:         1000,
		FirstHopChanId: 12345,
	}

	_, err = server.SendOnion(t.Context(), req)
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok, "expected a gRPC status error")

	require.Equalf(t, codes.AlreadyExists, st.Code(),
		"validation ran before the idempotency gate: a known attempt "+
			"reported %v instead of AlreadyExists. A caller reads "+
			"that as definitely-not-dispatched and may reroute an "+
			"HTLC that is already on the wire", st.Code())
}
