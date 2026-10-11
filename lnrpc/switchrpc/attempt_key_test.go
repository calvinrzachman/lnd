//go:build switchrpc
// +build switchrpc

package switchrpc

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestAttemptKey checks the encoding of the client's idempotency key.
func TestAttemptKey(t *testing.T) {
	t.Parallel()

	hash := make([]byte, 32)
	hash[0] = 0xaa

	key, err := attemptKey(&SendOnionRequest{
		PaymentHash: hash,
		AttemptId:   0x0102030405060708,
	})
	require.NoError(t, err)
	require.Len(t, key, 40)
	require.Equal(t, hash, key[:32])
	require.Equal(t, []byte{1, 2, 3, 4, 5, 6, 7, 8}, key[32:])

	// The same attempt ID under a different payment hash is a different
	// key.
	other := make([]byte, 32)
	otherKey, err := attemptKey(&TrackOnionRequest{
		PaymentHash: other,
		AttemptId:   0x0102030405060708,
	})
	require.NoError(t, err)
	require.NotEqual(t, key, otherKey)

	_, err = attemptKey(&SendOnionRequest{
		PaymentHash: make([]byte, 31),
		AttemptId:   1,
	})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

// TestRequestFingerprint checks that the fingerprint changes with every field
// that defines the HTLC, and only with those.
func TestRequestFingerprint(t *testing.T) {
	t.Parallel()

	base := func() *SendOnionRequest {
		return &SendOnionRequest{
			OnionBlob:      []byte{1, 2, 3},
			AttemptId:      7,
			FirstHopChanId: 100,
			Amount:         1000,
			Timelock:       500,
			PaymentHash:    make([]byte, 32),
			CustomRecords: map[uint64][]byte{
				65537: {1},
				65539: {2},
			},
		}
	}
	baseFP := requestFingerprint(base())

	// The same request always yields the same fingerprint.
	require.Equal(t, baseFP, requestFingerprint(base()))

	// The attempt ID is part of the key, not the fingerprint.
	req := base()
	req.AttemptId = 8
	require.Equal(t, baseFP, requestFingerprint(req))

	mutations := map[string]func(*SendOnionRequest){
		"onion": func(r *SendOnionRequest) {
			r.OnionBlob = []byte{1, 2, 4}
		},
		"amount": func(r *SendOnionRequest) {
			r.Amount = 1001
		},
		"timelock": func(r *SendOnionRequest) {
			r.Timelock = 501
		},
		"payment hash": func(r *SendOnionRequest) {
			r.PaymentHash[0] = 1
		},
		"first hop channel": func(r *SendOnionRequest) {
			r.FirstHopChanId = 101
		},
		"first hop by pubkey": func(r *SendOnionRequest) {
			r.FirstHopChanId = 0
			r.FirstHopPubkey = []byte{2, 3}
		},
		"custom record value": func(r *SendOnionRequest) {
			r.CustomRecords[65537] = []byte{9}
		},
		"custom record removed": func(r *SendOnionRequest) {
			delete(r.CustomRecords, 65539)
		},
		"empty blinding point": func(r *SendOnionRequest) {
			r.BlindingPoint = []byte{}
		},
		"extra data": func(r *SendOnionRequest) {
			r.ExtraData = []byte{5}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			req := base()
			mutate(req)
			require.NotEqual(t, baseFP, requestFingerprint(req))
		})
	}
}
