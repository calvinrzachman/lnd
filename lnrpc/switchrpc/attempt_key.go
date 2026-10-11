//go:build switchrpc
// +build switchrpc

package switchrpc

import (
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"slices"

	"github.com/lightningnetwork/lnd/lntypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fingerprintVersion is the version of the request fingerprint encoding. It
// is the first byte hashed, so a change to the encoding changes every
// fingerprint. A change across an upgrade makes retries of attempts
// registered before it look like mismatches, which fails closed.
const fingerprintVersion byte = 0

// keyedAttempt is a message that names an attempt by the client's attempt
// key.
type keyedAttempt interface {
	GetPaymentHash() []byte
	GetAttemptId() uint64
}

// attemptKey returns the idempotency key that m names: the 32-byte payment
// hash followed by the big-endian attempt ID.
//
// NOTE: The key's wire shape is defined only here and in switch.proto, so a
// change of shape is confined to the two.
func attemptKey(m keyedAttempt) ([]byte, error) {
	paymentHash := m.GetPaymentHash()
	if len(paymentHash) != lntypes.HashSize {
		return nil, status.Errorf(codes.InvalidArgument,
			"invalid payment_hash length %d, expected %d",
			len(paymentHash), lntypes.HashSize)
	}

	key := make([]byte, lntypes.HashSize+8)
	copy(key, paymentHash)
	binary.BigEndian.PutUint64(key[lntypes.HashSize:], m.GetAttemptId())

	return key, nil
}

// requestFingerprint returns a digest of the fields of a SendOnion request
// that define the HTLC it dispatches. Two requests with the same key must
// have the same fingerprint, or the second is refused. The first hop is
// fingerprinted as requested rather than as resolved, since a first hop given
// by public key may resolve to a different channel on a retry.
func requestFingerprint(req *SendOnionRequest) [32]byte {
	h := sha256.New()

	h.Write([]byte{fingerprintVersion})
	writeBytes(h, req.PaymentHash)
	writeUint64(h, uint64(req.Amount))
	writeUint64(h, uint64(req.Timelock))
	writeUint64(h, req.FirstHopChanId)
	writeBytes(h, req.FirstHopPubkey)
	writeOptionalBytes(h, req.BlindingPoint)
	writeOptionalBytes(h, req.ExtraData)

	// Custom records arrive as a map, so hash them in key order.
	recordKeys := make([]uint64, 0, len(req.CustomRecords))
	for k := range req.CustomRecords {
		recordKeys = append(recordKeys, k)
	}
	slices.Sort(recordKeys)

	writeUint64(h, uint64(len(recordKeys)))
	for _, k := range recordKeys {
		writeUint64(h, k)
		writeBytes(h, req.CustomRecords[k])
	}

	writeBytes(h, req.OnionBlob)

	var fp [32]byte
	copy(fp[:], h.Sum(nil))

	return fp
}

// writeUint64 hashes v as eight big-endian bytes.
func writeUint64(h hash.Hash, v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	h.Write(b[:])
}

// writeBytes hashes b prefixed with its length.
func writeBytes(h hash.Hash, b []byte) {
	writeUint64(h, uint64(len(b)))
	h.Write(b)
}

// writeOptionalBytes hashes a presence byte followed by b if it is set, so an
// unset field and an empty one are distinguished.
func writeOptionalBytes(h hash.Hash, b []byte) {
	if b == nil {
		h.Write([]byte{0})

		return
	}

	h.Write([]byte{1})
	writeBytes(h, b)
}
