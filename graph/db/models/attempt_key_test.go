package models

import (
	"bytes"
	"testing"

	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// drawAttemptKey draws an arbitrary AttemptKey for property testing.
func drawAttemptKey(t *rapid.T) AttemptKey {
	var id lntypes.Hash
	copy(id[:], rapid.SliceOfN(rapid.Byte(), lntypes.HashSize,
		lntypes.HashSize).Draw(t, "identifier"))

	return AttemptKey{
		Identifier: id,
		Seq:        rapid.Uint64().Draw(t, "seq"),
	}
}

// TestAttemptKeyRoundTrip asserts that both the Bytes/SetBytes and Encode/Decode
// paths reproduce the original key, and that the serialized form is always the
// fixed key length.
func TestAttemptKeyRoundTrip(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		key := drawAttemptKey(t)

		bs := key.Bytes()
		require.Len(t, bs, serializedAttemptKeyLen)

		var fromBytes AttemptKey
		require.NoError(t, fromBytes.SetBytes(bs))
		require.Equal(t, key, fromBytes)

		var buf bytes.Buffer
		require.NoError(t, key.Encode(&buf))

		var decoded AttemptKey
		require.NoError(t, decoded.Decode(&buf))
		require.Equal(t, key, decoded)
	})
}

// TestAttemptKeyOrdering asserts that the byte encoding sorts identifier-major,
// then by sequence. This is what lets callers iterate a single payment's
// attempts by identifier prefix in a byte-ordered store.
func TestAttemptKeyOrdering(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		a := drawAttemptKey(t)
		b := drawAttemptKey(t)

		byteCmp := bytes.Compare(a.Bytes(), b.Bytes())

		var wantCmp int
		switch idCmp := bytes.Compare(
			a.Identifier[:], b.Identifier[:],
		); {
		case idCmp != 0:
			wantCmp = idCmp
		case a.Seq < b.Seq:
			wantCmp = -1
		case a.Seq > b.Seq:
			wantCmp = 1
		}

		require.Equal(t, normalizeCmp(wantCmp), normalizeCmp(byteCmp))
	})
}

// normalizeCmp collapses a comparison result to -1, 0, or 1.
func normalizeCmp(c int) int {
	switch {
	case c < 0:
		return -1
	case c > 0:
		return 1
	default:
		return 0
	}
}

// TestAttemptKeySetBytesInvalidLen asserts that decoding rejects byte slices of
// the wrong length rather than silently truncating.
func TestAttemptKeySetBytesInvalidLen(t *testing.T) {
	t.Parallel()

	for _, n := range []int{0, 8, 16, serializedAttemptKeyLen - 1,
		serializedAttemptKeyLen + 1} {

		var key AttemptKey
		err := key.SetBytes(make([]byte, n))
		require.ErrorIs(t, err, ErrInvalidAttemptKeyLen)
	}
}
