package models

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/lightningnetwork/lnd/lntypes"
)

const (
	// serializedAttemptKeyLen is the exact length needed to encode a
	// serialized AttemptKey: a 32-byte payment identifier followed by an
	// 8-byte sequence number.
	serializedAttemptKeyLen = lntypes.HashSize + 8
)

// ErrInvalidAttemptKeyLen signals that an attempt key could not be decoded
// because the byte slice is of an invalid length.
var ErrInvalidAttemptKeyLen = fmt.Errorf("length of serialized attempt key "+
	"must be %d bytes", serializedAttemptKeyLen)

// AttemptKey uniquely identifies an HTLC attempt in the switch's result store.
// It pairs the payment-level identifier with a per-identifier sequence number
// so that attempts belonging to different payments occupy disjoint key
// subspaces. This lets more than one dispatcher (the local router and an
// external switchrpc client) write into the same store without their attempt
// identifiers colliding.
type AttemptKey struct {
	// Identifier is the payment-level identifier the attempt belongs to:
	// the payment hash for non-AMP payments and the SetID for AMP payments.
	Identifier lntypes.Hash

	// Seq is the attempt sequence within Identifier. For the local router
	// this is the switch's global attempt ID; an external dispatcher may
	// choose its own per-payment sequence.
	Seq uint64
}

// SetBytes deserializes the given bytes into this AttemptKey.
func (k *AttemptKey) SetBytes(bs []byte) error {
	if len(bs) != serializedAttemptKeyLen {
		return ErrInvalidAttemptKeyLen
	}

	copy(k.Identifier[:], bs[:lntypes.HashSize])
	k.Seq = binary.BigEndian.Uint64(bs[lntypes.HashSize:])

	return nil
}

// Bytes returns the serialized bytes for this attempt key. The identifier is
// laid out first so that a byte-ordered scan groups every attempt of one
// payment together, which lets callers iterate a single identifier's attempts
// by prefix.
func (k AttemptKey) Bytes() []byte {
	bs := make([]byte, serializedAttemptKeyLen)
	copy(bs[:lntypes.HashSize], k.Identifier[:])
	binary.BigEndian.PutUint64(bs[lntypes.HashSize:], k.Seq)

	return bs
}

// Encode writes an AttemptKey to the provided io.Writer.
func (k *AttemptKey) Encode(w io.Writer) error {
	_, err := w.Write(k.Bytes())

	return err
}

// Decode reads an AttemptKey from the provided io.Reader.
func (k *AttemptKey) Decode(r io.Reader) error {
	var scratch [serializedAttemptKeyLen]byte
	if _, err := io.ReadFull(r, scratch[:]); err != nil {
		return err
	}

	return k.SetBytes(scratch[:])
}

// String returns a human-readable representation of the attempt key.
func (k AttemptKey) String() string {
	return fmt.Sprintf("%v:%d", k.Identifier, k.Seq)
}
