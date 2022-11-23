package lnwire

import (
	"io"

	"github.com/lightningnetwork/lnd/tlv"
)

/*
	NOTE: Unlike AMP and MPP, here we have a single onion type/TLV value
	So this is not the deciding factor on how we define our TLV record

	However, like AMP and MPP we make a "dynamic record".
	AMP & MPP are represented as Go structs (not basic TLV type).
	ChannelType is represented as a RawFeatureVector (also not a basic TLV type).

	A RawFeatureVector can apparently vary in size, which is why we
	reach for tlv.MakeDynamicRecord() to define a dynamically sized record.

*/

const (
	// ChannelTypeRecordType is the type of the experimental record used
	// to denote which channel type is being negotiated.
	ChannelTypeRecordType tlv.Type = 1
)

// ChannelType represents a specific channel type as a set of feature bits that
// comprise it.
type ChannelType RawFeatureVector

// featureBitLen returns the length in bytes of the encoded feature bits.
func (c ChannelType) featureBitLen() uint64 {
	fv := RawFeatureVector(c)
	return uint64(fv.SerializeSize())
}

// Record returns a TLV record that can be used to encode/decode the channel
// type from a given TLV stream.
//
// ***IMPORTANT NOTE: When we make the record we give it a POINTER to
// a user defined Go type. It is this pointer which will point to a value
// after deserialization. This completes the map from raw bytes —> Go type (Decode).
func (c *ChannelType) Record() tlv.Record {
	return tlv.MakeDynamicRecord(
		ChannelTypeRecordType, c, c.featureBitLen, channelTypeEncoder,
		channelTypeDecoder,
	)
}

// channelTypeEncoder is a custom TLV encoder for the ChannelType record.
func channelTypeEncoder(w io.Writer, val interface{}, buf *[8]byte) error {
	if v, ok := val.(*ChannelType); ok {
		// Encode the feature bits as a byte slice without its length
		// prepended, as that's already taken care of by the TLV record.
		fv := RawFeatureVector(*v)
		return fv.encode(w, fv.SerializeSize(), 8)
	}

	return tlv.NewTypeForEncodingErr(val, "lnwire.ChannelType")
}

// channelTypeDecoder is a custom TLV decoder for the ChannelType record.
func channelTypeDecoder(r io.Reader, val interface{}, buf *[8]byte, l uint64) error {
	if v, ok := val.(*ChannelType); ok {
		fv := NewRawFeatureVector()
		if err := fv.decode(r, int(l), 8); err != nil {
			return err
		}
		*v = ChannelType(*fv)
		return nil
	}

	return tlv.NewTypeForEncodingErr(val, "lnwire.ChannelType")
}
