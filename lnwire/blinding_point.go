package lnwire

import (
	"io"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightningnetwork/lnd/tlv"
)

const (

	// BlindingPointRecordType is the type which refers to an ephemeral
	// public key used in route blinding.
	BlindingPointRecordType tlv.Type = 1
)

// NOTE(9/20/22): The swap from tlv.Record to tlv.RecordProducer inside
// ExtractRecords precludes one from being able to leverage the "primitive" TLV
// types. Instead it pushes a user to define his own custom type so that he may
// satisfy the RecordProducer interface{}, but this comes with its own
// complexities in (en/de)coding since you now have pointers or pointers to
// pointers to keep track of and need to use type cast/conversions.
type BlindingPoint btcec.PublicKey

// Record returns a TLV record that can be used to encode/decode the channel
// type from a given TLV stream.
func (b *BlindingPoint) Record() tlv.Record {
	// IDEA(9/20/22): Create point, type assert btcec.PublicKey
	// and use predefined codec for public keys.
	// point := new(btcec.PublicKey)
	// *point = btcec.PublicKey(*b)
	// ephemeralKey := (*btcec.PublicKey)(b)
	// return tlv.MakeStaticRecord(
	// 	// NOTE: Assumes we use compressed serialization.
	// 	BlindingPointRecordType, ephemeralKey, 33, tlv.EPubKey, blindingPointDecoder,
	// )
	return tlv.MakeStaticRecord(
		// NOTE: Assumes we use compressed serialization?
		BlindingPointRecordType, b, 33, blindingPointEncoder, blindingPointDecoder,
	)
	// return tlv.MakePrimitiveRecord(BlindingPointRecordType, &b)
}

// blindingPointEncoder is a custom TLV encoder for the BlindingPoint record.
func blindingPointEncoder(w io.Writer, val interface{}, buf *[8]byte) error {
	if v, ok := val.(*BlindingPoint); ok {
		// fmt.Printf("[blindingPointEncoder()]: encoding blinding point %+v\n", v)
		// 1. Encode: write bytes into buffer.
		// NOTE: Convert to type expected by tlv library if necessary.
		// Convert from *BlindingPoint to **btcec.PublicKey?
		// so that we can use tlv.EPubKey()?
		key := new(btcec.PublicKey)
		*key = btcec.PublicKey(*v)
		// fmt.Printf("[blindingPointEncoder()]: after converting to public key %+v\n", key.SerializeCompressed())
		if err := tlv.EPubKey(w, &key, buf); err != nil {
			return err
		}

		return nil
	}

	return tlv.NewTypeForEncodingErr(val, "lnwire.BlindingPoint")
}

// blindingPointDecoder is a custom TLV decoder for the BlindingPoint record.
func blindingPointDecoder(r io.Reader, val interface{}, buf *[8]byte, l uint64) error {
	if v, ok := val.(*BlindingPoint); ok {

		// 1. Decode: read bytes into internally defined variable.
		// Convert from *BlindingPoint to **btcec.PublicKey so
		// that we can use tlv.DPubKey()?
		var blindingPoint *btcec.PublicKey

		if err := tlv.DPubKey(r, &blindingPoint, buf, l); err != nil {
			return err
		}
		// fmt.Printf("[blindingPointDecoder()]: decoded blinding point %+v\n", blindingPoint.SerializeCompressed())

		// 2. Convert internal variable to desired custom type.
		*v = BlindingPoint(*blindingPoint)
		// fmt.Printf("[blindingPointDecoder()]: after converting back to blinding point %+v\n", v)

		return nil
	}

	return tlv.NewTypeForDecodingErr(val, "lnwire.BlindingPoint", l, 33)
}
