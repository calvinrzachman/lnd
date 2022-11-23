package lnwire

const (
// // BlindedHopRecordType is the type of the experimental record used
// // to denote which channel type is being negotiated.
// BlindedHopRecordType tlv.Type = 1

// NOTE(7/18/22): Each lnwire.Message has its own extra TLV data
// and TLVs which we  might expect to see there. Should each message
// have its own TLV namespace (ie: type ID #s can be reused)?
// The below tlv.Type matches that used by ChannelType.
// As long as the two TLV records are not expected on the same wire
// message this is fine. With each TLV record getting its own file
// there is nothing which maps the record to the wire message
// it is expected on except develop knowledge (could this be made any different?)
// BlindingPointRecordType tlv.Type = 1
)

// // BlindedHop represents a specific channel type as a set of feature bits that
// // comprise it.
// type BlindedHop struct {
// 	BlindingPoint          *btcec.PublicKey
// 	RecipientEncryptedData []byte
// }

// type BlindingPoint btcec.PublicKey

// // Record returns a TLV record that can be used to encode/decode the channel
// // type from a given TLV stream.
// func (b *BlindingPoint) Record() tlv.Record {
// 	return tlv.MakePrimitiveRecord(BlindingPointRecordType, &b)
// }

// // Record returns a TLV record that can be used to encode/decode the channel
// // type from a given TLV stream.
// func (b *BlindedHop) Record() tlv.Record {
// 	return tlv.MakeDynamicRecord(
// 		BlindedHopRecordType, b, b.Length,
// 		blindedHopTypeEncoder, blindedHopDecoder,
// 	)
// 	// return tlv.MakePrimitiveRecord(BlindedHopRecordType, nil)
// }

// // featureBitLen returns the length in bytes of the encoded feature bits.
// func (b BlindedHop) Length() uint64 {
// 	return uint64(len(b.RecipientEncryptedData) + len(b.BlindingPoint.SerializeCompressed()))
// }

// // blindedHopEncoder is a custom TLV encoder for the BlindedHop record.
// func blindedHopTypeEncoder(w io.Writer, val interface{}, buf *[8]byte) error {
// 	if v, ok := val.(*BlindedHop); ok {
// 		// blindingPoint := v.BlindingPoint.SerializeCompressed()
// 		// _, err := w.Write(blindingPoint)
// 		// _, err = w.Write(v.RecipientEncryptedData)
// 		if err := tlv.EPubKey(w, v.BlindingPoint, buf); err != nil {
// 			return err
// 		}

// 		if err := tlv.EVarBytes(w, &v.RecipientEncryptedData, buf); err != nil {
// 			return err
// 		}

// 		return nil
// 	}

// 	return tlv.NewTypeForEncodingErr(val, "lnwire.BlindedHop")
// }

// // blindedHopDecoder is a custom TLV decoder for the Blinded record.
// func blindedHopDecoder(r io.Reader, val interface{}, buf *[8]byte, l uint64) error {
// 	if v, ok := val.(*BlindedHop); ok {
// 		// v.BlindingPoint :=
// 		if err := tlv.DVarBytes(r, &v.RecipientEncryptedData, buf, l); err != nil {
// 			return err
// 		}

// 		if err := tlv.DPubKey(r, &v.BlindingPoint, buf, l); err != nil {
// 			return err
// 		}

// 		return nil
// 	}

// 	return tlv.NewTypeForEncodingErr(val, "lnwire.BlindedHop")
// }
