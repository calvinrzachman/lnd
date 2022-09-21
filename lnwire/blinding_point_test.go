package lnwire

import (
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

// TestRouteBlindingPointEncodeDecode tests that we're able to properly
// encode and decode channel types within TLV streams.
func TestRouteBlindingPointEncodeDecode(t *testing.T) {
	t.Parallel()

	pubkeyBytes, err := hex.DecodeString("02bedd1e7865e7476f522b02b13f137f418105154312b48c45985dd72cbf47c143")
	pubKey, _ := btcec.ParsePubKey(pubkeyBytes)
	blindingPoint := BlindingPoint(*pubKey)

	var extraData ExtraOpaqueData
	require.NoError(t, extraData.PackRecords(&blindingPoint))

	var blindingPoint2 BlindingPoint
	tlvs, err := extraData.ExtractRecords(&blindingPoint2)
	require.NoError(t, err)

	require.Contains(t, tlvs, BlindingPointRecordType)
	require.Equal(t, blindingPoint, blindingPoint2)
}
