package routing

import (
	"testing"

	"github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
)

// TestBandwidthManager tests getting of bandwidth hints from a bandwidth
// manager.
func TestBandwidthManager(t *testing.T) {
	var (
		chan1ID = lnwire.NewShortChanIDFromInt(101)
		chan2ID = lnwire.NewShortChanIDFromInt(102)
	)

	testCases := []struct {
		name              string
		channelID         lnwire.ShortChannelID
		liquiditySource   LiquiditySource
		expectedBandwidth lnwire.MilliSatoshi
		expectFound       bool
	}{
		{
			name:      "channel not known",
			channelID: chan2ID,
			liquiditySource: &mockLiquiditySource{
				channelLiquidity: map[lnwire.ShortChannelID]KnownLiquidity{
					chan1ID: {
						IsKnown: true,
					},
				},
			},
			expectedBandwidth: 0,
			expectFound:       false,
		},
		{
			name:      "channel known, no bandwidth",
			channelID: chan1ID,
			liquiditySource: &mockLiquiditySource{
				channelLiquidity: map[lnwire.ShortChannelID]KnownLiquidity{
					chan1ID: {
						IsKnown: true,
						Amount:  0,
					},
				},
			},
			expectedBandwidth: 0,
			expectFound:       true,
		},
		{
			name:      "channel known, bandwidth available",
			channelID: chan1ID,
			liquiditySource: &mockLiquiditySource{
				channelLiquidity: map[lnwire.ShortChannelID]KnownLiquidity{
					chan1ID: {
						IsKnown: true,
						Amount:  321,
					},
				},
			},
			expectedBandwidth: 321,
			expectFound:       true,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			m := newBandwidthManager(
				testCase.liquiditySource,
				fn.None[tlv.Blob](),
			)

			bandwidth, found := m.availableChanBandwidth(
				testCase.channelID.ToUint64(), 10,
			)
			require.Equal(t, testCase.expectedBandwidth, bandwidth)
			require.Equal(t, testCase.expectFound, found)
		})
	}
}

type mockTrafficShaper struct{}

// ShouldHandleTraffic is called in order to check if the channel identified
// by the provided channel ID may have external mechanisms that would
// allow it to carry out the payment.
func (*mockTrafficShaper) ShouldHandleTraffic(_ lnwire.ShortChannelID,
	_, _ fn.Option[tlv.Blob]) (bool, error) {

	return true, nil
}

// PaymentBandwidth returns the available bandwidth for a custom channel decided
// by the given channel funding/commitment aux blob and HTLC blob. A return
// value of 0 means there is no bandwidth available. To find out if a channel is
// a custom channel that should be handled by the traffic shaper, the
// ShouldHandleTraffic method should be called first.
func (*mockTrafficShaper) PaymentBandwidth(_, _, _ fn.Option[tlv.Blob],
	linkBandwidth, _ lnwire.MilliSatoshi,
	_ lnwallet.AuxHtlcView, _ route.Vertex) (lnwire.MilliSatoshi, error) {

	return linkBandwidth, nil
}

// ProduceHtlcExtraData is a function that, based on the previous extra
// data blob of an HTLC, may produce a different blob or modify the
// amount of bitcoin this htlc should carry.
func (*mockTrafficShaper) ProduceHtlcExtraData(totalAmount lnwire.MilliSatoshi,
	_ lnwire.CustomRecords, _ route.Vertex) (lnwire.MilliSatoshi,
	lnwire.CustomRecords, error) {

	return totalAmount, nil, nil
}

func (*mockTrafficShaper) IsCustomHTLC(_ lnwire.CustomRecords) bool {
	return false
}
