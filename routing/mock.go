package routing

import (
	"github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/tlv"
)

// mockLiquiditySource is a mock implementation of the LiquiditySource
// interface that can be used in tests. It can be configured to return
// specific liquidity information for different channels.
type mockLiquiditySource struct {
	// channelLiquidity maps a short channel ID to the desired liquidity
	// information that should be returned for it.
	channelLiquidity map[lnwire.ShortChannelID]KnownLiquidity
}

// GetAvailableBandwidth returns the available bandwidth of a channel. If a
// specific liquidity is configured for the given channel ID, it is returned.
// Otherwise, it returns a zero-value KnownLiquidity struct, indicating
// unknown liquidity.
func (m *mockLiquiditySource) GetAvailableBandwidth(scid lnwire.ShortChannelID,
	_ lnwire.MilliSatoshi) KnownLiquidity {

	// Look for a specific liquidity value for this channel ID in our map.
	liquidity, ok := m.channelLiquidity[scid]
	if ok {
		return liquidity
	}

	// If no specific value is found, return that the liquidity is unknown.
	return KnownLiquidity{
		IsKnown: false,
	}
}

// mockBandwidthHints is a mock implementation of the bandwidthHints interface.
type mockBandwidthHints struct {
	// hints is a map from channel ID to available bandwidth. If an entry
	// is missing, the channel is assumed to have sufficient bandwidth.
	hints map[uint64]lnwire.MilliSatoshi

	// knownHints is a map from channel ID to available bandwidth for which
	// the liquidity source is known.
	knownHints map[uint64]lnwire.MilliSatoshi
}

// availableChanBandwidth returns the available bandwidth for the given channel.
func (m *mockBandwidthHints) availableChanBandwidth(chanID uint64,
	_ lnwire.MilliSatoshi) (lnwire.MilliSatoshi, bool) {

	if m.knownHints != nil {
		if bandwidth, ok := m.knownHints[chanID]; ok {
			return bandwidth, true
		}
	}

	if m.hints == nil {
		return lnwire.MaxMilliSatoshi, false
	}

	bandwidth, ok := m.hints[chanID]
	if !ok {
		return lnwire.MaxMilliSatoshi, false
	}

	return bandwidth, false
}

func (m *mockBandwidthHints) firstHopCustomBlob() fn.Option[tlv.Blob] {
	return fn.None[tlv.Blob]()
}
