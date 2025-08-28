package routing

import "github.com/lightningnetwork/lnd/lnwire"

// KnownLiquidity is a struct that holds the available bandwidth of a channel
// and a boolean indicating whether the liquidity is known.
type KnownLiquidity struct {
	// Amount is the available bandwidth of the channel.
	Amount lnwire.MilliSatoshi

	// IsKnown is true if the liquidity is known.
	IsKnown bool
}

// LiquiditySource is an interface that can be used to obtain the available
// bandwidth of a channel.
type LiquiditySource interface {
	// GetAvailableBandwidth returns the available bandwidth of the channel
	// with the given short channel ID. The amount parameter is used to
	// validate the outgoing htlc amount that we wish to add to the channel
	// against its flow restrictions.
	GetAvailableBandwidth(scid lnwire.ShortChannelID,
		amount lnwire.MilliSatoshi) KnownLiquidity
}