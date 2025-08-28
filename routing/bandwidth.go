package routing

import (
	"github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/tlv"
)

// bandwidthHints provides hints about the currently available balance in our
// channels.
type bandwidthHints interface {
	// availableChanBandwidth returns the total available bandwidth for a
	// channel and a bool indicating whether the channel hint was found.
	// The amount parameter is used to validate the outgoing htlc amount
	// that we wish to add to the channel against its flow restrictions. If
	// a zero amount is provided, the minimum htlc value for the channel
	// will be used. If the channel is unavailable, a zero amount is
	// returned.
	availableChanBandwidth(channelID uint64,
		amount lnwire.MilliSatoshi) (lnwire.MilliSatoshi, bool)

	// firstHopCustomBlob returns the custom blob for the first hop of the
	// payment, if available.
	firstHopCustomBlob() fn.Option[tlv.Blob]
}

// bandwidthManager is an implementation of the bandwidthHints interface which
// uses a LiquiditySource to query for our latest local channel balances.
type bandwidthManager struct {
	liquiditySource LiquiditySource
	firstHopBlob    fn.Option[tlv.Blob]
}

// newBandwidthManager creates a bandwidth manager which is used to obtain
// hints from the lower layer w.r.t the available bandwidth of edges on the
// network.
func newBandwidthManager(liquiditySource LiquiditySource,
	firstHopBlob fn.Option[tlv.Blob]) *bandwidthManager {

	return &bandwidthManager{
		liquiditySource: liquiditySource,
		firstHopBlob:    firstHopBlob,
	}
}

// availableChanBandwidth returns the total available bandwidth for a channel
// and a bool indicating whether the channel hint was found. If the channel is
// unavailable, a zero amount is returned.
func (b *bandwidthManager) availableChanBandwidth(channelID uint64,
	amount lnwire.MilliSatoshi) (lnwire.MilliSatoshi, bool) {

	shortID := lnwire.NewShortChanIDFromInt(channelID)
	liquidity := b.liquiditySource.GetAvailableBandwidth(shortID, amount)

	return liquidity.Amount, liquidity.IsKnown
}

// firstHopCustomBlob returns the custom blob for the first hop of the payment,
// if available.
func (b *bandwidthManager) firstHopCustomBlob() fn.Option[tlv.Blob] {
	return b.firstHopBlob
}
