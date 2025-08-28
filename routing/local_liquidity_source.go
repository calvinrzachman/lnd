package routing

import (
	"fmt"

	"github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/htlcswitch"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/lightningnetwork/lnd/tlv"
)

// getLinkQuery is the function signature used to lookup a link.
type getLinkQuery func(lnwire.ShortChannelID) (
	htlcswitch.ChannelLink, error)

// LocalSwitchLiquiditySource is an implementation of the LiquiditySource
// interface that uses the local htlcswitch to obtain channel liquidity
// information.
type LocalSwitchLiquiditySource struct {
	getLink       getLinkQuery
	selfNode      route.Vertex
	trafficShaper fn.Option[htlcswitch.AuxTrafficShaper]
	firstHopBlob  fn.Option[tlv.Blob]
}

// NewLocalSwitchLiquiditySource creates a new LocalSwitchLiquiditySource.
func NewLocalSwitchLiquiditySource(getLink getLinkQuery,
	selfNode route.Vertex, ts fn.Option[htlcswitch.AuxTrafficShaper],
	firstHopBlob fn.Option[tlv.Blob]) *LocalSwitchLiquiditySource {

	return &LocalSwitchLiquiditySource{
		getLink:       getLink,
		selfNode:      selfNode,
		trafficShaper: ts,
		firstHopBlob:  firstHopBlob,
	}
}

// A compile-time check to ensure that LocalSwitchLiquiditySource implements the
// LiquiditySource interface.
var _ LiquiditySource = (*LocalSwitchLiquiditySource)(nil)

// getBandwidth queries the current state of a link and gets its currently
// available bandwidth. Note that this function assumes that the channel being
// queried is one of our local channels, so any failure to retrieve the link
// is interpreted as the link being offline.
func (s *LocalSwitchLiquiditySource) getBandwidth(cid lnwire.ShortChannelID,
	amount lnwire.MilliSatoshi) (lnwire.MilliSatoshi, error) {

	link, err := s.getLink(cid)
	if err != nil {
		return 0, fmt.Errorf("error querying switch for link: %w", err)
	}

	// If the link is found within the switch, but it isn't yet eligible
	// to forward any HTLCs, then we'll treat it as if it isn't online in
	// the first place.
	if !link.EligibleToForward() {
		return 0, fmt.Errorf("link not eligible to forward")
	}

	// bandwidthResult is an inline type that we'll use to pass the
	// bandwidth result from the external traffic shaper to the main logic
	// below.
	type bandwidthResult struct {
		// bandwidth is the available bandwidth for the channel as
		// reported by the external traffic shaper. If the external
		// traffic shaper is not handling the channel, this value will
		// be fn.None
		bandwidth fn.Option[lnwire.MilliSatoshi]

		// htlcAmount is the amount we're going to use to check if we
		// can add another HTLC to the channel. If the external traffic
		// shaper is handling the channel, we'll use 0 to just sanity
		// check the number of HTLCs on the channel, since we don't know
		// the actual HTLC amount that will be sent.
		htlcAmount fn.Option[lnwire.MilliSatoshi]
	}

	var (
		// We will pass the link bandwidth to the external traffic
		// shaper. This is the current best estimate for the available
		// bandwidth for the link.
		linkBandwidth = link.Bandwidth()

		bandwidthErr = func(err error) fn.Result[bandwidthResult] {
			return fn.Err[bandwidthResult](err)
		}
	)

	result, err := fn.MapOptionZ(
		s.trafficShaper,
		func(shaper htlcswitch.AuxTrafficShaper) fn.Result[bandwidthResult] {
			auxBandwidth, err := link.AuxBandwidth(
				amount, cid, s.firstHopBlob, shaper,
			).Unpack()
			if err != nil {
				return bandwidthErr(fmt.Errorf("failed to get "+
					"auxiliary bandwidth: %w", err))
			}

			// If the external traffic shaper is not handling the
			// channel, we'll just return the original bandwidth and
			// no custom amount.
			if !auxBandwidth.IsHandled {
				return fn.Ok(bandwidthResult{})
			}

			// We don't know the actual HTLC amount that will be
			// sent using the custom channel. But we'll still want
			// to make sure we can add another HTLC, using the
			// MayAddOutgoingHtlc method below. Passing 0 into that
			// method will use the minimum HTLC value for the
			// channel, which is okay to just check we don't exceed
			// the max number of HTLCs on the channel. A proper
			// balance check is done elsewhere.
			return fn.Ok(bandwidthResult{
				bandwidth:  auxBandwidth.Bandwidth,
				htlcAmount: fn.Some[lnwire.MilliSatoshi](0),
			})
		},
	).Unpack()
	if err != nil {
		return 0, fmt.Errorf("failed to consult external traffic "+
			"shaper: %w", err)
	}

	htlcAmount := result.htlcAmount.UnwrapOr(amount)

	// If our link isn't currently in a state where it can add another
	// outgoing htlc, treat the link as unusable.
	if err := link.MayAddOutgoingHtlc(htlcAmount); err != nil {
		return 0, fmt.Errorf("cannot add outgoing htlc to channel %v "+
			"with amount %v: %w", cid, htlcAmount, err)
	}

	// If the external traffic shaper determined the bandwidth, we'll return
	// that value, even if it is zero (which would mean no bandwidth is
	// available on that channel).
	reportedBandwidth := result.bandwidth.UnwrapOr(linkBandwidth)

	return reportedBandwidth, nil
}

// GetAvailableBandwidth returns the available bandwidth of the channel with the
// given short channel ID.
func (s *LocalSwitchLiquiditySource) GetAvailableBandwidth(
	scid lnwire.ShortChannelID, amount lnwire.MilliSatoshi) KnownLiquidity {

	bandwidth, err := s.getBandwidth(scid, amount)
	if err != nil {
		// If we failed to get the bandwidth, it means the channel is
		// not online or not a local channel, so we don't know the
		// liquidity.
		return KnownLiquidity{
			IsKnown: false,
		}
	}

	return KnownLiquidity{
		Amount:  bandwidth,
		IsKnown: true,
	}
}
