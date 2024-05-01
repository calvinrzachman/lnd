//go:build switchrpc
// +build switchrpc

package switchrpc

import (
	"github.com/lightningnetwork/lnd/htlcswitch"
	"github.com/lightningnetwork/lnd/macaroons"
	"github.com/lightningnetwork/lnd/routing"
)

// Config is the primary configuration struct for the switch RPC subserver.
// It contains all the items required for the server to carry out its duties.
// The fields with struct tags are meant to be parsed as normal configuration
// options, while if able to be populated, the latter fields MUST also be
// specified.
type Config struct {
	// Switch...
	Switch *htlcswitch.Switch

	// SwitchMacPath is the path for the router macaroon. If unspecified
	// then we assume that the macaroon will be found under the network
	// directory, named DefaultRouterMacFilename.
	SwitchMacPath string `long:"routermacaroonpath" description:"Path to the router macaroon"`

	// NetworkDir is the main network directory wherein the router rpc
	// server will find the macaroon named DefaultRouterMacFilename.
	NetworkDir string

	// MacService is the main macaroon service that we'll use to handle
	// authentication for the Router rpc server.
	MacService *macaroons.Service

	// HtlcDispatcher provides the means by which payment attempts can
	// be dispatched.
	HtlcDispatcher routing.PaymentAttemptDispatcher

	ChannelInfoAccessor ChannelInfoAccessor
}
