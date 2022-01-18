package lncfg

import "fmt"

// WtClient holds the configuration options for the daemon's watchtower client.
type WtClient struct {
	// Active determines whether a watchtower client should be created to
	// back up channel states with registered watchtowers.
	Active bool `long:"active" description:"Whether the daemon should use private watchtowers to back up revoked channel states."`

	// PrivateTowerURIs specifies the lightning URIs of the towers the
	// watchtower client should send new backups to.
	PrivateTowerURIs []string `long:"private-tower-uris" description:"(Deprecated) Specifies the URIs of private watchtowers to use in backing up revoked states. URIs must be of the form <pubkey>@<addr>. Only 1 URI is supported at this time, if none are provided the tower will not be enabled."`

	// SweepFeeRate specifies the fee rate in sat/byte to be used when
	// constructing justice transactions sent to the tower.
	SweepFeeRate uint64 `long:"sweep-fee-rate" description:"Specifies the fee rate in sat/byte to be used when constructing justice transactions sent to the watchtower."`

	// EnableReward allows the watchtower client to negotiate sessions with reward towers.
	EnableReward bool `long:"enablereward" description:"Allow watchtower client to negotiate sessions with reward towers."`

	// RewardBase specifies the maximum accepted flat fee the tower
	// client will pay any given tower.
	RewardBase uint32 `long:"rewardbase" description:"Maximum flat fee paid to tower for justice transaction broadcast (in satoshis)."`

	// RewardRate specifies the maximum accepted proportional fee the tower
	// client will pay any given tower for justice broadcasts.
	RewardRate uint32 `long:"rewardrate" description:"Maximum portion of justice transaction paid to tower as reward."`

	// NOTE: Could consolidate the above to a single parameter which specifies the maximum total reward burden
	// the tower client will accept in session negotiation. This would likely need to be specified in % of output
	// terms (like total tax burden/effective tax rate) and would include base + proportional fee taken by the tower.
	// MaxReward uint32 `long:"maxreward" description:"Maximum effective reward rate paid to tower for justice transaction broadcast (in % of channel)"`
}

// Validate ensures the user has provided a valid configuration.
//
// NOTE: Part of the Validator interface.
func (c *WtClient) Validate() error {
	// TODO(wilmer): remove in v0.9.0 release.
	if len(c.PrivateTowerURIs) > 0 {
		return fmt.Errorf("the `wtclient.private-tower-uris` option " +
			"has been deprecated as of v0.8.0-beta and will be " +
			"removed in v0.9.0-beta. To setup watchtowers for " +
			"the client, set `wtclient.active` and run " +
			"`lncli wtclient -h` for more information")
	}

	return nil
}

// Compile-time constraint to ensure WtClient implements the Validator
// interface.
var _ Validator = (*WtClient)(nil)
