package wtpolicy_test

import (
	"testing"

	"github.com/lightningnetwork/lnd/watchtower/blob"
	"github.com/lightningnetwork/lnd/watchtower/wtpolicy"
	"github.com/stretchr/testify/require"
)

var validationTests = []struct {
	name   string
	policy wtpolicy.Policy
	expErr error
}{
	{
		name: "fail no maxupdates",
		policy: wtpolicy.Policy{
			TxPolicy: wtpolicy.TxPolicy{
				BlobType: blob.TypeAltruistCommit,
			},
		},
		expErr: wtpolicy.ErrNoMaxUpdates,
	},
	{
		name: "fail altruist with reward base",
		policy: wtpolicy.Policy{
			TxPolicy: wtpolicy.TxPolicy{
				BlobType:   blob.TypeAltruistCommit,
				RewardBase: 1,
			},
		},
		expErr: wtpolicy.ErrAltruistReward,
	},
	{
		name: "fail altruist with reward rate",
		policy: wtpolicy.Policy{
			TxPolicy: wtpolicy.TxPolicy{
				BlobType:   blob.TypeAltruistCommit,
				RewardRate: 1,
			},
		},
		expErr: wtpolicy.ErrAltruistReward,
	},
	{
		name: "fail sweep fee rate too low",
		policy: wtpolicy.Policy{
			TxPolicy: wtpolicy.TxPolicy{
				BlobType: blob.TypeAltruistCommit,
			},
			MaxUpdates: 1,
		},
		expErr: wtpolicy.ErrSweepFeeRateTooLow,
	},
	{
		name: "minimal valid altruist policy",
		policy: wtpolicy.Policy{
			TxPolicy: wtpolicy.TxPolicy{
				BlobType:     blob.TypeAltruistCommit,
				SweepFeeRate: wtpolicy.MinSweepFeeRate,
			},
			MaxUpdates: 1,
		},
	},
	{
		name: "valid altruist policy with default sweep rate",
		policy: wtpolicy.Policy{
			TxPolicy: wtpolicy.TxPolicy{
				BlobType:     blob.TypeAltruistCommit,
				SweepFeeRate: wtpolicy.DefaultSweepFeeRate,
			},
			MaxUpdates: 1,
		},
	},
	{
		name:   "valid default policy",
		policy: wtpolicy.DefaultAltruistPolicy(),
	},
	{
		name: "valid reward policy",
		policy: wtpolicy.Policy{
			TxPolicy: wtpolicy.TxPolicy{
				BlobType:     blob.TypeRewardCommit,
				SweepFeeRate: wtpolicy.MinSweepFeeRate,
				RewardBase:   wtpolicy.DefaultRewardBase,
				RewardRate:   wtpolicy.DefaultRewardRate,
			},
			MaxUpdates: 1,
		},
	},
	{
		name: "fail reward with invalid reward rate",
		policy: wtpolicy.Policy{
			TxPolicy: wtpolicy.TxPolicy{
				BlobType:     blob.TypeRewardCommit,
				SweepFeeRate: wtpolicy.MinSweepFeeRate,
				RewardRate:   wtpolicy.RewardScale + 1,
			},
			MaxUpdates: 1,
		},
		expErr: wtpolicy.ErrRewardRateTooHigh,
	},
}

// TestPolicyValidate asserts that the sanity checks for policies behave as
// expected.
func TestPolicyValidate(t *testing.T) {
	for i := range validationTests {
		test := validationTests[i]
		t.Run(test.name, func(t *testing.T) {
			err := test.policy.Validate()
			if err != test.expErr {
				t.Fatalf("validation error mismatch, "+
					"want: %v, got: %v", test.expErr, err)
			}
		})
	}
}

// TestPolicyIsAnchorChannel asserts that the IsAnchorChannel helper properly
// reflects the anchor bit of the policy's blob type.
func TestPolicyIsAnchorChannel(t *testing.T) {
	policyNoAnchor := wtpolicy.Policy{
		TxPolicy: wtpolicy.TxPolicy{
			BlobType: blob.TypeAltruistCommit,
		},
	}
	require.Equal(t, false, policyNoAnchor.IsAnchorChannel())

	policyAnchor := wtpolicy.Policy{
		TxPolicy: wtpolicy.TxPolicy{
			BlobType: blob.TypeAltruistAnchorCommit,
		},
	}
	require.Equal(t, true, policyAnchor.IsAnchorChannel())
}

// NOTE: You could imagine a scenario in which clients and severs
// haggle/negotiate to find mutually acceptable session terms.
// - Right now the client picks some session parameters and trys to establish a session
// - If the server rejects the session parameters it doesn't really say why (fixing this)
//   and it certainly does not specify its entire policy so that the client may adapt.
//   IDEA: flesh out the session negotiation to allow the server to communicate its policy
//   to clients. In this instance, both client and tower could use a validator to determine whether
//   the policy they receive matches their configuration.

// Clients set maximums. Towers set minimums.
// A client's maximum fee must be set at least as high as (>=) a tower's minimum fee.
// In the absence of true negotiation/server policy reveal the amount past which a client exceeds
// a servers minimum is paid to the server. If the client knew this "distance" between his offer
// and what the server would minimally accept, he could get a better deal. Should server's be nice
// and offer his policy or simply charge clients exactly what he is configured? Don't give preferential
// treatment to clients over servers.

// In practice established towers will advertise their rates so as to compete for service against
// other tower services. Clients will know the tower rates and will offer exactly the rate. Clients
// will only be interested in knowing that servers are not silently adjusting rates upward. Perhaps
// reputation is sufficient to guard against this, but the role of session policy could simply be to alert
// client's as to when this happens.

// QUESTION: Say you run a tower client with a configured maximum reward offered to towers. Now say your only
// connected tower increases it's reward rate. What should LND do? Not back up payment channel states because it
// cannot find a tower offering a low enough rate? Yes I think so. How will a user be notified of this so they can
// go configure a higher reward in their client policy? Maybe they will need to monitor logs for a message which indicates
// this and send an alert so they can manually intervene.

var serverSessionPolicyValidationTests = []struct {
	name         string
	clientPolicy wtpolicy.Policy
	// in order for a given test to be self contained this information
	// should be present.
	towerPolicy wtpolicy.Policy
	expErr      error
}{
	{
		name: "reward base too low",
		clientPolicy: wtpolicy.Policy{
			TxPolicy: wtpolicy.TxPolicy{
				BlobType: blob.TypeRewardCommit,
			},
		},
		expErr: wtpolicy.ErrRewardBaseTooLow,
	},
}

// TestPolicyValidator asserts that the sanity checks for policies behave as
// expected.
func TestPolicyValidator(t *testing.T) {
	for i := range serverSessionPolicyValidationTests {
		test := validationTests[i]
		t.Run(test.name, func(t *testing.T) {
			err := test.policy.Validate()
			if err != test.expErr {
				t.Fatalf("validation error mismatch, "+
					"want: %v, got: %v", test.expErr, err)
			}
		})
	}
}
