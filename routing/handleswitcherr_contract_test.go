package routing

import (
	"errors"
	"testing"
	"time"

	"github.com/lightningnetwork/lnd/htlcswitch"
	"github.com/lightningnetwork/lnd/lnwire"
	paymentsdb "github.com/lightningnetwork/lnd/payments/db"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// disposition is the safety-relevant outcome of handleSwitchErr.
type disposition int

const (
	// dispFailAttempt fails only the attempt; the payment continues.
	dispFailAttempt disposition = iota

	// dispFailPayment fails the whole payment.
	dispFailPayment
)

// TestHandleSwitchErrContract pins how handleSwitchErr treats a SendHTLC error.
// A ClearTextError means nothing was committed, so it goes to mission control,
// which decides whether only the attempt or the whole payment fails. Any other
// error fails the payment. The switchrpc server classifies dispatch errors with
// the same predicate, so a change to one should be reflected in the other.
func TestHandleSwitchErrContract(t *testing.T) {
	t.Parallel()

	escalate := paymentsdb.FailureReasonError

	// A ClearTextError carrying a decodable, update-free wire failure (so
	// handleFailureMessage is a no-op and never touches the graph).
	clearText := htlcswitch.NewLinkError(
		lnwire.NewTemporaryChannelFailure(nil),
	)

	cases := []struct {
		name string
		err  error

		// isClearText marks the cases that go to mission control.
		isClearText bool

		// mcReason is what mission control returns for those cases:
		// nil fails only the attempt, non-nil fails the payment.
		mcReason *paymentsdb.FailureReason

		want disposition
	}{
		// A wire failure mission control deems retryable fails only
		// the attempt.
		{
			name:        "cleartext_mc_retry",
			err:         clearText,
			isClearText: true,
			mcReason:    nil,
			want:        dispFailAttempt,
		},
		// The same wire failure, escalated to the whole payment.
		{
			name:        "cleartext_mc_escalates",
			err:         clearText,
			isClearText: true,
			mcReason:    &escalate,
			want:        dispFailPayment,
		},
		// A not-checkpointed attempt: safe to fail the attempt only.
		{
			name: "payment_id_not_found",
			err:  htlcswitch.ErrPaymentIDNotFound,
			want: dispFailAttempt,
		},
		// Non-ClearTextErrors funnel to failPaymentAndAttempt.
		{
			name: "switch_exiting",
			err:  htlcswitch.ErrSwitchExiting,
			want: dispFailPayment,
		},
		{
			name: "ambiguous_init",
			err:  htlcswitch.ErrAmbiguousAttemptInit,
			want: dispFailPayment,
		},
		{
			name: "generic_internal",
			err:  errors.New("boom"),
			want: dispFailPayment,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p, m := newTestPaymentLifecycle(t)
			attempt := makeFailedAttempt(t, 10_000)

			// Every disposition ends by failing the attempt.
			m.clock.On("Now").Return(time.Now())
			m.shardTracker.On(
				"CancelShard", attempt.AttemptID,
			).Return(nil).Once()
			m.control.On("FailAttempt",
				p.identifier, attempt.AttemptID, mock.Anything,
			).Return(attempt, nil).Once()

			// A ClearTextError goes to mission control, which
			// decides between the attempt and the payment.
			if tc.isClearText {
				call := m.missionControl.On("ReportPaymentFail",
					attempt.AttemptID, &attempt.Route,
					mock.Anything, mock.Anything,
				)
				if tc.mcReason == nil {
					call.Return(nil, nil).Once()
				} else {
					call.Return(tc.mcReason, nil).Once()
				}
			}

			// The whole-payment funnel additionally fails the
			// payment (and must run before the attempt is failed).
			if tc.want == dispFailPayment {
				m.control.On("FailPayment",
					p.identifier, mock.Anything,
				).Return(nil).Once()
			}

			res, err := p.handleSwitchErr(
				t.Context(), attempt, tc.err,
			)
			require.NoError(t, err)
			require.NotNil(t, res)

			// The mocks already enforce the disposition; assert it
			// explicitly as well.
			switch tc.want {
			case dispFailAttempt:
				m.control.AssertNotCalled(t, "FailPayment",
					p.identifier, mock.Anything)

			case dispFailPayment:
				m.control.AssertCalled(t, "FailPayment",
					p.identifier, mock.Anything)
			}
		})
	}
}
