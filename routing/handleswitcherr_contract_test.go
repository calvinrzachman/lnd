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

// This test pins the routing-layer half of the SwitchRPC fund-safety contract:
// how paymentLifecycle.handleSwitchErr classifies switch errors into
// attempt-level failures (the payment continues) vs whole-payment failures (the
// "Path-C" funnel that, over the wire, becomes a caller-visible terminal
// failure and hence the cross-payment double-pay risk).
//
// The load-bearing invariant, and the lockstep with lnrpc/switchrpc: both
// handleSwitchErr and switchrpc's marshallDispatchFailure branch on
// errors.As(err, &htlcswitch.ClearTextError). handleSwitchErr routes a
// ClearTextError through Mission Control (attempt-level unless MC escalates the
// whole payment), and routes every NON-ClearTextError straight to
// failPaymentAndAttempt. marshallDispatchFailure maps a ClearTextError to a
// definitive gRPC code and everything else to an indefinite one. If either
// side's partition drifts, PS can be handed a definitive code for an HTLC that
// reached the wire. This test is the change-detector on the routing side;
// TestMarshallDispatchFailure (lnrpc/switchrpc) is its twin. Keep them in
// lockstep: a change here that reclassifies an error type should be mirrored
// there, and vice versa.

// disposition is the safety-relevant outcome of handleSwitchErr.
type disposition int

const (
	// dispFailAttempt fails only the attempt; the payment continues.
	dispFailAttempt disposition = iota

	// dispFailPayment fails the whole payment (the Path-C funnel).
	dispFailPayment
)

// TestHandleSwitchErrContract asserts the error-type -> disposition mapping
// that PS relies on and that switchrpc's code mapping must mirror.
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

		// isClearText documents the predicate both consumers branch on;
		// a ClearTextError is reported to Mission Control.
		isClearText bool

		// mcReason is what mock Mission Control returns for the
		// ClearTextError cases: nil => fail only the attempt, non-nil =>
		// escalate to a payment failure. Non-ClearTextError errors never
		// reach MC.
		mcReason *paymentsdb.FailureReason

		want disposition
	}{
		// A decodable wire failure that MC decides is retryable stays at
		// the attempt level.
		{
			name:        "cleartext_mc_retry",
			err:         clearText,
			isClearText: true,
			mcReason:    nil,
			want:        dispFailAttempt,
		},
		// The same wire failure, but MC escalates the whole payment.
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

			// A ClearTextError is reported to Mission Control, which
			// decides attempt-vs-payment.
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

			// The mock set-up encodes the disposition and t.Cleanup's
			// AssertExpectations enforces it; assert it explicitly too.
			switch tc.want {
			case dispFailAttempt:
				m.control.AssertNotCalled(t, "FailPayment")

			case dispFailPayment:
				m.control.AssertCalled(t, "FailPayment",
					p.identifier, mock.Anything)
			}
		})
	}
}
