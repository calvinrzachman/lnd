//go:build switchrpc
// +build switchrpc

package switchrpc

import (
	"bytes"
	context "context"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightningnetwork/lnd/htlcswitch"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/stretchr/testify/require"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// TestSendOnion is a unit test that rigorously verifies the behavior of the
// SendOnion RPC handler in isolation. It ensures that the server correctly
// implements its side of the RPC contract by sending the correct signals back
// to the client under various conditions. The test guarantees:
//  1. Correct translation of internal htlcswitch errors (e.g., ErrDuplicateAdd)
//     into the specific error codes defined in the protobuf contract.
//  2. Robust validation of incoming requests, ensuring malformed requests are
//     rejected with the appropriate gRPC status code.
//  3. Correct propagation of success signals when the underlying dispatcher
//     succeeds.
func TestSendOnion(t *testing.T) {
	t.Parallel()

	// Create a valid request that can be used as a template for tests.
	makeValidRequest := func() *SendOnionRequest {
		return &SendOnionRequest{
			OnionBlob:      make([]byte, lnwire.OnionPacketSize),
			PaymentHash:    make([]byte, 32),
			AttemptId:      1,
			Amount:         1000,
			FirstHopChanId: 12345,
		}
	}

	testCases := []struct {
		name string

		// setup is a function that modifies the server or request for a
		// specific test case.
		setup func(*testing.T, *Server, *SendOnionRequest)

		// expectedErrCode is the gRPC error code we expect from the call.
		expectedErrCode codes.Code

		// expectedResponse is the expected response from the RPC call.
		expectedResponse *SendOnionResponse
	}{
		{
			name: "valid request",
			setup: func(t *testing.T, s *Server,
				req *SendOnionRequest) {

				// Mock a successful dispatch.
				s.cfg.HtlcDispatcher.(*mockPayer).sendErr = nil
			},
			expectedResponse: &SendOnionResponse{Success: true},
		},
		{
			name: "missing onion blob",
			setup: func(t *testing.T, s *Server,
				req *SendOnionRequest) {

				req.OnionBlob = nil
			},
			expectedErrCode: codes.InvalidArgument,
		},
		{
			name: "invalid onion blob size",
			setup: func(t *testing.T, s *Server,
				req *SendOnionRequest) {

				req.OnionBlob = make([]byte, 1)
			},
			expectedErrCode: codes.InvalidArgument,
		},
		{
			name: "missing payment hash",
			setup: func(t *testing.T, s *Server,
				req *SendOnionRequest) {

				req.PaymentHash = nil
			},
			expectedErrCode: codes.InvalidArgument,
		},
		{
			name: "zero amount",
			setup: func(t *testing.T, s *Server,
				req *SendOnionRequest) {

				req.Amount = 0
			},
			expectedErrCode: codes.InvalidArgument,
		},
		{
			name: "dispatcher internal error",
			setup: func(t *testing.T, s *Server,
				req *SendOnionRequest) {

				// Mock a generic error from the dispatcher.
				s.cfg.HtlcDispatcher.(*mockPayer).sendErr =
					errors.New("internal error")
			},
			expectedResponse: &SendOnionResponse{
				Success:      false,
				ErrorMessage: "internal error",
				ErrorCode:    ErrorCode_ERROR_CODE_INTERNAL,
			},
		},
		{
			// The ErrDuplicateAdd error is the means by which an
			// rpc client is safe to retry the SendOnion rpc until
			// an explicit acknowledgement of htlc dispatch can be
			// received from the server. The ability to retry and
			// rely on duplicate prevention is useful under
			// scenarios where the status of htlc dispatch is
			// uncertain (eg: network timeout or after restart).
			name: "dispatcher duplicate htlc error",
			setup: func(t *testing.T, s *Server,
				req *SendOnionRequest) {

				// Mock a duplicate error from the dispatcher,
				// which is the new way to signal a duplicate
				// attempt for the same ID.
				s.cfg.HtlcDispatcher.(*mockPayer).sendErr =
					htlcswitch.ErrDuplicateAdd
			},
			expectedResponse: &SendOnionResponse{
				Success:      false,
				ErrorMessage: htlcswitch.ErrDuplicateAdd.Error(),
				ErrorCode:    ErrorCode_ERROR_CODE_DUPLICATE_HTLC,
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Create a new server for each test case to ensure
			// isolation.
			server, _, err := New(&Config{
				HtlcDispatcher: &mockPayer{},
			})
			require.NoError(t, err)

			req := makeValidRequest()

			// Apply the test-specific setup.
			if tc.setup != nil {
				tc.setup(t, server, req)
			}

			resp, err := server.SendOnion(context.Background(), req)

			// Check for gRPC level errors.
			if tc.expectedErrCode != codes.OK {
				require.Error(t, err)
				s, ok := status.FromError(err)
				require.True(t, ok)
				require.Equal(t, tc.expectedErrCode, s.Code())
				return
			}

			// If no gRPC error was expected, check the response.
			require.NoError(t, err)
			require.Equal(t, tc.expectedResponse, resp)
		})
	}
}

// TestTrackOnion is a unit test that rigorously verifies the behavior of the
// TrackOnion RPC handler in isolation.
func TestTrackOnion(t *testing.T) {
	t.Parallel()

	preimage := lntypes.Preimage{1, 2, 3}
	preimageBytes := preimage[:]

	// Create a valid request that can be used as a template for tests.
	makeValidRequest := func() *TrackOnionRequest {
		return &TrackOnionRequest{
			PaymentHash: make([]byte, 32),
			AttemptId:   1,
		}
	}

	testCases := []struct {
		name string

		// setup is a function that modifies the server or request for a
		// specific test case.
		setup func(*testing.T, *mockPayer, *TrackOnionRequest)

		// ctx is the context to use for the RPC call.
		ctx context.Context

		// expectedErrCode is the gRPC error code we expect from the call.
		expectedErrCode codes.Code

		// expectedResponse is the expected response from the RPC call.
		expectedResponse *TrackOnionResponse
	}{
		{
			name: "payment success",
			setup: func(t *testing.T, m *mockPayer,
				req *TrackOnionRequest) {

				m.getResultResult = &htlcswitch.PaymentResult{
					Preimage: preimage,
				}
			},
			ctx: context.Background(),
			expectedResponse: &TrackOnionResponse{
				Preimage: preimageBytes,
			},
		},
		{
			name: "payment failed",
			setup: func(t *testing.T, m *mockPayer,
				req *TrackOnionRequest) {

				m.getResultResult = &htlcswitch.PaymentResult{
					Error: errors.New("test error"),
				}
			},
			ctx: context.Background(),
			expectedResponse: &TrackOnionResponse{
				ErrorMessage: "test error",
				ErrorCode:    ErrorCode_ERROR_CODE_INTERNAL,
			},
		},
		{
			name: "payment not found",
			setup: func(t *testing.T, m *mockPayer,
				req *TrackOnionRequest) {

				m.getResultErr = htlcswitch.ErrPaymentIDNotFound
			},
			ctx: context.Background(),
			expectedResponse: &TrackOnionResponse{
				ErrorMessage: htlcswitch.ErrPaymentIDNotFound.Error(),
				ErrorCode:    ErrorCode_ERROR_CODE_PAYMENT_ID_NOT_FOUND,
			},
		},
		{
			name: "invalid payment hash",
			setup: func(t *testing.T, m *mockPayer,
				req *TrackOnionRequest) {

				req.PaymentHash = []byte{1, 2, 3}
			},
			ctx:             context.Background(),
			expectedErrCode: codes.InvalidArgument,
		},
		{
			name:  "context canceled",
			setup: nil, // No setup needed, mock will block.
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			}(),
			expectedErrCode: codes.Canceled,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mockPayer := &mockPayer{}

			// Create a new server for each test case to ensure
			// isolation.
			server, _, err := New(&Config{
				HtlcDispatcher: mockPayer,
			})
			require.NoError(t, err)

			req := makeValidRequest()

			// Apply the test-specific setup.
			if tc.setup != nil {
				tc.setup(t, mockPayer, req)
			}

			resp, err := server.TrackOnion(tc.ctx, req)

			// Check for gRPC level errors.
			if tc.expectedErrCode != codes.OK {
				require.Error(t, err)
				s, ok := status.FromError(err)
				require.True(t, ok)
				require.Equal(t, tc.expectedErrCode, s.Code())
				return
			}

			// If no gRPC error was expected, check the response.
			require.NoError(t, err)
			require.Equal(t, tc.expectedResponse, resp)
		})
	}
}

// TestBuildOnion is a unit test that verifies the behavior of the BuildOnion
// RPC handler, ensuring that it correctly validates inputs, handles dependency
// failures, and constructs a valid response upon success.
func TestBuildOnion(t *testing.T) {
	t.Parallel()

	// Create a valid session key for the "provided key" test case.
	validSessionKeyBytes := []byte{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
	}

	// Create a mock route to be returned by the processor.
	// We need to generate some mock public keys for the hops.
	privKey1, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	pubKey1 := privKey1.PubKey()

	privKey2, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	pubKey2 := privKey2.PubKey()

	// The mock route needs to have realistic values for amounts,
	// timelocks, and channel IDs, otherwise sphinx packet construction
	// will fail.
	paymentAmt := lnwire.MilliSatoshi(10000)
	finalCltv := uint32(40)

	mockRoute := &route.Route{
		TotalAmount: paymentAmt,
		Hops: []*route.Hop{
			{
				PubKeyBytes:      route.NewVertex(pubKey1),
				AmtToForward:     paymentAmt,
				OutgoingTimeLock: finalCltv + 10,
				ChannelID:        1,
			},
			{
				PubKeyBytes:      route.NewVertex(pubKey2),
				AmtToForward:     paymentAmt,
				OutgoingTimeLock: finalCltv,
				ChannelID:        2,
			},
		},
	}

	testCases := []struct {
		name string

		// setup is a function that modifies the server or request for a
		// specific test case.
		setup func(*testing.T, *mockRouteProcessor, *BuildOnionRequest)

		// expectedErrCode is the gRPC error code we expect.
		expectedErrCode codes.Code

		// checkResponse is a function that validates the response on
		// success.
		checkResponse func(*testing.T, *BuildOnionResponse)
	}{
		{
			name: "success new session key",
			setup: func(t *testing.T, m *mockRouteProcessor,
				req *BuildOnionRequest) {

				m.unmarshallRoute = mockRoute
			},
			checkResponse: func(t *testing.T, resp *BuildOnionResponse) {
				require.Len(t, resp.OnionBlob, lnwire.OnionPacketSize)
				require.Len(t, resp.SessionKey, 32)
				require.Len(t, resp.HopPubkeys, len(mockRoute.Hops))
			},
		},
		{
			name: "success with provided session key",
			setup: func(t *testing.T, m *mockRouteProcessor,
				req *BuildOnionRequest) {

				m.unmarshallRoute = mockRoute
				req.SessionKey = validSessionKeyBytes
			},
			checkResponse: func(t *testing.T, resp *BuildOnionResponse) {
				require.Len(t, resp.OnionBlob, lnwire.OnionPacketSize)
				require.Equal(t, validSessionKeyBytes, resp.SessionKey)
			},
		},
		{
			name: "missing route",
			setup: func(t *testing.T, m *mockRouteProcessor,
				req *BuildOnionRequest) {

				req.Route = nil
			},
			expectedErrCode: codes.InvalidArgument,
		},
		{
			name: "missing payment hash",
			setup: func(t *testing.T, m *mockRouteProcessor,
				req *BuildOnionRequest) {

				req.PaymentHash = nil
			},
			expectedErrCode: codes.InvalidArgument,
		},
		{
			name: "invalid session key",
			setup: func(t *testing.T, m *mockRouteProcessor,
				req *BuildOnionRequest) {

				req.SessionKey = []byte{1, 2, 3}
			},
			expectedErrCode: codes.InvalidArgument,
		},
		{
			name: "route unmarshall fails",
			setup: func(t *testing.T, m *mockRouteProcessor,
				req *BuildOnionRequest) {

				m.unmarshallErr = errors.New("unmarshall error")
			},
			expectedErrCode: codes.InvalidArgument,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mockProcessor := &mockRouteProcessor{}
			server := &Server{
				cfg: &Config{RouteProcessor: mockProcessor},
			}

			req := &BuildOnionRequest{
				Route:       &lnrpc.Route{},
				PaymentHash: make([]byte, 32),
			}

			if tc.setup != nil {
				tc.setup(t, mockProcessor, req)
			}

			resp, err := server.BuildOnion(context.Background(), req)

			if tc.expectedErrCode != codes.OK {
				require.Error(t, err)
				s, ok := status.FromError(err)
				require.True(t, ok)
				require.Equal(t, tc.expectedErrCode, s.Code())
				return
			}

			require.NoError(t, err)
			if tc.checkResponse != nil {
				tc.checkResponse(t, resp)
			}
		})
	}
}

// TestTranslateErrorForRPC tests the TranslateErrorForRPC function.
func TestTranslateErrorForRPC(t *testing.T) {
	t.Parallel()

	failureIndex := 1
	mockWireMsg := lnwire.NewTemporaryChannelFailure(nil)
	mockForwardingErr := htlcswitch.NewForwardingError(mockWireMsg, failureIndex)
	mockClearTextErr := htlcswitch.NewLinkError(mockWireMsg)

	var buf bytes.Buffer
	lnwire.EncodeFailure(&buf, mockWireMsg, 0)
	encodedMsg := hex.EncodeToString(buf.Bytes())

	tests := []struct {
		name         string
		err          error
		expectedMsg  string
		expectedCode ErrorCode
	}{
		{
			name:         "ErrPaymentIDNotFound",
			err:          htlcswitch.ErrPaymentIDNotFound,
			expectedMsg:  htlcswitch.ErrPaymentIDNotFound.Error(),
			expectedCode: ErrorCode_ERROR_CODE_PAYMENT_ID_NOT_FOUND,
		},
		{
			name:         "ErrUnreadableFailureMessage",
			err:          htlcswitch.ErrUnreadableFailureMessage,
			expectedMsg:  htlcswitch.ErrUnreadableFailureMessage.Error(),
			expectedCode: ErrorCode_ERROR_CODE_UNREADABLE_FAILURE_MESSAGE,
		},
		{
			name:         "ErrSwitchExiting",
			err:          htlcswitch.ErrSwitchExiting,
			expectedMsg:  htlcswitch.ErrSwitchExiting.Error(),
			expectedCode: ErrorCode_ERROR_CODE_SWITCH_EXITING,
		},
		{
			name:         "ForwardingError",
			err:          mockForwardingErr,
			expectedMsg:  fmt.Sprintf("%d@%s", failureIndex, encodedMsg),
			expectedCode: ErrorCode_ERROR_CODE_FORWARDING_ERROR,
		},
		{
			name:         "ClearTextError",
			err:          mockClearTextErr,
			expectedMsg:  encodedMsg,
			expectedCode: ErrorCode_ERROR_CODE_CLEAR_TEXT_ERROR,
		},
		{
			name:         "Unknown Error",
			err:          errors.New("some unexpected error"),
			expectedMsg:  "some unexpected error",
			expectedCode: ErrorCode_ERROR_CODE_INTERNAL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, code := translateErrorForRPC(tt.err)
			require.Contains(t, msg, tt.expectedMsg)
			require.Equal(t, tt.expectedCode, code)
		})
	}
}

// TestParseForwardingError tests the ParseForwardingError function.
func TestParseForwardingError(t *testing.T) {
	t.Parallel()

	mockWireMsg := lnwire.NewTemporaryChannelFailure(nil)

	var buf bytes.Buffer
	lnwire.EncodeFailure(&buf, mockWireMsg, 0)
	encodedMsg := hex.EncodeToString(buf.Bytes())

	tests := []struct {
		name         string
		errStr       string
		expectedIdx  int
		expectedWire lnwire.FailureMessage
		expectsError bool
	}{
		{
			name:         "Valid ForwardingError",
			errStr:       fmt.Sprintf("1@%s", encodedMsg),
			expectedIdx:  1,
			expectedWire: mockWireMsg,
			expectsError: false,
		},
		{
			name:         "Invalid Format",
			errStr:       "invalid_format",
			expectsError: true,
		},
		{
			name:         "Invalid Index",
			errStr:       "invalid@" + encodedMsg,
			expectsError: true,
		},
		{
			name:         "Invalid Wire Message",
			errStr:       "1@invalid",
			expectsError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fwdErr, err := ParseForwardingError(tt.errStr)

			if tt.expectsError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.expectedIdx, fwdErr.FailureSourceIdx)
			require.Equal(t, tt.expectedWire, fwdErr.WireMessage())
		})
	}
}

// TestForwardingErrorEncodeDecode tests the encoding and decoding of a
// forwarding error.
func TestForwardingErrorEncodeDecode(t *testing.T) {
	t.Parallel()

	mockWireMsg := lnwire.NewTemporaryChannelFailure(nil)
	mockForwardingErr := htlcswitch.NewForwardingError(mockWireMsg, 1)

	// Encode the forwarding error.
	encodedError, _ := translateErrorForRPC(mockForwardingErr)

	// Decode the forwarding error.
	decodedError, err := ParseForwardingError(encodedError)
	require.NoError(t, err, "decoding failed")

	// Assert the decoded error matches the original.
	require.Equal(t, mockForwardingErr.FailureSourceIdx, decodedError.FailureSourceIdx)
	require.Equal(t, mockForwardingErr.WireMessage(), decodedError.WireMessage())
}

// TestBuildErrorDecryptor tests the buildErrorDecryptor function.
func TestBuildErrorDecryptor(t *testing.T) {
	t.Parallel()

	validSessionKey := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	validPubKey := []byte{2, 153, 44, 150, 184, 220, 236, 177, 70, 240, 51, 88, 154, 232, 72, 158, 23, 39, 58, 18, 201, 79, 200, 164, 48, 103, 208, 148, 27, 216, 153, 206, 77}
	invalidSessionKey := []byte{1, 2, 3}
	invalidPubKey := []byte{1, 2, 3}

	tests := []struct {
		name           string
		sessionKey     []byte
		hopPubkeys     [][]byte
		expectsError   bool
		expectsDecrypt bool
	}{
		{
			name:           "Valid session key and pubkeys",
			sessionKey:     validSessionKey,
			hopPubkeys:     [][]byte{validPubKey, validPubKey},
			expectsError:   false,
			expectsDecrypt: true,
		},
		{
			name:           "Empty session key",
			sessionKey:     []byte{},
			hopPubkeys:     [][]byte{validPubKey},
			expectsError:   false,
			expectsDecrypt: false,
		},
		{
			name:           "Empty pubkeys",
			sessionKey:     validSessionKey,
			hopPubkeys:     [][]byte{},
			expectsError:   false,
			expectsDecrypt: false,
		},
		{
			name:           "Invalid pubkey format",
			sessionKey:     validSessionKey,
			hopPubkeys:     [][]byte{invalidPubKey},
			expectsError:   true,
			expectsDecrypt: false,
		},
		{
			name:           "Invalid session key format",
			sessionKey:     invalidSessionKey,
			hopPubkeys:     [][]byte{validPubKey},
			expectsError:   true,
			expectsDecrypt: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decryptor, err := buildErrorDecryptor(
				tt.sessionKey, tt.hopPubkeys,
			)

			if tt.expectsError {
				require.Error(t, err)
				require.Nil(t, decryptor)
				return
			}

			require.NoError(t, err)
			if tt.expectsDecrypt {
				require.NotNil(t, decryptor)
			} else {
				require.Nil(t, decryptor)
			}
		})
	}
}
