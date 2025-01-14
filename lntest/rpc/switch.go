package rpc

import (
	"context"

	"github.com/lightningnetwork/lnd/lnrpc/switchrpc"
)

// =====================
// SwitchClient related RPCs.
// =====================

// SendOnion makes a RPC call to SendOnion and asserts.
//
//nolint:lll
func (h *HarnessRPC) SendOnion(
	req *switchrpc.SendOnionRequest) *switchrpc.SendOnionResponse {

	ctxt, cancel := context.WithTimeout(h.runCtx, DefaultTimeout)
	defer cancel()

	resp, err := h.Switch.SendOnion(ctxt, req)
	h.NoError(err, "SendOnion")

	return resp
}

// TrackOnion makes a RPC call to TrackOnion and asserts.
//
//nolint:lll
func (h *HarnessRPC) TrackOnion(
	req *switchrpc.TrackOnionRequest) *switchrpc.TrackOnionResponse {

	ctxt, cancel := context.WithTimeout(h.runCtx, DefaultTimeout)
	defer cancel()

	resp, err := h.Switch.TrackOnion(ctxt, req)
	h.NoError(err, "TrackOnion")

	return resp
}

// BuildOnion makes a RPC call to BuildOnion and asserts.
//
//nolint:lll
func (h *HarnessRPC) BuildOnion(
	req *switchrpc.BuildOnionRequest) *switchrpc.BuildOnionResponse {

	ctxt, cancel := context.WithTimeout(h.runCtx, DefaultTimeout)
	defer cancel()

	resp, err := h.Switch.BuildOnion(ctxt, req)
	h.NoError(err, "BuildOnion")

	return resp
}

// FetchAttemptResults makes a RPC call to FetchAttemptResults and asserts.
//
//nolint:lll
func (h *HarnessRPC) FetchAttemptResults(
	req *switchrpc.FetchAttemptResultsRequest) *switchrpc.FetchAttemptResultsResponse {

	ctxt, cancel := context.WithTimeout(h.runCtx, DefaultTimeout)
	defer cancel()

	resp, err := h.Switch.FetchAttemptResults(ctxt, req)
	h.NoError(err, "FetchAttemptResult")

	return resp
}

// DeleteAttemptResult makes a RPC call to DeleteAttemptResult and asserts.
//
//nolint:lll
func (h *HarnessRPC) DeleteAttemptResult(
	req *switchrpc.DeleteAttemptResultRequest) *switchrpc.DeleteAttemptResultResponse {

	ctxt, cancel := context.WithTimeout(h.runCtx, DefaultTimeout)
	defer cancel()

	resp, err := h.Switch.DeleteAttemptResult(ctxt, req)
	h.NoError(err, "DeleteAttemptResult")

	return resp
}
