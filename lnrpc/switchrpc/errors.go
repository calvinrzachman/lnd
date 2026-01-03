//go:build switchrpc
// +build switchrpc

package switchrpc

import "errors"

var (
	// ErrUnknown is returned when a client is unable to unmarshall an
	// error from a gRPC status.
	ErrUnknown = errors.New("unable to unmarshall error")
)
