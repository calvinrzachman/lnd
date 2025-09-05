//go:build !switchrpc
// +build !switchrpc

package routing

func init() {
	managedExternally = false
}
