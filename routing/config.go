package routing

// managedExternally is a build-time variable that indicates whether the
// payment lifecycle is managed by an external entity. This is true when the
// 'switchrpc' build tag is active.
var managedExternally bool
