package routing

import (
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
)

// GraphSessionFactory can be used to produce a new GraphSession instance which
// can then be used for a path-finding session. In some instances, a "session"
type GraphSessionFactory interface {
	// NewSession will produce a new GraphSession to use for a path-finding
	// session.
	NewSession() (GraphSession, error)
}

// GraphSession describes a new read session with a Graph backend. It must be
// closed using its Close method after path-finding is complete.
type GraphSession interface {
	// Graph returns the Graph that this session gives access to.
	Graph() Graph

	// Close closes the GraphSession and must be called once path-finding
	// using this GraphSession is complete.
	Close() error
}

// Graph is an abstract interface that provides information about nodes
// and edges to pathfinding.
type Graph interface {
	// ForEachNodeChannel calls the callback for every channel of the given
	// node.
	ForEachNodeChannel(nodePub route.Vertex,
		cb func(channel *channeldb.DirectedChannel) error) error

	// FetchNodeFeatures returns the features of the given node.
	FetchNodeFeatures(nodePub route.Vertex) (*lnwire.FeatureVector, error)
}

// FetchAmountPairCapacity determines the maximal public capacity between two
// nodes depending on the amount we try to send.
func FetchAmountPairCapacity(g Graph, source, nodeFrom,
	nodeTo route.Vertex, amount lnwire.MilliSatoshi) (btcutil.Amount,
	error) {

	// Create unified edges for all incoming connections.
	//
	// Note: Inbound fees are not used here because this method is only used
	// by a deprecated router rpc.
	u := newNodeEdgeUnifier(source, nodeTo, false, nil)

	err := u.addGraphPolicies(g)
	if err != nil {
		return 0, err
	}

	edgeUnifier, ok := u.edgeUnifiers[nodeFrom]
	if !ok {
		return 0, fmt.Errorf("no edge info for node pair %v -> %v",
			nodeFrom, nodeTo)
	}

	edge := edgeUnifier.getEdgeNetwork(amount, 0)
	if edge == nil {
		return 0, fmt.Errorf("no edge for node pair %v -> %v "+
			"(amount %v)", nodeFrom, nodeTo, amount)
	}

	return edge.capacity, nil
}
