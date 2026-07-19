package neutron

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack"

	"github.com/bigstack-oss/lachesis/internal/osclient"
)

// Client is the agent's Neutron API handle. Internally it wraps up to
// three [gophercloud.ServiceClient]s — the Network v2 client for
// Neutron calls, an Identity v3 client used to resolve project IDs to
// names, and (best-effort) a Compute v2 client for the Nova server
// list behind lachesis_server_info. Keystone authentication, token
// caching, and reactive 401-driven reauth live in
// [osclient.Authenticate] (AllowReauth=true). Construct with
// [NewClient].
type Client struct {
	network  *gophercloud.ServiceClient
	identity *gophercloud.ServiceClient
	// compute is nil when the Keystone catalog carries no Compute
	// endpoint for the agent's credentials. Its only consumer,
	// [Client.ListServers], degrades to an empty list — the info
	// series is optional, so a compute-less deployment keeps working.
	compute *gophercloud.ServiceClient
}

// NewClient authenticates against Keystone with creds and returns a
// Client bound to the Network ServiceClient. The endpoint-catalog
// interface defaults to "internal" — compute-node agents talk to
// the internal endpoint, not the operator-facing public one. Set
// [Credentials.Interface] to override.
//
// On Neutron 401 responses, gophercloud transparently re-auths and
// retries the call once; the caller sees a successful response or
// a final error. This is gophercloud's standard AllowReauth model;
// see docs/architecture/trie-construction.md#data-sources for the broader cold-start flow.
func NewClient(ctx context.Context, creds Credentials) (*Client, error) {
	eo, err := creds.EndpointOpts(defaultInterface)
	if err != nil {
		return nil, fmt.Errorf("neutron: %w", err)
	}
	provider, err := osclient.Authenticate(ctx, creds)
	if err != nil {
		return nil, fmt.Errorf("neutron: %w", err)
	}
	net, err := openstack.NewNetworkV2(provider, eo)
	if err != nil {
		return nil, fmt.Errorf("neutron: endpoint discovery: %w", err)
	}
	id, err := openstack.NewIdentityV3(provider, eo)
	if err != nil {
		return nil, fmt.Errorf("neutron: identity endpoint discovery: %w", err)
	}
	// Compute is best-effort: the agent needs it only for the optional
	// lachesis_server_info family, so a catalog without a Compute
	// endpoint leaves the client nil and logs rather than failing the
	// whole cold-start (docs/architecture/metrics.md info metrics).
	compute, err := openstack.NewComputeV2(provider, eo)
	if err != nil {
		slog.Warn("compute endpoint discovery failed; lachesis_server_info will be absent",
			"component", componentNeutron, "err", err)
		compute = nil
	}
	return &Client{network: net, identity: id, compute: compute}, nil
}

// EndpointURL returns the Neutron base URL gophercloud discovered
// from the Keystone catalog. Useful for log / metric attribution
// and for diagnostics when an operator misconfigures the catalog.
func (c *Client) EndpointURL() string { return c.network.Endpoint }
