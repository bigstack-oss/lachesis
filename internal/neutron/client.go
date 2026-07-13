package neutron

import (
	"context"
	"fmt"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/osclient"
)

// Client is the agent's Neutron API handle. Internally it wraps two
// [gophercloud.ServiceClient]s — the Network v2 client for Neutron
// calls and an Identity v3 client used to resolve project IDs to
// names. Keystone authentication, token caching, and reactive
// 401-driven reauth live in [osclient.Authenticate]
// (AllowReauth=true). Construct with [NewClient].
type Client struct {
	network  *gophercloud.ServiceClient
	identity *gophercloud.ServiceClient
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
// see docs/DESIGN.md §5.1 for the broader cold-start flow.
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
	return &Client{network: net, identity: id}, nil
}

// EndpointURL returns the Neutron base URL gophercloud discovered
// from the Keystone catalog. Useful for log / metric attribution
// and for diagnostics when an operator misconfigures the catalog.
func (c *Client) EndpointURL() string { return c.network.Endpoint }
