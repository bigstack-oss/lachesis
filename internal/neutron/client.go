package neutron

import (
	"context"
	"fmt"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack"
)

// defaultInterface is the Keystone endpoint-catalog interface the
// agent picks when the operator does not override it. Compute-node
// agents talk to OpenStack over the internal interface; public is
// only meaningful for off-cluster clients.
const defaultInterface = "internal"

// Client is the agent's Neutron API handle. Internally it wraps two
// [gophercloud.ServiceClient]s — the Network v2 client for Neutron
// calls and an Identity v3 client used to resolve project IDs to
// names. gophercloud owns Keystone v3 authentication, token caching,
// and reactive 401-driven reauth (AllowReauth=true). Construct with
// [NewClient].
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
	iface := creds.Interface
	if iface == "" {
		iface = defaultInterface
	}
	switch gophercloud.Availability(iface) {
	case gophercloud.AvailabilityInternal,
		gophercloud.AvailabilityPublic,
		gophercloud.AvailabilityAdmin:
		// ok
	default:
		return nil, fmt.Errorf("neutron: invalid interface %q (want internal/public/admin)", iface)
	}

	authOpts := gophercloud.AuthOptions{
		IdentityEndpoint: creds.AuthURL,
		Username:         creds.Username,
		Password:         creds.Password,
		DomainName:       creds.UserDomain,
		Scope: &gophercloud.AuthScope{
			ProjectName: creds.ProjectName,
			DomainName:  creds.ProjectDomain,
		},
		AllowReauth: true,
	}

	provider, err := openstack.AuthenticatedClient(ctx, authOpts)
	if err != nil {
		return nil, fmt.Errorf("neutron: keystone auth: %w", err)
	}
	net, err := openstack.NewNetworkV2(provider, gophercloud.EndpointOpts{
		Region:       creds.Region,
		Availability: gophercloud.Availability(iface),
	})
	if err != nil {
		return nil, fmt.Errorf("neutron: endpoint discovery: %w", err)
	}
	id, err := openstack.NewIdentityV3(provider, gophercloud.EndpointOpts{
		Region:       creds.Region,
		Availability: gophercloud.Availability(iface),
	})
	if err != nil {
		return nil, fmt.Errorf("neutron: identity endpoint discovery: %w", err)
	}
	return &Client{network: net, identity: id}, nil
}

// EndpointURL returns the Neutron base URL gophercloud discovered
// from the Keystone catalog. Useful for log / metric attribution
// and for diagnostics when an operator misconfigures the catalog.
func (c *Client) EndpointURL() string { return c.network.Endpoint }
