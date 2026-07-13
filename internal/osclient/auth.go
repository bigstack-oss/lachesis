// auth.go owns Keystone v3 authentication and endpoint-catalog
// selection — the mechanics shared by every OpenStack consumer in
// this repo. Service-client construction stays with the consumers.

package osclient

import (
	"context"
	"fmt"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack"
)

// EndpointOpts validates the credentials' Interface (falling back to
// fallbackInterface when empty) and returns the endpoint-catalog
// selection consumers pass to gophercloud's service-client
// constructors. The fallback is consumer policy: compute-node agents
// pass "internal", operator tools pass "public".
func (c Credentials) EndpointOpts(fallbackInterface string) (gophercloud.EndpointOpts, error) {
	iface := c.Interface
	if iface == "" {
		iface = fallbackInterface
	}
	switch gophercloud.Availability(iface) {
	case gophercloud.AvailabilityInternal,
		gophercloud.AvailabilityPublic,
		gophercloud.AvailabilityAdmin:
		// ok
	default:
		return gophercloud.EndpointOpts{}, fmt.Errorf("osclient: invalid interface %q (want internal/public/admin)", iface)
	}
	return gophercloud.EndpointOpts{
		Region:       c.Region,
		Availability: gophercloud.Availability(iface),
	}, nil
}

// Authenticate obtains a Keystone v3 token scoped to the
// credentials' own project (ProjectName + ProjectDomain) and returns
// the provider consumers build service clients from.
//
// AllowReauth is set: on a 401 gophercloud transparently re-auths
// and retries the call once, so callers see a successful response or
// a final error. Boot-time retry policy remains the caller's.
func Authenticate(ctx context.Context, c Credentials) (*gophercloud.ProviderClient, error) {
	return authenticate(ctx, c, &gophercloud.AuthScope{
		ProjectName: c.ProjectName,
		DomainName:  c.ProjectDomain,
	})
}

// AuthenticateProject is [Authenticate] scoped to an explicit
// project ID instead of the credentials' own project. gophercloud
// fixes a token's project scope at construction and resources are
// born in the token's project, so creating resources inside another
// project requires a token minted this way (the authenticating user
// must already hold a role on that project).
func AuthenticateProject(ctx context.Context, c Credentials, projectID string) (*gophercloud.ProviderClient, error) {
	return authenticate(ctx, c, &gophercloud.AuthScope{ProjectID: projectID})
}

func authenticate(ctx context.Context, c Credentials, scope *gophercloud.AuthScope) (*gophercloud.ProviderClient, error) {
	provider, err := openstack.AuthenticatedClient(ctx, gophercloud.AuthOptions{
		IdentityEndpoint: c.AuthURL,
		Username:         c.Username,
		Password:         c.Password,
		DomainName:       c.UserDomain,
		Scope:            scope,
		AllowReauth:      true,
	})
	if err != nil {
		return nil, fmt.Errorf("osclient: keystone auth: %w", err)
	}
	return provider, nil
}
