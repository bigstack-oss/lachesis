package neutron

import (
	"context"
	"fmt"

	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/projects"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/external"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/layer3/floatingips"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/layer3/routers"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/subnets"
)

// networkWithExternal combines the base Network with the
// `router:external` extension so the agent can tell external
// (operator-managed gateway) networks apart from tenant ones.
type networkWithExternal struct {
	networks.Network
	external.NetworkExternalExt
}

// ListNetworks returns every Neutron network the agent's project is
// authorised to read, including the `router:external` flag needed by
// the trie builder to classify external (operator-managed) networks
// correctly. Pagination is drained inside the call; the returned
// slice is the full result set.
func (c *Client) ListNetworks(ctx context.Context) ([]Network, error) {
	pages, err := networks.List(c.network, networks.ListOpts{}).AllPages(ctx)
	if err != nil {
		return nil, fmt.Errorf("neutron: list networks: %w", err)
	}
	var gcs []networkWithExternal
	if err := networks.ExtractNetworksInto(pages, &gcs); err != nil {
		return nil, fmt.Errorf("neutron: extract networks: %w", err)
	}
	out := make([]Network, len(gcs))
	for i, n := range gcs {
		out[i] = Network{
			ID:         n.ID,
			ProjectID:  preferProjectID(n.ProjectID, n.TenantID),
			Name:       n.Name,
			Shared:     n.Shared,
			IsExternal: n.External,
		}
	}
	return out, nil
}

// ListSubnets returns every Neutron subnet the agent's project can
// see. See [ListNetworks] for pagination semantics.
func (c *Client) ListSubnets(ctx context.Context) ([]Subnet, error) {
	pages, err := subnets.List(c.network, subnets.ListOpts{}).AllPages(ctx)
	if err != nil {
		return nil, fmt.Errorf("neutron: list subnets: %w", err)
	}
	gcs, err := subnets.ExtractSubnets(pages)
	if err != nil {
		return nil, fmt.Errorf("neutron: extract subnets: %w", err)
	}
	out := make([]Subnet, len(gcs))
	for i, s := range gcs {
		out[i] = Subnet{
			ID:        s.ID,
			NetworkID: s.NetworkID,
			ProjectID: preferProjectID(s.ProjectID, s.TenantID),
			CIDR:      s.CIDR,
			GatewayIP: s.GatewayIP,
			IPVersion: s.IPVersion,
		}
	}
	return out, nil
}

// ListPorts returns every Neutron port the agent's project can see.
// See [ListNetworks] for pagination semantics.
func (c *Client) ListPorts(ctx context.Context) ([]Port, error) {
	pages, err := ports.List(c.network, ports.ListOpts{}).AllPages(ctx)
	if err != nil {
		return nil, fmt.Errorf("neutron: list ports: %w", err)
	}
	gcs, err := ports.ExtractPorts(pages)
	if err != nil {
		return nil, fmt.Errorf("neutron: extract ports: %w", err)
	}
	out := make([]Port, len(gcs))
	for i, p := range gcs {
		fixed := make([]FixedIP, len(p.FixedIPs))
		for j, ip := range p.FixedIPs {
			fixed[j] = FixedIP{SubnetID: ip.SubnetID, IPAddress: ip.IPAddress}
		}
		out[i] = Port{
			ID:          p.ID,
			NetworkID:   p.NetworkID,
			ProjectID:   preferProjectID(p.ProjectID, p.TenantID),
			MACAddress:  p.MACAddress,
			DeviceOwner: p.DeviceOwner,
			DeviceID:    p.DeviceID,
			FixedIPs:    fixed,
		}
	}
	return out, nil
}

// ListRouters returns every Neutron router the agent's project can
// see, including each router's external-gateway network ID (when
// set) and operator-configured extra routes. See [ListNetworks] for
// pagination semantics.
func (c *Client) ListRouters(ctx context.Context) ([]Router, error) {
	pages, err := routers.List(c.network, routers.ListOpts{}).AllPages(ctx)
	if err != nil {
		return nil, fmt.Errorf("neutron: list routers: %w", err)
	}
	gcs, err := routers.ExtractRouters(pages)
	if err != nil {
		return nil, fmt.Errorf("neutron: extract routers: %w", err)
	}
	out := make([]Router, len(gcs))
	for i, r := range gcs {
		routes := make([]Route, len(r.Routes))
		for j, rt := range r.Routes {
			routes[j] = Route{Destination: rt.DestinationCIDR, Nexthop: rt.NextHop}
		}
		out[i] = Router{
			ID:                r.ID,
			ProjectID:         preferProjectID(r.ProjectID, r.TenantID),
			Name:              r.Name,
			ExternalNetworkID: r.GatewayInfo.NetworkID,
			Routes:            routes,
		}
	}
	return out, nil
}

// ListFloatingIPs returns every Neutron floating IP the agent's
// project can see, carrying the port binding and source external
// network needed by [ExternalNetworkByPort]. See [ListNetworks] for
// pagination semantics.
func (c *Client) ListFloatingIPs(ctx context.Context) ([]FloatingIP, error) {
	pages, err := floatingips.List(c.network, floatingips.ListOpts{}).AllPages(ctx)
	if err != nil {
		return nil, fmt.Errorf("neutron: list floatingips: %w", err)
	}
	gcs, err := floatingips.ExtractFloatingIPs(pages)
	if err != nil {
		return nil, fmt.Errorf("neutron: extract floatingips: %w", err)
	}
	out := make([]FloatingIP, len(gcs))
	for i, f := range gcs {
		out[i] = FloatingIP{
			ID:                f.ID,
			PortID:            f.PortID,
			FloatingNetworkID: f.FloatingNetworkID,
		}
	}
	return out, nil
}

// ListProjects returns every Keystone project the agent's project is
// authorised to see. Used by /debug pages to display project names
// alongside the UUIDs Neutron resources carry. Pagination is drained
// inside the call.
func (c *Client) ListProjects(ctx context.Context) ([]Project, error) {
	pages, err := projects.List(c.identity, projects.ListOpts{}).AllPages(ctx)
	if err != nil {
		return nil, fmt.Errorf("keystone: list projects: %w", err)
	}
	gcs, err := projects.ExtractProjects(pages)
	if err != nil {
		return nil, fmt.Errorf("keystone: extract projects: %w", err)
	}
	out := make([]Project, len(gcs))
	for i, p := range gcs {
		out[i] = Project{ID: p.ID, Name: p.Name}
	}
	return out, nil
}

// preferProjectID returns project_id when set, otherwise tenant_id.
// Neutron v2.0 emits both during the long-running v3-naming
// migration; project_id is the canonical modern field while
// tenant_id survives in older responses and some plugin overrides.
func preferProjectID(projectID, tenantID string) string {
	if projectID != "" {
		return projectID
	}
	return tenantID
}
