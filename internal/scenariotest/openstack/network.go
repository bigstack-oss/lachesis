package openstack

import (
	"context"
	"fmt"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/external"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/portsecurity"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/security/groups"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/subnets"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
)

// --- prerequisite lookups ---

func (o *Cloud) FindSecGroup(ctx context.Context, name string) (string, error) {
	pages, err := groups.List(o.network, groups.ListOpts{Name: name}).AllPages(ctx)
	if err != nil {
		return "", fmt.Errorf("openstack: list security groups: %w", err)
	}
	all, err := groups.ExtractGroups(pages)
	if err != nil {
		return "", fmt.Errorf("openstack: extract security groups: %w", err)
	}
	if len(all) == 0 {
		return "", fmt.Errorf("openstack: security group %q not found", name)
	}
	return all[0].ID, nil
}

func (o *Cloud) FindExternalNetwork(ctx context.Context, name string) (string, error) {
	pages, err := networks.List(o.network, networks.ListOpts{Name: name}).AllPages(ctx)
	if err != nil {
		return "", fmt.Errorf("openstack: list networks: %w", err)
	}
	all, err := networks.ExtractNetworks(pages)
	if err != nil {
		return "", fmt.Errorf("openstack: extract networks: %w", err)
	}
	if len(all) == 0 {
		return "", fmt.Errorf("openstack: external network %q not found", name)
	}
	return all[0].ID, nil
}

// --- creation ---

func (o *Cloud) CreateNetwork(ctx context.Context, projectID string, spec scenariotest.NetworkSpec) (string, error) {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return "", err
	}
	up := true
	opts := networks.CreateOpts{Name: spec.Name, AdminStateUp: &up}
	if spec.Shared {
		shared := true
		opts.Shared = &shared
	}
	var createOpts networks.CreateOptsBuilder = opts
	if spec.External {
		// router:external needs the admin role, which scopedFor's
		// client holds on every scenario project.
		isExternal := true
		createOpts = external.CreateOptsExt{CreateOptsBuilder: opts, External: &isExternal}
	}
	n, err := networks.Create(ctx, sc.network, createOpts).Extract()
	if err != nil {
		return "", fmt.Errorf("openstack: create network %q: %w", spec.Name, err)
	}
	return n.ID, nil
}

func (o *Cloud) CreateSubnet(ctx context.Context, projectID string, spec scenariotest.SubnetSpec) (string, error) {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return "", err
	}
	opts := subnets.CreateOpts{
		NetworkID: spec.NetworkID,
		CIDR:      spec.CIDR,
		Name:      spec.Name,
		IPVersion: gophercloud.IPv4,
	}
	if spec.GatewayIP != "" {
		gw := spec.GatewayIP
		opts.GatewayIP = &gw
	}
	s, err := subnets.Create(ctx, sc.network, opts).Extract()
	if err != nil {
		return "", fmt.Errorf("openstack: create subnet %q: %w", spec.Name, err)
	}
	return s.ID, nil
}

func (o *Cloud) CreatePort(ctx context.Context, projectID string, spec scenariotest.PortSpec) (string, error) {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return "", err
	}
	opts := ports.CreateOpts{
		NetworkID:  spec.NetworkID,
		Name:       spec.Name,
		FixedIPs:   []ports.IP{{SubnetID: spec.SubnetID, IPAddress: spec.FixedIP}},
		MACAddress: spec.MACAddress,
	}
	for _, ap := range spec.AllowedPairs {
		opts.AllowedAddressPairs = append(opts.AllowedAddressPairs,
			ports.AddressPair{IPAddress: ap.IP, MACAddress: ap.MAC})
	}
	if spec.SecGroupID != "" {
		sg := []string{spec.SecGroupID}
		opts.SecurityGroups = &sg
	}
	builder := ports.CreateOptsBuilder(opts)
	if spec.PortSecurityOff {
		// Disabling port security requires the port to carry no security
		// groups; force the empty set regardless of SecGroupID.
		empty := []string{}
		opts.SecurityGroups = &empty
		off := false
		builder = portsecurity.PortCreateOptsExt{CreateOptsBuilder: opts, PortSecurityEnabled: &off}
	}
	p, err := ports.Create(ctx, sc.network, builder).Extract()
	if err != nil {
		return "", fmt.Errorf("openstack: create port %q: %w", spec.Name, err)
	}
	return p.ID, nil
}

// PortMAC reads a port's MAC address through the admin network client.
func (o *Cloud) PortMAC(ctx context.Context, portID string) (string, error) {
	p, err := ports.Get(ctx, o.network, portID).Extract()
	if err != nil {
		return "", fmt.Errorf("openstack: get port %s: %w", portID, err)
	}
	return p.MACAddress, nil
}

// ListNetworkPorts uses the admin network client: the residual ports
// it exists to find (platform-created, e.g. cube:mgr) belong to other
// projects and are invisible to a scenario-project-scoped token.
func (o *Cloud) ListNetworkPorts(ctx context.Context, networkID string) ([]string, error) {
	pages, err := ports.List(o.network, ports.ListOpts{NetworkID: networkID}).AllPages(ctx)
	if err != nil {
		return nil, fmt.Errorf("openstack: list ports on network %s: %w", networkID, err)
	}
	all, err := ports.ExtractPorts(pages)
	if err != nil {
		return nil, fmt.Errorf("openstack: extract ports: %w", err)
	}
	ids := make([]string, 0, len(all))
	for _, p := range all {
		ids = append(ids, p.ID)
	}
	return ids, nil
}

// --- teardown ---

func (o *Cloud) DeletePort(ctx context.Context, projectID, id string) error {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return err
	}
	if err := ignoreNotFound(ports.Delete(ctx, sc.network, id).ExtractErr()); err != nil {
		return fmt.Errorf("openstack: delete port %s: %w", id, err)
	}
	return nil
}

func (o *Cloud) DeleteSubnet(ctx context.Context, projectID, id string) error {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return err
	}
	if err := ignoreNotFound(subnets.Delete(ctx, sc.network, id).ExtractErr()); err != nil {
		return fmt.Errorf("openstack: delete subnet %s: %w", id, err)
	}
	return nil
}

func (o *Cloud) DeleteNetwork(ctx context.Context, projectID, id string) error {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return err
	}
	if err := ignoreNotFound(networks.Delete(ctx, sc.network, id).ExtractErr()); err != nil {
		return fmt.Errorf("openstack: delete network %s: %w", id, err)
	}
	return nil
}
