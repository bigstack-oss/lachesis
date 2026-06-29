package scenariotest

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/flavors"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/hypervisors"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/keypairs"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/projects"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/roles"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/tokens"
	"github.com/gophercloud/gophercloud/v2/openstack/image/v2/images"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/layer3/floatingips"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/layer3/routers"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/security/groups"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/subnets"
)

// OpenStack is the gophercloud-backed [Cloud]. It holds admin-scoped
// service clients plus a cache of per-project-scoped Network/Compute
// clients, minted lazily by re-authenticating the admin credentials
// scoped to the target project. Used single-threaded by realize, so
// the scoped-client cache needs no locking.
type OpenStack struct {
	creds OpenStackCreds
	eo    gophercloud.EndpointOpts

	identity *gophercloud.ServiceClient
	network  *gophercloud.ServiceClient
	compute  *gophercloud.ServiceClient
	image    *gophercloud.ServiceClient

	userID      string // authenticated admin user, for role grants
	adminRoleID string // resolved lazily on first GrantAdminRole

	scoped map[string]*scopedClients
}

type scopedClients struct {
	network *gophercloud.ServiceClient
	compute *gophercloud.ServiceClient
}

// NewOpenStack authenticates creds (admin, project-scoped to the
// credential's own project) and returns a ready [Cloud]. The
// endpoint-catalog interface defaults to "public" — scenariotest is
// an operator-facing tool, not a compute-node agent.
func NewOpenStack(ctx context.Context, creds OpenStackCreds) (*OpenStack, error) {
	iface := creds.Interface
	if iface == "" {
		iface = "public"
	}
	switch gophercloud.Availability(iface) {
	case gophercloud.AvailabilityInternal, gophercloud.AvailabilityPublic, gophercloud.AvailabilityAdmin:
	default:
		return nil, fmt.Errorf("openstack: invalid interface %q (want internal/public/admin)", iface)
	}

	o := &OpenStack{
		creds:  creds,
		eo:     gophercloud.EndpointOpts{Region: creds.Region, Availability: gophercloud.Availability(iface)},
		scoped: map[string]*scopedClients{},
	}

	adminScope := &gophercloud.AuthScope{ProjectName: creds.ProjectName, DomainName: creds.ProjectDomain}
	provider, err := openstack.AuthenticatedClient(ctx, o.authOpts(adminScope))
	if err != nil {
		return nil, fmt.Errorf("openstack: keystone auth: %w", err)
	}
	if creds.RequestTimeout > 0 {
		provider.HTTPClient = http.Client{Timeout: creds.RequestTimeout}
	}

	ar := provider.GetAuthResult()
	ctr, ok := ar.(tokens.CreateResult)
	if !ok {
		return nil, fmt.Errorf("openstack: unexpected auth result %T (want identity v3 token)", ar)
	}
	user, err := ctr.ExtractUser()
	if err != nil {
		return nil, fmt.Errorf("openstack: extract auth user: %w", err)
	}
	o.userID = user.ID

	if o.identity, err = openstack.NewIdentityV3(provider, o.eo); err != nil {
		return nil, fmt.Errorf("openstack: identity endpoint: %w", err)
	}
	if o.network, err = openstack.NewNetworkV2(provider, o.eo); err != nil {
		return nil, fmt.Errorf("openstack: network endpoint: %w", err)
	}
	if o.compute, err = openstack.NewComputeV2(provider, o.eo); err != nil {
		return nil, fmt.Errorf("openstack: compute endpoint: %w", err)
	}
	if o.image, err = openstack.NewImageV2(provider, o.eo); err != nil {
		return nil, fmt.Errorf("openstack: image endpoint: %w", err)
	}
	return o, nil
}

func (o *OpenStack) authOpts(scope *gophercloud.AuthScope) gophercloud.AuthOptions {
	return gophercloud.AuthOptions{
		IdentityEndpoint: o.creds.AuthURL,
		Username:         o.creds.Username,
		Password:         o.creds.Password,
		DomainName:       o.creds.UserDomain,
		Scope:            scope,
		AllowReauth:      true,
	}
}

// scopedFor returns Network/Compute clients whose token is scoped to
// projectID, minting and caching them on first use. The admin user
// must already hold a role on projectID (see GrantAdminRole).
func (o *OpenStack) scopedFor(ctx context.Context, projectID string) (*scopedClients, error) {
	if sc, ok := o.scoped[projectID]; ok {
		return sc, nil
	}
	provider, err := openstack.AuthenticatedClient(ctx, o.authOpts(&gophercloud.AuthScope{ProjectID: projectID}))
	if err != nil {
		return nil, fmt.Errorf("openstack: scope to project %s: %w", projectID, err)
	}
	if o.creds.RequestTimeout > 0 {
		provider.HTTPClient = http.Client{Timeout: o.creds.RequestTimeout}
	}
	net, err := openstack.NewNetworkV2(provider, o.eo)
	if err != nil {
		return nil, fmt.Errorf("openstack: scoped network endpoint: %w", err)
	}
	comp, err := openstack.NewComputeV2(provider, o.eo)
	if err != nil {
		return nil, fmt.Errorf("openstack: scoped compute endpoint: %w", err)
	}
	sc := &scopedClients{network: net, compute: comp}
	o.scoped[projectID] = sc
	return sc, nil
}

// --- prerequisite + placement lookups ---

func (o *OpenStack) FindImage(ctx context.Context, name string) (string, error) {
	pages, err := images.List(o.image, images.ListOpts{Name: name}).AllPages(ctx)
	if err != nil {
		return "", fmt.Errorf("openstack: list images: %w", err)
	}
	all, err := images.ExtractImages(pages)
	if err != nil {
		return "", fmt.Errorf("openstack: extract images: %w", err)
	}
	if len(all) == 0 {
		return "", fmt.Errorf("openstack: image %q not found", name)
	}
	return all[0].ID, nil
}

func (o *OpenStack) FindFlavor(ctx context.Context, name string) (string, error) {
	pages, err := flavors.ListDetail(o.compute, flavors.ListOpts{}).AllPages(ctx)
	if err != nil {
		return "", fmt.Errorf("openstack: list flavors: %w", err)
	}
	all, err := flavors.ExtractFlavors(pages)
	if err != nil {
		return "", fmt.Errorf("openstack: extract flavors: %w", err)
	}
	for _, f := range all {
		if f.Name == name {
			return f.ID, nil
		}
	}
	return "", fmt.Errorf("openstack: flavor %q not found", name)
}

func (o *OpenStack) CheckKeypair(ctx context.Context, name string) error {
	if _, err := keypairs.Get(ctx, o.compute, name, keypairs.GetOpts{}).Extract(); err != nil {
		return fmt.Errorf("openstack: keypair %q: %w", name, err)
	}
	return nil
}

func (o *OpenStack) FindSecGroup(ctx context.Context, name string) (string, error) {
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

func (o *OpenStack) FindExternalNetwork(ctx context.Context, name string) (string, error) {
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

func (o *OpenStack) Hypervisors(ctx context.Context) ([]string, error) {
	pages, err := hypervisors.List(o.compute, hypervisors.ListOpts{}).AllPages(ctx)
	if err != nil {
		return nil, fmt.Errorf("openstack: list hypervisors: %w", err)
	}
	all, err := hypervisors.ExtractHypervisors(pages)
	if err != nil {
		return nil, fmt.Errorf("openstack: extract hypervisors: %w", err)
	}
	hosts := make([]string, 0, len(all))
	for _, h := range all {
		hosts = append(hosts, h.HypervisorHostname)
	}
	return hosts, nil
}

// --- projects ---

func (o *OpenStack) FindProject(ctx context.Context, name string) (string, bool, error) {
	pages, err := projects.List(o.identity, projects.ListOpts{Name: name}).AllPages(ctx)
	if err != nil {
		return "", false, fmt.Errorf("openstack: list projects: %w", err)
	}
	all, err := projects.ExtractProjects(pages)
	if err != nil {
		return "", false, fmt.Errorf("openstack: extract projects: %w", err)
	}
	if len(all) == 0 {
		return "", false, nil
	}
	return all[0].ID, true, nil
}

func (o *OpenStack) CreateProject(ctx context.Context, name string) (string, error) {
	enabled := true
	p, err := projects.Create(ctx, o.identity, projects.CreateOpts{
		Name:        name,
		Enabled:     &enabled,
		Description: "scenariotest live-validation project (not torn down)",
	}).Extract()
	if err != nil {
		return "", fmt.Errorf("openstack: create project %q: %w", name, err)
	}
	return p.ID, nil
}

func (o *OpenStack) GrantAdminRole(ctx context.Context, projectID string) error {
	if o.adminRoleID == "" {
		pages, err := roles.List(o.identity, roles.ListOpts{Name: "admin"}).AllPages(ctx)
		if err != nil {
			return fmt.Errorf("openstack: list roles: %w", err)
		}
		rs, err := roles.ExtractRoles(pages)
		if err != nil {
			return fmt.Errorf("openstack: extract roles: %w", err)
		}
		if len(rs) == 0 {
			return fmt.Errorf("openstack: role \"admin\" not found")
		}
		o.adminRoleID = rs[0].ID
	}
	err := roles.Assign(ctx, o.identity, o.adminRoleID, roles.AssignOpts{
		UserID:    o.userID,
		ProjectID: projectID,
	}).ExtractErr()
	if err != nil {
		return fmt.Errorf("openstack: grant admin role on project %s: %w", projectID, err)
	}
	return nil
}

// --- per-project resource creation ---

func (o *OpenStack) CreateNetwork(ctx context.Context, projectID string, spec NetworkSpec) (string, error) {
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
	n, err := networks.Create(ctx, sc.network, opts).Extract()
	if err != nil {
		return "", fmt.Errorf("openstack: create network %q: %w", spec.Name, err)
	}
	return n.ID, nil
}

func (o *OpenStack) CreateSubnet(ctx context.Context, projectID string, spec SubnetSpec) (string, error) {
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

func (o *OpenStack) CreateRouter(ctx context.Context, projectID string, spec RouterSpec) (string, error) {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return "", err
	}
	up := true
	opts := routers.CreateOpts{Name: spec.Name, AdminStateUp: &up}
	if spec.ExternalNetworkID != "" {
		opts.GatewayInfo = &routers.GatewayInfo{NetworkID: spec.ExternalNetworkID}
	}
	r, err := routers.Create(ctx, sc.network, opts).Extract()
	if err != nil {
		return "", fmt.Errorf("openstack: create router %q: %w", spec.Name, err)
	}
	return r.ID, nil
}

func (o *OpenStack) CreatePort(ctx context.Context, projectID string, spec PortSpec) (string, error) {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return "", err
	}
	opts := ports.CreateOpts{
		NetworkID: spec.NetworkID,
		Name:      spec.Name,
		FixedIPs:  []ports.IP{{SubnetID: spec.SubnetID, IPAddress: spec.FixedIP}},
	}
	if spec.SecGroupID != "" {
		sg := []string{spec.SecGroupID}
		opts.SecurityGroups = &sg
	}
	p, err := ports.Create(ctx, sc.network, opts).Extract()
	if err != nil {
		return "", fmt.Errorf("openstack: create port %q: %w", spec.Name, err)
	}
	return p.ID, nil
}

func (o *OpenStack) AddRouterInterface(ctx context.Context, projectID, routerID, subnetID, portID string) error {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return err
	}
	_, err = routers.AddInterface(ctx, sc.network, routerID, routers.AddInterfaceOpts{
		SubnetID: subnetID,
		PortID:   portID,
	}).Extract()
	if err != nil {
		return fmt.Errorf("openstack: add interface (router %s, subnet %q, port %q): %w", routerID, subnetID, portID, err)
	}
	return nil
}

func (o *OpenStack) SetRouterRoutes(ctx context.Context, projectID, routerID string, routes []RouteSpec) error {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return err
	}
	rs := make([]routers.Route, len(routes))
	for i, r := range routes {
		rs[i] = routers.Route{DestinationCIDR: r.Destination, NextHop: r.Nexthop}
	}
	_, err = routers.Update(ctx, sc.network, routerID, routers.UpdateOpts{Routes: &rs}).Extract()
	if err != nil {
		return fmt.Errorf("openstack: set routes on router %s: %w", routerID, err)
	}
	return nil
}

func (o *OpenStack) CreateServer(ctx context.Context, projectID string, spec ServerSpec) (string, error) {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return "", err
	}
	base := servers.CreateOpts{
		Name:             spec.Name,
		FlavorRef:        spec.FlavorID,
		ImageRef:         spec.ImageID,
		Networks:         []servers.Network{{Port: spec.PortID}},
		AvailabilityZone: spec.AvailabilityZone,
	}
	if spec.SecGroupName != "" {
		base.SecurityGroups = []string{spec.SecGroupName}
	}
	var opts servers.CreateOptsBuilder = base
	if spec.KeypairName != "" {
		opts = keypairs.CreateOptsExt{CreateOptsBuilder: base, KeyName: spec.KeypairName}
	}
	s, err := servers.Create(ctx, sc.compute, opts, nil).Extract()
	if err != nil {
		return "", fmt.Errorf("openstack: boot server %q: %w", spec.Name, err)
	}
	return s.ID, nil
}

// serverPollInterval is how often WaitServerActive re-checks a
// booting server. Boot on a real cluster takes tens of seconds, so a
// few seconds between polls keeps Nova load low without adding
// meaningful latency.
const serverPollInterval = 3 * time.Second

func (o *OpenStack) WaitServerActive(ctx context.Context, projectID, serverID string) error {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return err
	}
	ticker := time.NewTicker(serverPollInterval)
	defer ticker.Stop()
	for {
		s, err := servers.Get(ctx, sc.compute, serverID).Extract()
		if err != nil {
			return fmt.Errorf("openstack: get server %s: %w", serverID, err)
		}
		switch s.Status {
		case "ACTIVE":
			return nil
		case "ERROR":
			return fmt.Errorf("openstack: server %s entered ERROR state", serverID)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("openstack: server %s not ACTIVE before deadline (last status %q): %w", serverID, s.Status, ctx.Err())
		case <-ticker.C:
		}
	}
}

func (o *OpenStack) CreateFIP(ctx context.Context, projectID string, spec FIPCreateSpec) (string, string, error) {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return "", "", err
	}
	opts := floatingips.CreateOpts{
		FloatingNetworkID: spec.ExternalNetworkID,
		PortID:            spec.PortID,
		FixedIP:           spec.FixedIP,
		FloatingIP:        spec.FloatingIP,
	}
	fip, err := floatingips.Create(ctx, sc.network, opts).Extract()
	if err != nil {
		return "", "", fmt.Errorf("openstack: allocate floating ip: %w", err)
	}
	return fip.ID, fip.FloatingIP, nil
}
