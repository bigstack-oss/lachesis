package scenariotest

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/attachinterfaces"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/flavors"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/hypervisors"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/keypairs"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/projects"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/roles"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/tokens"
	"github.com/gophercloud/gophercloud/v2/openstack/image/v2/images"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/external"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/layer3/floatingips"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/layer3/routers"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/portsecurity"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/security/groups"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/subnets"

	"github.com/bigstack-oss/lachesis/internal/osclient"
)

// OpenStack is the gophercloud-backed [Cloud]. It holds admin-scoped
// service clients plus a cache of per-project-scoped Network/Compute
// clients, minted lazily by re-authenticating the admin credentials
// scoped to the target project (see [osclient.AuthenticateProject]).
// Used single-threaded by realize, so the scoped-client cache needs
// no locking.
type OpenStack struct {
	creds   osclient.Credentials
	timeout time.Duration
	eo      gophercloud.EndpointOpts
	log     *slog.Logger

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

// NewOpenStack resolves the config's two-mode credentials,
// authenticates (admin, scoped to the credential's own project), and
// returns a ready [Cloud]. The endpoint-catalog interface defaults
// to "public" — scenariotest is an operator-facing tool, not a
// compute-node agent. log (nil = discard) receives one [LevelTrace]
// line per API call.
func NewOpenStack(ctx context.Context, oc OpenStackCreds, log *slog.Logger) (*OpenStack, error) {
	creds, err := oc.ResolveCredentials()
	if err != nil {
		return nil, err
	}
	eo, err := creds.EndpointOpts("public")
	if err != nil {
		return nil, fmt.Errorf("openstack: %w", err)
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	o := &OpenStack{
		creds:   creds,
		timeout: oc.RequestTimeout,
		eo:      eo,
		log:     log,
		scoped:  map[string]*scopedClients{},
	}

	provider, err := osclient.Authenticate(ctx, creds)
	if err != nil {
		return nil, fmt.Errorf("openstack: %w", err)
	}
	o.applyTimeout(provider)

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

// applyTimeout caps every request on the provider with the config's
// request_timeout and installs the wire-trace transport. osclient
// deliberately leaves HTTP-client policy to its consumers.
func (o *OpenStack) applyTimeout(provider *gophercloud.ProviderClient) {
	provider.HTTPClient = http.Client{
		Timeout:   o.timeout, // zero = unbounded, as before
		Transport: NewTraceTransport(nil, o.log),
	}
}

// scopedFor returns Network/Compute clients whose token is scoped to
// projectID, minting and caching them on first use. The admin user
// must already hold a role on projectID (see GrantAdminRole).
func (o *OpenStack) scopedFor(ctx context.Context, projectID string) (*scopedClients, error) {
	if sc, ok := o.scoped[projectID]; ok {
		return sc, nil
	}
	provider, err := osclient.AuthenticateProject(ctx, o.creds, projectID)
	if err != nil {
		return nil, fmt.Errorf("openstack: scope to project %s: %w", projectID, err)
	}
	o.applyTimeout(provider)
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
func (o *OpenStack) PortMAC(ctx context.Context, portID string) (string, error) {
	p, err := ports.Get(ctx, o.network, portID).Extract()
	if err != nil {
		return "", fmt.Errorf("openstack: get port %s: %w", portID, err)
	}
	return p.MACAddress, nil
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

// SetRouterGateway replaces a router's external gateway network — the
// re-gateway mutation of the router-regateway scenario. Empty
// externalNetworkID clears the gateway.
func (o *OpenStack) SetRouterGateway(ctx context.Context, projectID, routerID, externalNetworkID string) error {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return err
	}
	var gw *routers.GatewayInfo
	if externalNetworkID != "" {
		gw = &routers.GatewayInfo{NetworkID: externalNetworkID}
	}
	_, err = routers.Update(ctx, sc.network, routerID, routers.UpdateOpts{GatewayInfo: gw}).Extract()
	if err != nil {
		return fmt.Errorf("openstack: set gateway on router %s: %w", routerID, err)
	}
	return nil
}

func (o *OpenStack) CreateServer(ctx context.Context, projectID string, spec ServerSpec) (string, error) {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return "", err
	}
	nics := []servers.Network{{Port: spec.PortID}}
	for _, extra := range spec.ExtraPortIDs {
		nics = append(nics, servers.Network{Port: extra})
	}
	base := servers.CreateOpts{
		Name:             spec.Name,
		FlavorRef:        spec.FlavorID,
		ImageRef:         spec.ImageID,
		Networks:         nics,
		AvailabilityZone: spec.AvailabilityZone,
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

func (o *OpenStack) ServerHost(ctx context.Context, projectID, serverID string) (string, error) {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return "", err
	}
	s, err := servers.Get(ctx, sc.compute, serverID).Extract()
	if err != nil {
		return "", fmt.Errorf("openstack: get server %s: %w", serverID, err)
	}
	if s.Host == "" {
		return "", fmt.Errorf("openstack: server %s exposes no OS-EXT-SRV-ATTR:host (token lacks admin?)", serverID)
	}
	return s.Host, nil
}

func (o *OpenStack) LiveMigrateServer(ctx context.Context, projectID, serverID, targetHost string) error {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return err
	}
	// At the default compute microversion os-migrateLive REQUIRES
	// block_migration and disk_over_commit — omitting them is a 400,
	// not a default (found live). False/false is correct for the
	// shared-storage (CephFS instances dir) clusters this harness
	// targets; a block-migration cluster would need a knob nobody has
	// asked for yet.
	no := false
	opts := servers.LiveMigrateOpts{BlockMigration: &no, DiskOverCommit: &no}
	if targetHost != "" {
		opts.Host = &targetHost
	}
	if err := servers.LiveMigrate(ctx, sc.compute, serverID, opts).ExtractErr(); err != nil {
		return fmt.Errorf("openstack: live-migrate server %s: %w", serverID, err)
	}
	return nil
}

func (o *OpenStack) AttachInterface(ctx context.Context, projectID, serverID, portID string) error {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return err
	}
	opts := attachinterfaces.CreateOpts{PortID: portID}
	if _, err := attachinterfaces.Create(ctx, sc.compute, serverID, opts).Extract(); err != nil {
		return fmt.Errorf("openstack: attach port %s to server %s: %w", portID, serverID, err)
	}
	return nil
}

func (o *OpenStack) DetachInterface(ctx context.Context, projectID, serverID, portID string) error {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return err
	}
	if err := attachinterfaces.Delete(ctx, sc.compute, serverID, portID).ExtractErr(); err != nil {
		return fmt.Errorf("openstack: detach port %s from server %s: %w", portID, serverID, err)
	}
	return nil
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

// --- teardown ---

// ignoreNotFound swallows 404s so deletes are idempotent: removing a
// resource that is already gone is success, and a re-run of `down`
// converges instead of failing on the survivors of a partial pass.
func ignoreNotFound(err error) error {
	if err == nil || gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
		return nil
	}
	return err
}

func (o *OpenStack) DeleteFIP(ctx context.Context, projectID, id string) error {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return err
	}
	if err := ignoreNotFound(floatingips.Delete(ctx, sc.network, id).ExtractErr()); err != nil {
		return fmt.Errorf("openstack: delete floating ip %s: %w", id, err)
	}
	return nil
}

func (o *OpenStack) DeleteServer(ctx context.Context, projectID, id string) error {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return err
	}
	if err := ignoreNotFound(servers.Delete(ctx, sc.compute, id).ExtractErr()); err != nil {
		return fmt.Errorf("openstack: delete server %s: %w", id, err)
	}
	return nil
}

func (o *OpenStack) WaitServerGone(ctx context.Context, projectID, id string) error {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return err
	}
	ticker := time.NewTicker(serverPollInterval)
	defer ticker.Stop()
	for {
		_, err := servers.Get(ctx, sc.compute, id).Extract()
		if gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("openstack: poll server %s: %w", id, err)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("openstack: server %s still present at deadline: %w", id, ctx.Err())
		case <-ticker.C:
		}
	}
}

func (o *OpenStack) DeletePort(ctx context.Context, projectID, id string) error {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return err
	}
	if err := ignoreNotFound(ports.Delete(ctx, sc.network, id).ExtractErr()); err != nil {
		return fmt.Errorf("openstack: delete port %s: %w", id, err)
	}
	return nil
}

func (o *OpenStack) ClearRouterRoutes(ctx context.Context, projectID, routerID string) error {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return err
	}
	// Must be a non-nil empty slice: it marshals to "routes": [], which
	// clears. A nil slice would send "routes": null and leave them —
	// and that only ever surfaces live, as a 409 on the next detach.
	empty := []routers.Route{}
	_, err = routers.Update(ctx, sc.network, routerID, routers.UpdateOpts{Routes: &empty}).Extract()
	if err := ignoreNotFound(err); err != nil {
		return fmt.Errorf("openstack: clear routes on router %s: %w", routerID, err)
	}
	return nil
}

func (o *OpenStack) RemoveRouterInterface(ctx context.Context, projectID, routerID, subnetID, portID string) error {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return err
	}
	_, err = routers.RemoveInterface(ctx, sc.network, routerID, routers.RemoveInterfaceOpts{
		SubnetID: subnetID,
		PortID:   portID,
	}).Extract()
	if err := ignoreNotFound(err); err != nil {
		return fmt.Errorf("openstack: remove interface (router %s, subnet %q, port %q): %w", routerID, subnetID, portID, err)
	}
	return nil
}

func (o *OpenStack) DeleteRouter(ctx context.Context, projectID, id string) error {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return err
	}
	if err := ignoreNotFound(routers.Delete(ctx, sc.network, id).ExtractErr()); err != nil {
		return fmt.Errorf("openstack: delete router %s: %w", id, err)
	}
	return nil
}

// ListNetworkPorts uses the admin network client: the residual ports
// it exists to find (platform-created, e.g. cube:mgr) belong to other
// projects and are invisible to a scenario-project-scoped token.
func (o *OpenStack) ListNetworkPorts(ctx context.Context, networkID string) ([]string, error) {
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

// ListProjectServers lists servers through a token scoped to
// projectID, so the returned set is exactly that project's servers —
// never another tenant's. It does no name filtering: `down` owns the
// exact-prefix match, keeping the collision-safety discipline in one
// place. Backs the residual server sweep for a boot Nova accepted in
// the create→save window.
func (o *OpenStack) ListProjectServers(ctx context.Context, projectID string) ([]ServerRef, error) {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return nil, err
	}
	pages, err := servers.List(sc.compute, servers.ListOpts{}).AllPages(ctx)
	if err != nil {
		return nil, fmt.Errorf("openstack: list servers in project %s: %w", projectID, err)
	}
	all, err := servers.ExtractServers(pages)
	if err != nil {
		return nil, fmt.Errorf("openstack: extract servers: %w", err)
	}
	refs := make([]ServerRef, 0, len(all))
	for _, s := range all {
		refs = append(refs, ServerRef{ID: s.ID, Name: s.Name})
	}
	return refs, nil
}

func (o *OpenStack) DeleteSubnet(ctx context.Context, projectID, id string) error {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return err
	}
	if err := ignoreNotFound(subnets.Delete(ctx, sc.network, id).ExtractErr()); err != nil {
		return fmt.Errorf("openstack: delete subnet %s: %w", id, err)
	}
	return nil
}

func (o *OpenStack) DeleteNetwork(ctx context.Context, projectID, id string) error {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return err
	}
	if err := ignoreNotFound(networks.Delete(ctx, sc.network, id).ExtractErr()); err != nil {
		return fmt.Errorf("openstack: delete network %s: %w", id, err)
	}
	return nil
}
