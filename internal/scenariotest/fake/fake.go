// Package fake is the harness's shared test double: an in-memory
// [scenariotest.Cloud] that models the Neutron/Nova behaviour the
// phases actually depend on (floating-IP reachability, port binding,
// router-route ordering), plus the matching MetricsSource and VMExec.
//
// It lives in its own package because four of the phase packages test
// against the same fake; keeping one model of the cloud means a
// behaviour the fake gets wrong is wrong in one place, not five.
package fake

import (
	"context"
	"fmt"
	"strings"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// Env is shared mutable state between the fake scenariotest.Cloud and fake
// [scenariotest.MetricsSource] so the attach gate sees taps appear as VMs boot.
type Env struct {
	BaseAttached float64
	Booted       int // CreateServer increments; one tap per boot
	Failures     float64
}

// Cloud is a recording [scenariotest.Cloud]: lookups return configured IDs,
// creates append to typed slices and hand back synthetic IDs. It also
// models Neutron's floating-IP reachability rule — a FIP only
// associates when a router with a gateway on the FIP's external
// network has an interface on the port's subnet — so a scenario whose
// topology can't carry FIPs fails here the same way it would live.
type Cloud struct {
	Env *Env

	ExtNetID string
	Hyps     []string
	// projects already present in Keystone (mangled name → id).
	PreProjects map[string]string
	// findErrs injects lookup failures by kind (image/flavor/keypair/
	// secgroup/extnet) for preflight tests.
	FindErrs map[string]error

	Seq             int
	CreatedProjects []string
	Grants          []string
	Nets            []scenariotest.NetworkSpec
	Subs            []scenariotest.SubnetSpec
	Rtrs            []scenariotest.RouterSpec
	Ifaces          []IfaceRec
	Routes          []RouteRec
	Ports           []scenariotest.PortSpec
	Servers         []scenariotest.ServerSpec
	ServerIDs       []string
	Hosts           map[string]string // server id → current compute host
	Migrations      []string          // "srv:from→to" in call order
	// live-server model: CreateServer records these so the residual
	// sweep can list a project's servers by name and DeletePort can
	// refuse a still-bound port (both keyed by server id).
	ServerName       map[string]string   // id → mangled name
	ServerProject    map[string]string   // id → project it booted in
	ServerPort       map[string]string   // id → primary port it sits on
	ServerExtraPorts map[string][]string // id → extra NIC ports (multi-homed VMs)
	// hotAttached models Nova os-interface state: port id → server id
	// for ports hot-plugged after boot ([scenariotest.Cloud.AttachInterface]); a
	// bound port refuses deletion exactly like a boot port.
	HotAttached map[string]string
	IfaceOps    []string // "attach:<srv>:<port>" / "detach:<srv>:<port>" in call order
	Fips        []scenariotest.FIPCreateSpec
	FipIDs      []string

	// Octavia model. LBs/Listeners/Pools/Members record creates in call
	// order; LBAmphorae is the read-back ListAmphorae serves, seeded per
	// load balancer at create time so an ACTIVE_STANDBY flavor yields
	// two. LBDeleted records cascade deletes, and LBFlavorID is what
	// FindLBFlavor resolves (empty = "no such flavor", which is how a
	// test drives the SKIPPED path).
	LBs        []scenariotest.LBSpec
	LBIDs      []string
	Listeners  []scenariotest.ListenerSpec
	Pools      []scenariotest.PoolSpec
	Members    []scenariotest.MemberSpec
	LBAmphorae map[string][]scenariotest.AmphoraRef
	LBDeleted  []string
	LBFlavorID string
	// HAFlavorIDs marks flavor ids whose topology is ACTIVE_STANDBY, so
	// CreateLoadBalancer knows to seed two Amphorae.
	HAFlavorIDs map[string]bool

	// reachability model (live IDs)
	PortSubnet    map[string]string          // port id → subnet id
	RouterExt     map[string]string          // router id → ext network id
	RouterSubnets map[string]map[string]bool // router id → attached subnet ids
	// routerRoutes is the router's live static routes; a non-empty set
	// makes RemoveRouterInterface refuse (see there), so teardown must
	// clear routes first.
	RouterRoutes map[string][]scenariotest.RouteSpec // router id → current extra routes

	// MAC model: every port gets a MAC (explicit from the spec, or a
	// synthetic assignment), unique per network like real Neutron.
	MACs        map[string]string // port id → mac
	PortName    map[string]string // port id → spec name
	PortProject map[string]string // port id → project
	PortNet     map[string]string // port id → network id

	// teardown model: residualPorts seeds platform-created ports
	// (cube:mgr) per network id; deletions and detaches append to
	// downOps in call order ("fip:<id>", "server:<id>", …).
	ResidualPorts map[string][]string
	DownOps       []string
	Deleted       map[string]bool
	FailDown      map[string]bool // ops (kind:id) that refuse to delete
}

type IfaceRec struct{ RouterID, SubnetID, PortID string }
type RouteRec struct {
	RouterID string
	Routes   []scenariotest.RouteSpec
}

func NewCloud(env *Env) *Cloud {
	return &Cloud{
		Env: env, ExtNetID: "ext-net-real", Hyps: []string{"compute-0"},
		PreProjects: map[string]string{}, FindErrs: map[string]error{},
		PortSubnet: map[string]string{}, RouterExt: map[string]string{},
		RouterSubnets: map[string]map[string]bool{},
		RouterRoutes:  map[string][]scenariotest.RouteSpec{},
		MACs:          map[string]string{}, PortNet: map[string]string{},
		PortName:    map[string]string{},
		PortProject: map[string]string{},
		ServerName:  map[string]string{}, ServerProject: map[string]string{},
		ServerPort:       map[string]string{},
		ServerExtraPorts: map[string][]string{},
		ResidualPorts:    map[string][]string{}, Deleted: map[string]bool{},
		Hosts:       map[string]string{},
		HotAttached: map[string]string{},
	}
}

func (c *Cloud) id(kind string) string { c.Seq++; return fmt.Sprintf("%s-%d", kind, c.Seq) }

func (c *Cloud) FindImage(context.Context, string) (string, error) {
	return "img-1", c.FindErrs["image"]
}
func (c *Cloud) FindFlavor(context.Context, string) (string, error) {
	return "flv-1", c.FindErrs["flavor"]
}
func (c *Cloud) CheckKeypair(context.Context, string) error { return c.FindErrs["keypair"] }
func (c *Cloud) FindSecGroup(context.Context, string) (string, error) {
	return "sg-1", c.FindErrs["secgroup"]
}
func (c *Cloud) FindExternalNetwork(context.Context, string) (string, error) {
	return c.ExtNetID, c.FindErrs["extnet"]
}
func (c *Cloud) Hypervisors(context.Context) ([]string, error) { return c.Hyps, nil }

func (c *Cloud) FindProject(_ context.Context, name string) (string, bool, error) {
	if id, ok := c.PreProjects[name]; ok {
		return id, true, nil
	}
	return "", false, nil
}
func (c *Cloud) CreateProject(_ context.Context, name string) (string, error) {
	c.CreatedProjects = append(c.CreatedProjects, name)
	return c.id("proj"), nil
}
func (c *Cloud) GrantAdminRole(_ context.Context, projectID string) error {
	c.Grants = append(c.Grants, projectID)
	return nil
}
func (c *Cloud) CreateNetwork(_ context.Context, _ string, spec scenariotest.NetworkSpec) (string, error) {
	c.Nets = append(c.Nets, spec)
	return c.id("net"), nil
}
func (c *Cloud) CreateSubnet(_ context.Context, _ string, spec scenariotest.SubnetSpec) (string, error) {
	c.Subs = append(c.Subs, spec)
	return c.id("sub"), nil
}
func (c *Cloud) CreateRouter(_ context.Context, _ string, spec scenariotest.RouterSpec) (string, error) {
	c.Rtrs = append(c.Rtrs, spec)
	id := c.id("rtr")
	c.RouterExt[id] = spec.ExternalNetworkID
	c.RouterSubnets[id] = map[string]bool{}
	return id, nil
}

// CreatePort models Neutron's per-network MAC uniqueness: an explicit
// MACAddress already used by a live port on the same network is
// rejected (MacAddressInUse), otherwise a synthetic MAC is assigned.
func (c *Cloud) CreatePort(_ context.Context, proj string, spec scenariotest.PortSpec) (string, error) {
	if spec.MACAddress != "" {
		for pid, mac := range c.MACs {
			if mac == spec.MACAddress && c.PortNet[pid] == spec.NetworkID && !c.Deleted["port:"+pid] {
				return "", fmt.Errorf("fake neutron: mac %s already in use on network %s", spec.MACAddress, spec.NetworkID)
			}
		}
	}
	c.Ports = append(c.Ports, spec)
	id := c.id("port")
	c.PortSubnet[id] = spec.SubnetID
	c.PortNet[id] = spec.NetworkID
	c.PortProject[id] = proj
	c.PortName[id] = spec.Name
	if spec.MACAddress != "" {
		c.MACs[id] = spec.MACAddress
	} else {
		c.MACs[id] = fmt.Sprintf("fa:16:3e:00:00:%02x", c.Seq)
	}
	return id, nil
}

func (c *Cloud) PortMAC(_ context.Context, portID string) (string, error) {
	mac, ok := c.MACs[portID]
	if !ok {
		return "", fmt.Errorf("fake neutron: no port %s", portID)
	}
	return mac, nil
}
func (c *Cloud) AddRouterInterface(_ context.Context, _, routerID, subnetID, portID string) error {
	c.Ifaces = append(c.Ifaces, IfaceRec{routerID, subnetID, portID})
	if subnetID == "" {
		subnetID = c.PortSubnet[portID]
	}
	c.RouterSubnets[routerID][subnetID] = true
	return nil
}
func (c *Cloud) SetRouterRoutes(_ context.Context, _, routerID string, routes []scenariotest.RouteSpec) error {
	c.Routes = append(c.Routes, RouteRec{routerID, routes})
	c.RouterRoutes[routerID] = routes
	return nil
}

func (c *Cloud) SetRouterGateway(_ context.Context, _, routerID, externalNetworkID string) error {
	if externalNetworkID == "" {
		delete(c.RouterExt, routerID)
	} else {
		c.RouterExt[routerID] = externalNetworkID
	}
	return nil
}

// CreateServer models placement the way Nova does: an AZ host pin
// ("nova:<host>") lands the server there; unpinned servers go to the
// first hypervisor (a deterministic stand-in for the scheduler).
func (c *Cloud) CreateServer(_ context.Context, proj string, spec scenariotest.ServerSpec) (string, error) {
	c.Servers = append(c.Servers, spec)
	// One tap per bound port: a single-NIC boot is +1 (unchanged); a
	// multi-homed boot adds one per extra NIC, so the attach gauge the
	// metrics fake derives from this matches the gate's per-tap target.
	c.Env.Booted += 1 + len(spec.ExtraPortIDs)
	id := c.id("srv")
	c.ServerIDs = append(c.ServerIDs, id)
	host := strings.TrimPrefix(spec.AvailabilityZone, "nova:")
	if host == spec.AvailabilityZone { // no pin
		host = ""
		if len(c.Hyps) > 0 {
			host = c.Hyps[0]
		}
	}
	c.Hosts[id] = host
	c.ServerName[id] = spec.Name
	c.ServerProject[id] = proj
	c.ServerPort[id] = spec.PortID
	// Extra NICs bind to this server too — a bound port refuses
	// deletion until the server is gone, same as the primary.
	c.ServerExtraPorts[id] = append(c.ServerExtraPorts[id], spec.ExtraPortIDs...)
	return id, nil
}
func (c *Cloud) WaitServerActive(context.Context, string, string) error { return nil }

func (c *Cloud) ServerHost(_ context.Context, _, serverID string) (string, error) {
	host, ok := c.Hosts[serverID]
	if !ok {
		return "", fmt.Errorf("fake nova: no server %s", serverID)
	}
	return host, nil
}

// LiveMigrateServer mirrors Nova's contract: an explicit target must
// be a known hypervisor; no target lets the "scheduler" pick the
// first hypervisor that differs from the current host.
func (c *Cloud) LiveMigrateServer(_ context.Context, _, serverID, targetHost string) error {
	from, ok := c.Hosts[serverID]
	if !ok {
		return fmt.Errorf("fake nova: no server %s", serverID)
	}
	to := targetHost
	if to == "" {
		for _, h := range c.Hyps {
			if h != from {
				to = h
				break
			}
		}
		if to == "" {
			return fmt.Errorf("fake nova: no other hypervisor to migrate %s to", serverID)
		}
	} else {
		known := false
		for _, h := range c.Hyps {
			if h == to {
				known = true
				break
			}
		}
		if !known {
			return fmt.Errorf("fake nova: no hypervisor %q", to)
		}
	}
	c.Hosts[serverID] = to
	c.Migrations = append(c.Migrations, serverID+":"+from+"→"+to)
	return nil
}

// CreateFIP enforces the same reachability rule as Neutron: the FIP's
// external network must be the gateway of a router that also has an
// interface on the port's subnet.
func (c *Cloud) CreateFIP(_ context.Context, _ string, spec scenariotest.FIPCreateSpec) (string, string, error) {
	subnet := c.PortSubnet[spec.PortID]
	reachable := false
	for routerID, ext := range c.RouterExt {
		if ext == spec.ExternalNetworkID && c.RouterSubnets[routerID][subnet] {
			reachable = true
			break
		}
	}
	if !reachable {
		return "", "", fmt.Errorf("fake neutron: external network %s is not reachable from subnet %s (no gatewayed router)", spec.ExternalNetworkID, subnet)
	}
	c.Fips = append(c.Fips, spec)
	id := c.id("fip")
	c.FipIDs = append(c.FipIDs, id)
	return id, fmt.Sprintf("203.0.113.%d", len(c.Fips)), nil
}

// --- Octavia fakes ---

// FindLBFlavor resolves the configured load-balancer flavor. An unset
// LBFlavorID means the cluster has none staged — the condition that
// makes an ACTIVE_STANDBY scenario SKIPPED rather than failed.
func (c *Cloud) FindLBFlavor(_ context.Context, name string) (string, error) {
	if err := c.FindErrs["lb_flavor"]; err != nil {
		return "", err
	}
	if c.LBFlavorID == "" {
		return "", fmt.Errorf("fake octavia: lb flavor %q not found", name)
	}
	return c.LBFlavorID, nil
}

// CreateLoadBalancer records the spec and seeds the Amphorae
// ListAmphorae will report: two for an ACTIVE_STANDBY flavor, one
// otherwise. Each carries a distinct ComputeID, because that is the key
// the attribution join uses to find an Amphora's ports.
func (c *Cloud) CreateLoadBalancer(_ context.Context, _ string, spec scenariotest.LBSpec) (string, string, error) {
	c.LBs = append(c.LBs, spec)
	id := c.id("lb")
	c.LBIDs = append(c.LBIDs, id)
	count := 1
	if c.HAFlavorIDs[spec.FlavorID] {
		count = 2
	}
	if c.LBAmphorae == nil {
		c.LBAmphorae = map[string][]scenariotest.AmphoraRef{}
	}
	roles := []string{"MASTER", "BACKUP"}
	for i := 0; i < count; i++ {
		role := "STANDALONE"
		if count > 1 {
			role = roles[i]
		}
		c.LBAmphorae[id] = append(c.LBAmphorae[id], scenariotest.AmphoraRef{
			ID:          fmt.Sprintf("%s-amp-%d", id, i),
			ComputeID:   fmt.Sprintf("%s-compute-%d", id, i),
			LBNetworkIP: fmt.Sprintf("10.254.0.%d", 10+len(c.LBAmphorae)*2+i),
			Role:        role,
		})
	}
	return id, fmt.Sprintf("10.0.99.%d", len(c.LBs)), nil
}

func (c *Cloud) CreateListener(_ context.Context, _ string, spec scenariotest.ListenerSpec) (string, error) {
	c.Listeners = append(c.Listeners, spec)
	return c.id("listener"), nil
}

func (c *Cloud) CreatePool(_ context.Context, _ string, spec scenariotest.PoolSpec) (string, error) {
	c.Pools = append(c.Pools, spec)
	return c.id("pool"), nil
}

func (c *Cloud) CreateMember(_ context.Context, _ string, spec scenariotest.MemberSpec) (string, error) {
	c.Members = append(c.Members, spec)
	return c.id("member"), nil
}

// WaitLBActive is instant: the fake has no provisioning state machine.
func (c *Cloud) WaitLBActive(_ context.Context, _, _ string) error { return nil }

func (c *Cloud) ListAmphorae(_ context.Context, lbID string) ([]scenariotest.AmphoraRef, error) {
	return c.LBAmphorae[lbID], nil
}

// DeleteLoadBalancer records the cascade and drops the Amphorae, so a
// teardown test can assert the Amphora VMs were reclaimed through
// Octavia rather than by deleting their ports.
func (c *Cloud) DeleteLoadBalancer(_ context.Context, _, id string) error {
	c.LBDeleted = append(c.LBDeleted, id)
	delete(c.LBAmphorae, id)
	return nil
}

// --- teardown fakes: record in order, idempotent like the real
// 404-tolerant implementations ---

// down honors ctx like the real gophercloud client would — the
// interrupt tests depend on a cancelled context failing deletes.
func (c *Cloud) down(ctx context.Context, kind, id string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("fake neutron: %s %s: %w", kind, id, err)
	}
	if c.FailDown[kind+":"+id] {
		return fmt.Errorf("fake neutron: %s %s refuses to delete", kind, id)
	}
	if !c.Deleted[kind+":"+id] {
		c.Deleted[kind+":"+id] = true
		c.DownOps = append(c.DownOps, kind+":"+id)
	}
	return nil
}
func (c *Cloud) DeleteFIP(ctx context.Context, _, id string) error {
	return c.down(ctx, "fip", id)
}
func (c *Cloud) DeleteServer(ctx context.Context, _, id string) error {
	return c.down(ctx, "server", id)
}
func (c *Cloud) WaitServerGone(context.Context, string, string) error {
	return nil
}
func (c *Cloud) DeletePort(ctx context.Context, _, id string) error {
	// Neutron refuses (PortInUse) to delete a port a live server still
	// sits on. Models the create→save-race case: the VM's port is
	// recorded, so `down` reaches it in the port loop — and must fail
	// there unless the residual server sweep tore the VM down first.
	for sid, pid := range c.ServerPort {
		if pid == id && !c.Deleted["server:"+sid] {
			return fmt.Errorf("fake neutron: port %s in use by server %s", id, sid)
		}
	}
	for sid, extras := range c.ServerExtraPorts {
		if c.Deleted["server:"+sid] {
			continue
		}
		for _, pid := range extras {
			if pid == id {
				return fmt.Errorf("fake neutron: port %s in use by server %s (extra NIC)", id, sid)
			}
		}
	}
	// A hot-plugged port is just as bound; it must be detached first.
	if sid, ok := c.HotAttached[id]; ok && !c.Deleted["server:"+sid] {
		return fmt.Errorf("fake neutron: port %s in use by server %s (hot-attached)", id, sid)
	}
	return c.down(ctx, "port", id)
}

// AttachInterface mirrors Nova os-interface attach: the server and
// port must exist and the port must be unbound.
func (c *Cloud) AttachInterface(_ context.Context, _, serverID, portID string) error {
	if _, ok := c.Hosts[serverID]; !ok || c.Deleted["server:"+serverID] {
		return fmt.Errorf("fake nova: no server %s", serverID)
	}
	if _, ok := c.MACs[portID]; !ok || c.Deleted["port:"+portID] {
		return fmt.Errorf("fake nova: no port %s", portID)
	}
	if _, bound := c.HotAttached[portID]; bound {
		return fmt.Errorf("fake nova: port %s already attached", portID)
	}
	for sid, pid := range c.ServerPort {
		if pid == portID && !c.Deleted["server:"+sid] {
			return fmt.Errorf("fake nova: port %s already attached (boot port of %s)", portID, sid)
		}
	}
	c.HotAttached[portID] = serverID
	c.IfaceOps = append(c.IfaceOps, "attach:"+serverID+":"+portID)
	return nil
}

// DetachInterface mirrors Nova os-interface detach: the binding must
// exist; the port survives, unbound.
func (c *Cloud) DetachInterface(_ context.Context, _, serverID, portID string) error {
	if c.HotAttached[portID] != serverID {
		return fmt.Errorf("fake nova: port %s is not attached to server %s", portID, serverID)
	}
	delete(c.HotAttached, portID)
	c.IfaceOps = append(c.IfaceOps, "detach:"+serverID+":"+portID)
	return nil
}

// ClearRouterRoutes unpins only once the call itself succeeds: a
// failed clear (cancelled ctx, injected failure) never reached the
// server, so the routes — and the pin they hold — must survive it.
func (c *Cloud) ClearRouterRoutes(ctx context.Context, _, routerID string) error {
	if err := c.down(ctx, "routes", routerID); err != nil {
		return err
	}
	delete(c.RouterRoutes, routerID)
	return nil
}
func (c *Cloud) RemoveRouterInterface(ctx context.Context, _, routerID, subnetID, portID string) error {
	// Neutron refuses (RouterInterfaceInUseByRoute) while a static
	// route pins an interface. Over-approximated on purpose: any route
	// blocks every interface of the router, where Neutron pins only the
	// one its next-hop sits on. Stricter than live, so it can demand a
	// clear the cluster wouldn't — never hide one it would.
	if len(c.RouterRoutes[routerID]) > 0 {
		return fmt.Errorf("fake neutron: router %s interface in use by route", routerID)
	}
	return c.down(ctx, "detach", routerID+"/"+subnetID+portID)
}
func (c *Cloud) DeleteRouter(ctx context.Context, _, id string) error {
	return c.down(ctx, "router", id)
}
func (c *Cloud) ListNetworkPorts(_ context.Context, networkID string) ([]string, error) {
	var out []string
	for _, id := range c.ResidualPorts[networkID] {
		if !c.Deleted["port:"+id] {
			out = append(out, id)
		}
	}
	return out, nil
}
func (c *Cloud) ListProjectServers(_ context.Context, projectID string) ([]scenariotest.ServerRef, error) {
	var out []scenariotest.ServerRef
	for _, id := range c.ServerIDs {
		if c.ServerProject[id] == projectID && !c.Deleted["server:"+id] {
			out = append(out, scenariotest.ServerRef{ID: id, Name: c.ServerName[id]})
		}
	}
	return out, nil
}
func (c *Cloud) DeleteSubnet(ctx context.Context, _, id string) error {
	return c.down(ctx, "subnet", id)
}
func (c *Cloud) DeleteNetwork(ctx context.Context, _, id string) error {
	if rem, _ := c.ListNetworkPorts(context.Background(), id); len(rem) > 0 {
		return fmt.Errorf("fake neutron: network %s has %d port(s) in use", id, len(rem))
	}
	return c.down(ctx, "network", id)
}

// Metrics reports an attached-interface count that grows as the
// fake scenariotest.Cloud boots servers, so the attach gate goes green.
type Metrics struct {
	InstantMACs
	Env *Env
}

func (m *Metrics) Scrape(context.Context, string) (scenariotest.ScrapeResult, error) {
	return scenariotest.ScrapeResult{
		Present:            map[string]bool{scenariotest.MetricBytesTotal: true, scenariotest.MetricAttachedInterfaces: true},
		AttachedInterfaces: m.Env.BaseAttached + float64(m.Env.Booted),
		AttachFailures:     m.Env.Failures,
	}, nil
}

func Config() scenariotest.Config {
	cfg := scenariotest.Defaults()
	cfg.OpenStack = scenariotest.OpenStackCreds{AuthURL: "http://k", Username: "admin", Password: "p", ProjectName: "admin"}
	cfg.Cluster.Agents = []scenariotest.AgentConfig{{Host: "compute-0", MetricsURL: "http://compute-0:9100/metrics"}}
	cfg.Prerequisites = scenariotest.Prereqs{ImageName: "img", FlavorName: "flv", KeypairName: "kp", SecGroupName: "sg", ExternalNetworkName: "ext"}
	cfg.SSH.KeyPath = "/k"
	return cfg
}

// Exec records every (addr, command) pair. Commands matching a
// failSubstring return an error.
type Exec struct {
	Calls []ExecCall
	Fail  string
}

type ExecCall struct{ Addr, Command string }

func (f *Exec) Run(_ context.Context, addr, command string) (string, error) {
	f.Calls = append(f.Calls, ExecCall{addr, command})
	if f.Fail != "" && strings.Contains(command, f.Fail) {
		return "", fmt.Errorf("injected failure for %q", command)
	}
	return "", nil
}

// InstantMACs satisfies the LookupMAC half of [scenariotest.MetricsSource] for
// fakes whose tests don't exercise the MAC-learn gate: every MAC is
// already learned. The empty TenantID is tenant-agnostic to the gate.
type InstantMACs struct{}

func (InstantMACs) LookupMAC(context.Context, string, string) (scenariotest.MACLookup, error) {
	return scenariotest.MACLookup{Found: true}, nil
}

func (InstantMACs) LookupFlows(context.Context, string, string) ([]scenariotest.FlowRow, error) {
	return nil, nil
}

// SameTenantScenario mirrors the registered twovms-same-tenant
// topology, gatewayed router included (FIP reachability).
func SameTenantScenario() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.1.0/24", "10.0.1.1").
		VM("vm-a", "T1", "10.0.1.5").
		VM("vm-b", "T1", "10.0.1.6")
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").Attach("sub-T1", "10.0.1.1").ExternalGateway("net-ext")
	return &scenariotest.Scenario{Name: "same", Builder: b}
}

// HealthyMetrics reports a healthy cluster: a fixed attached-tap count,
// no attach failures, and every MAC already learned.
type HealthyMetrics struct {
	InstantMACs
	Attached float64
	Failures float64
	Bytes    []scenariotest.BytesSample
	Servers  []scenariotest.ServerSample
}

func (m HealthyMetrics) Scrape(context.Context, string) (scenariotest.ScrapeResult, error) {
	return scenariotest.ScrapeResult{
		Present:            map[string]bool{scenariotest.MetricBytesTotal: true, scenariotest.MetricAttachedInterfaces: true},
		AttachedInterfaces: m.Attached,
		AttachFailures:     m.Failures,
		Bytes:              m.Bytes,
		Servers:            m.Servers,
	}, nil
}

// ExtPathScenario mirrors the registered multi-external-path scenario:
// a created second external network, a second router for FIP
// reachability, and the associate → assert-anomaly → drive →
// delete-fip script.
// ExtPathTopology is the multi-external-path topology: one tenant
// network reachable through three routers — a gatewayed one on the
// provider external network, a second on a created external network,
// and one with no gateway at all. The steps that exercise it live with
// the step vocabulary; this is the declaration alone.
func ExtPathTopology() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.11.0/24", "10.0.11.1").
		VM("vm-a", "T1", "10.0.11.5")
	b.ExternalNetwork("net-ext", "admin")
	b.ExternalNetwork("net-ext2", "T1").
		Subnet("sub-ext2", "172.24.99.0/24", "172.24.99.1")
	b.Router("r-T1", "T1").Attach("sub-T1", "10.0.11.1").ExternalGateway("net-ext")
	b.Router("r-ext2", "T1").Attach("sub-T1", "10.0.11.254").ExternalGateway("net-ext2")
	b.Router("r-nogw", "T1").Attach("sub-T1", "10.0.11.253")

	return &scenariotest.Scenario{
		Name:               "multi-external-path",
		Builder:            b,
		CreateExternalNets: []string{"net-ext2"},
	}
}

// PerNode is a [scenariotest.MetricsSource] that answers per agent URL
// — how a test gives two agents different series without standing up
// two servers.
type PerNode struct {
	InstantMACs
	ByURL map[string]scenariotest.ScrapeResult
}

func (p PerNode) Scrape(_ context.Context, url string) (scenariotest.ScrapeResult, error) {
	return p.ByURL[url], nil
}
