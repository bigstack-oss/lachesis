package scenariotest

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// fakeEnv is shared mutable state between the fake Cloud and fake
// MetricsSource so the attach gate sees taps appear as VMs boot.
type fakeEnv struct {
	baseAttached float64
	booted       int // CreateServer increments; one tap per boot
	failures     float64
}

// fakeCloud is a recording [Cloud]: lookups return configured IDs,
// creates append to typed slices and hand back synthetic IDs. It also
// models Neutron's floating-IP reachability rule — a FIP only
// associates when a router with a gateway on the FIP's external
// network has an interface on the port's subnet — so a scenario whose
// topology can't carry FIPs fails here the same way it would live.
type fakeCloud struct {
	env *fakeEnv

	extNetID string
	hyps     []string
	// projects already present in Keystone (mangled name → id).
	preProjects map[string]string
	// findErrs injects lookup failures by kind (image/flavor/keypair/
	// secgroup/extnet) for preflight tests.
	findErrs map[string]error

	seq             int
	createdProjects []string
	grants          []string
	nets            []NetworkSpec
	subs            []SubnetSpec
	rtrs            []RouterSpec
	ifaces          []ifaceRec
	routes          []routeRec
	ports           []PortSpec
	servers         []ServerSpec
	serverIDs       []string
	fips            []FIPCreateSpec
	fipIDs          []string

	// reachability model (live IDs)
	portSubnet    map[string]string          // port id → subnet id
	routerExt     map[string]string          // router id → ext network id
	routerSubnets map[string]map[string]bool // router id → attached subnet ids

	// MAC model: every port gets a MAC (explicit from the spec, or a
	// synthetic assignment), unique per network like real Neutron.
	portMAC     map[string]string // port id → mac
	portName    map[string]string // port id → spec name
	portProject map[string]string // port id → project
	portNet     map[string]string // port id → network id

	// teardown model: residualPorts seeds platform-created ports
	// (cube:mgr) per network id; deletions and detaches append to
	// downOps in call order ("fip:<id>", "server:<id>", …).
	residualPorts map[string][]string
	downOps       []string
	deleted       map[string]bool
	failDown      map[string]bool // ops (kind:id) that refuse to delete
}

type ifaceRec struct{ routerID, subnetID, portID string }
type routeRec struct {
	routerID string
	routes   []RouteSpec
}

func newFakeCloud(env *fakeEnv) *fakeCloud {
	return &fakeCloud{
		env: env, extNetID: "ext-net-real", hyps: []string{"compute-0"},
		preProjects: map[string]string{}, findErrs: map[string]error{},
		portSubnet: map[string]string{}, routerExt: map[string]string{},
		routerSubnets: map[string]map[string]bool{},
		portMAC:       map[string]string{}, portNet: map[string]string{},
		portName:      map[string]string{},
		portProject:   map[string]string{},
		residualPorts: map[string][]string{}, deleted: map[string]bool{},
	}
}

func (c *fakeCloud) id(kind string) string { c.seq++; return fmt.Sprintf("%s-%d", kind, c.seq) }

func (c *fakeCloud) FindImage(context.Context, string) (string, error) {
	return "img-1", c.findErrs["image"]
}
func (c *fakeCloud) FindFlavor(context.Context, string) (string, error) {
	return "flv-1", c.findErrs["flavor"]
}
func (c *fakeCloud) CheckKeypair(context.Context, string) error { return c.findErrs["keypair"] }
func (c *fakeCloud) FindSecGroup(context.Context, string) (string, error) {
	return "sg-1", c.findErrs["secgroup"]
}
func (c *fakeCloud) FindExternalNetwork(context.Context, string) (string, error) {
	return c.extNetID, c.findErrs["extnet"]
}
func (c *fakeCloud) Hypervisors(context.Context) ([]string, error) { return c.hyps, nil }

func (c *fakeCloud) FindProject(_ context.Context, name string) (string, bool, error) {
	if id, ok := c.preProjects[name]; ok {
		return id, true, nil
	}
	return "", false, nil
}
func (c *fakeCloud) CreateProject(_ context.Context, name string) (string, error) {
	c.createdProjects = append(c.createdProjects, name)
	return c.id("proj"), nil
}
func (c *fakeCloud) GrantAdminRole(_ context.Context, projectID string) error {
	c.grants = append(c.grants, projectID)
	return nil
}
func (c *fakeCloud) CreateNetwork(_ context.Context, _ string, spec NetworkSpec) (string, error) {
	c.nets = append(c.nets, spec)
	return c.id("net"), nil
}
func (c *fakeCloud) CreateSubnet(_ context.Context, _ string, spec SubnetSpec) (string, error) {
	c.subs = append(c.subs, spec)
	return c.id("sub"), nil
}
func (c *fakeCloud) CreateRouter(_ context.Context, _ string, spec RouterSpec) (string, error) {
	c.rtrs = append(c.rtrs, spec)
	id := c.id("rtr")
	c.routerExt[id] = spec.ExternalNetworkID
	c.routerSubnets[id] = map[string]bool{}
	return id, nil
}

// CreatePort models Neutron's per-network MAC uniqueness: an explicit
// MACAddress already used by a live port on the same network is
// rejected (MacAddressInUse), otherwise a synthetic MAC is assigned.
func (c *fakeCloud) CreatePort(_ context.Context, proj string, spec PortSpec) (string, error) {
	if spec.MACAddress != "" {
		for pid, mac := range c.portMAC {
			if mac == spec.MACAddress && c.portNet[pid] == spec.NetworkID && !c.deleted["port:"+pid] {
				return "", fmt.Errorf("fake neutron: mac %s already in use on network %s", spec.MACAddress, spec.NetworkID)
			}
		}
	}
	c.ports = append(c.ports, spec)
	id := c.id("port")
	c.portSubnet[id] = spec.SubnetID
	c.portNet[id] = spec.NetworkID
	c.portProject[id] = proj
	c.portName[id] = spec.Name
	if spec.MACAddress != "" {
		c.portMAC[id] = spec.MACAddress
	} else {
		c.portMAC[id] = fmt.Sprintf("fa:16:3e:00:00:%02x", c.seq)
	}
	return id, nil
}

func (c *fakeCloud) PortMAC(_ context.Context, portID string) (string, error) {
	mac, ok := c.portMAC[portID]
	if !ok {
		return "", fmt.Errorf("fake neutron: no port %s", portID)
	}
	return mac, nil
}
func (c *fakeCloud) AddRouterInterface(_ context.Context, _, routerID, subnetID, portID string) error {
	c.ifaces = append(c.ifaces, ifaceRec{routerID, subnetID, portID})
	if subnetID == "" {
		subnetID = c.portSubnet[portID]
	}
	c.routerSubnets[routerID][subnetID] = true
	return nil
}
func (c *fakeCloud) SetRouterRoutes(_ context.Context, _, routerID string, routes []RouteSpec) error {
	c.routes = append(c.routes, routeRec{routerID, routes})
	return nil
}
func (c *fakeCloud) CreateServer(_ context.Context, _ string, spec ServerSpec) (string, error) {
	c.servers = append(c.servers, spec)
	c.env.booted++
	id := c.id("srv")
	c.serverIDs = append(c.serverIDs, id)
	return id, nil
}
func (c *fakeCloud) WaitServerActive(context.Context, string, string) error { return nil }

// CreateFIP enforces the same reachability rule as Neutron: the FIP's
// external network must be the gateway of a router that also has an
// interface on the port's subnet.
func (c *fakeCloud) CreateFIP(_ context.Context, _ string, spec FIPCreateSpec) (string, string, error) {
	subnet := c.portSubnet[spec.PortID]
	reachable := false
	for routerID, ext := range c.routerExt {
		if ext == spec.ExternalNetworkID && c.routerSubnets[routerID][subnet] {
			reachable = true
			break
		}
	}
	if !reachable {
		return "", "", fmt.Errorf("fake neutron: external network %s is not reachable from subnet %s (no gatewayed router)", spec.ExternalNetworkID, subnet)
	}
	c.fips = append(c.fips, spec)
	id := c.id("fip")
	c.fipIDs = append(c.fipIDs, id)
	return id, fmt.Sprintf("203.0.113.%d", len(c.fips)), nil
}

// --- teardown fakes: record in order, idempotent like the real
// 404-tolerant implementations ---

// down honors ctx like the real gophercloud client would — the
// interrupt tests depend on a cancelled context failing deletes.
func (c *fakeCloud) down(ctx context.Context, kind, id string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("fake neutron: %s %s: %w", kind, id, err)
	}
	if c.failDown[kind+":"+id] {
		return fmt.Errorf("fake neutron: %s %s refuses to delete", kind, id)
	}
	if !c.deleted[kind+":"+id] {
		c.deleted[kind+":"+id] = true
		c.downOps = append(c.downOps, kind+":"+id)
	}
	return nil
}
func (c *fakeCloud) DeleteFIP(ctx context.Context, _, id string) error {
	return c.down(ctx, "fip", id)
}
func (c *fakeCloud) DeleteServer(ctx context.Context, _, id string) error {
	return c.down(ctx, "server", id)
}
func (c *fakeCloud) WaitServerGone(context.Context, string, string) error {
	return nil
}
func (c *fakeCloud) DeletePort(ctx context.Context, _, id string) error {
	return c.down(ctx, "port", id)
}
func (c *fakeCloud) RemoveRouterInterface(ctx context.Context, _, routerID, subnetID, portID string) error {
	return c.down(ctx, "detach", routerID+"/"+subnetID+portID)
}
func (c *fakeCloud) DeleteRouter(ctx context.Context, _, id string) error {
	return c.down(ctx, "router", id)
}
func (c *fakeCloud) ListNetworkPorts(_ context.Context, networkID string) ([]string, error) {
	var out []string
	for _, id := range c.residualPorts[networkID] {
		if !c.deleted["port:"+id] {
			out = append(out, id)
		}
	}
	return out, nil
}
func (c *fakeCloud) DeleteSubnet(ctx context.Context, _, id string) error {
	return c.down(ctx, "subnet", id)
}
func (c *fakeCloud) DeleteNetwork(ctx context.Context, _, id string) error {
	if rem, _ := c.ListNetworkPorts(context.Background(), id); len(rem) > 0 {
		return fmt.Errorf("fake neutron: network %s has %d port(s) in use", id, len(rem))
	}
	return c.down(ctx, "network", id)
}

// fakeMetrics reports an attached-interface count that grows as the
// fake Cloud boots servers, so the attach gate goes green.
type fakeMetrics struct {
	instantMACs
	env *fakeEnv
}

func (m *fakeMetrics) Scrape(context.Context, string) (ScrapeResult, error) {
	return ScrapeResult{
		Present:            map[string]bool{metricBytesTotal: true, metricAttachedInterfaces: true},
		AttachedInterfaces: m.env.baseAttached + float64(m.env.booted),
		AttachFailures:     m.env.failures,
	}, nil
}

func testConfig() Config {
	cfg := Defaults()
	cfg.OpenStack = OpenStackCreds{AuthURL: "http://k", Username: "admin", Password: "p", ProjectName: "admin"}
	cfg.Cluster.Agents = []AgentConfig{{Host: "compute-0", MetricsURL: "http://compute-0:9100/metrics"}}
	cfg.Prerequisites = Prereqs{ImageName: "img", FlavorName: "flv", KeypairName: "kp", SecGroupName: "sg", ExternalNetworkName: "ext"}
	cfg.SSH.KeyPath = "/k"
	return cfg
}

func realizeFixture(t *testing.T, sc *Scenario) (*fakeCloud, *RunState) {
	t.Helper()
	env := &fakeEnv{baseAttached: 5}
	cloud := newFakeCloud(env)
	rs, err := Realize(context.Background(), RealizeOptions{
		Config:    testConfig(),
		Scenario:  sc,
		RunID:     "run1",
		StatePath: t.TempDir() + "/state.json",
		Cloud:     cloud,
		Metrics:   &fakeMetrics{env: env},
		Log:       slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("Realize: %v", err)
	}
	return cloud, rs
}

// sameTenantScenario mirrors the registered twovms-same-tenant
// topology, gatewayed router included (FIP reachability).
func sameTenantScenario() *Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.1.0/24", "10.0.1.1").
		VM("vm-a", "T1", "10.0.1.5").
		VM("vm-b", "T1", "10.0.1.6")
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").Attach("sub-T1", "10.0.1.1").ExternalGateway("net-ext")
	return &Scenario{Name: "same", Builder: b}
}

func TestRealize_SameTenant(t *testing.T) {
	cloud, rs := realizeFixture(t, sameTenantScenario())

	if len(cloud.nets) != 1 { // ext net resolves to the provider net, never created
		t.Errorf("networks: got %d, want 1", len(cloud.nets))
	}
	if len(cloud.subs) != 1 {
		t.Errorf("subnets: got %d, want 1", len(cloud.subs))
	}
	if len(cloud.rtrs) != 1 || cloud.rtrs[0].ExternalNetworkID != cloud.extNetID {
		t.Errorf("routers: got %+v, want 1 gatewayed to %s", cloud.rtrs, cloud.extNetID)
	}
	if len(cloud.ifaces) != 1 || cloud.ifaces[0].subnetID == "" {
		t.Errorf("router interfaces: got %+v, want 1 subnet-based (gateway) attach", cloud.ifaces)
	}
	if len(cloud.ports) != 2 { // VM ports only; the gateway attach creates no port
		t.Errorf("ports: got %d, want 2", len(cloud.ports))
	}
	for _, p := range cloud.ports {
		if p.SecGroupID != "sg-1" {
			t.Errorf("vm port %q missing secgroup, got %q", p.Name, p.SecGroupID)
		}
	}
	if len(cloud.servers) != 2 {
		t.Errorf("servers: got %d, want 2", len(cloud.servers))
	}
	for _, s := range cloud.servers {
		if s.FlavorID != "flv-1" || s.ImageID != "img-1" || s.KeypairName != "kp" {
			t.Errorf("server boot spec wrong: %+v", s)
		}
	}
	if len(cloud.fips) != 2 {
		t.Errorf("fips: got %d, want 2 (one per VM)", len(cloud.fips))
	}
	// The attach gate's green state is recorded for drive's recheck:
	// baseline 5 + 2 VM taps.
	if rs.Attach.Target != 7 {
		t.Errorf("attach record target = %v, want 7", rs.Attach.Target)
	}
	if ref, ok := rs.Projects["T1"]; !ok || !ref.Created {
		t.Errorf("project T1 not recorded as created: %+v", rs.Projects)
	}
	// Name mangling reaches the live resource names.
	if cloud.nets[0].Name != "scenariotest-run1-net-T1" {
		t.Errorf("network name not mangled: %q", cloud.nets[0].Name)
	}
}

// crossTenantRoutedScenario mirrors the registered other_tenant
// topology: two tenants, a transit subnet, routers with static routes
// and external gateways (FIP reachability).
func crossTenantRoutedScenario() *Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").Subnet("sub-T1", "10.0.0.0/24", "10.0.0.1").VM("vm-a", "T1", "10.0.0.5")
	b.Network("net-T2", "T2").Subnet("sub-T2", "10.50.0.0/24", "10.50.0.1").VM("vm-b", "T2", "10.50.0.5")
	b.SharedNetwork("net-transit", "admin").Subnet("sub-transit", "192.168.100.0/24", "192.168.100.1")
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").Attach("sub-T1", "10.0.0.1").Attach("sub-transit", "192.168.100.10").
		ExtraRoute("10.50.0.0/24", "192.168.100.20").ExternalGateway("net-ext")
	b.Router("r-T2", "T2").Attach("sub-T2", "10.50.0.1").Attach("sub-transit", "192.168.100.20").
		ExtraRoute("10.0.0.0/24", "192.168.100.10").ExternalGateway("net-ext")
	return &Scenario{Name: "other", Builder: b}
}

func TestRealize_CrossTenantRouted(t *testing.T) {
	cloud, rs := realizeFixture(t, crossTenantRoutedScenario())

	if len(cloud.nets) != 3 { // T1, T2, transit; the ext net is never created
		t.Errorf("networks: got %d, want 3", len(cloud.nets))
	}
	if len(cloud.rtrs) != 2 {
		t.Errorf("routers: got %d, want 2", len(cloud.rtrs))
	}
	for i, rt := range cloud.rtrs {
		if rt.ExternalNetworkID != cloud.extNetID {
			t.Errorf("router[%d] external gateway = %q, want %q", i, rt.ExternalNetworkID, cloud.extNetID)
		}
	}
	if len(cloud.routes) != 2 {
		t.Errorf("route-sets: got %d, want 2", len(cloud.routes))
	}
	// Four router-interface attaches: two gateway IPs (subnet-based),
	// two transit IPs (port-based).
	var subnetBased, portBased int
	for _, i := range cloud.ifaces {
		switch {
		case i.subnetID != "" && i.portID == "":
			subnetBased++
		case i.portID != "" && i.subnetID == "":
			portBased++
		default:
			t.Errorf("interface attach has both/neither subnet+port: %+v", i)
		}
	}
	if subnetBased != 2 || portBased != 2 {
		t.Errorf("interface attach modes: subnet=%d port=%d, want 2/2", subnetBased, portBased)
	}
	for _, want := range []string{"T1", "T2", "admin"} {
		if _, ok := rs.Projects[want]; !ok {
			t.Errorf("project %q not recorded: %+v", want, rs.Projects)
		}
	}
	if len(cloud.servers) != 2 || len(cloud.fips) != 2 {
		t.Errorf("servers=%d fips=%d, want 2/2", len(cloud.servers), len(cloud.fips))
	}
}

// externalScenario mirrors the registered external topology: an
// ExternalNetwork marker plus a router gatewaying to it.
func externalScenario() *Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").Subnet("sub-T1", "10.0.1.0/24", "10.0.1.1").VM("vm-a", "T1", "10.0.1.5")
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").Attach("sub-T1", "10.0.1.1").ExternalGateway("net-ext")
	return &Scenario{Name: "ext", Builder: b}
}

func TestRealize_ExternalNetworkResolvesToProvider(t *testing.T) {
	cloud, _ := realizeFixture(t, externalScenario())

	// The external network is NOT created — only net-T1 is.
	if len(cloud.nets) != 1 {
		t.Fatalf("networks created: got %d, want 1 (external net must not be created)", len(cloud.nets))
	}
	if cloud.nets[0].Name != "scenariotest-run1-net-T1" {
		t.Errorf("created network is not net-T1: %q", cloud.nets[0].Name)
	}
	// The router gateways to the real provider external network.
	if len(cloud.rtrs) != 1 || cloud.rtrs[0].ExternalNetworkID != cloud.extNetID {
		t.Errorf("router external gateway = %q, want provider %q", cloud.rtrs[0].ExternalNetworkID, cloud.extNetID)
	}
}

// TestRealize_FIPRequiresGatewayedRouter is the regression test for
// the Neutron reachability rule: a topology whose VM subnet has no
// router gatewayed to the external network cannot carry the FIP `up`
// allocates for SSH reach, and must fail loudly rather than at drive
// time.
func TestRealize_FIPRequiresGatewayedRouter(t *testing.T) {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.1.0/24", "10.0.1.1").
		VM("vm-a", "T1", "10.0.1.5")
	sc := &Scenario{Name: "no-router", Builder: b}

	env := &fakeEnv{baseAttached: 5}
	cloud := newFakeCloud(env)
	_, err := Realize(context.Background(), RealizeOptions{
		Config: testConfig(), Scenario: sc, RunID: "run1",
		StatePath: t.TempDir() + "/s.json", Cloud: cloud, Metrics: &fakeMetrics{env: env}, Log: slog.New(slog.DiscardHandler),
	})
	if err == nil || !strings.Contains(err.Error(), "not reachable") {
		t.Fatalf("want FIP reachability error, got %v", err)
	}
}

func TestRealize_ReusesExistingProject(t *testing.T) {
	env := &fakeEnv{baseAttached: 5}
	cloud := newFakeCloud(env)
	cloud.preProjects["scenariotest-T1"] = "existing-T1"

	rs, err := Realize(context.Background(), RealizeOptions{
		Config: testConfig(), Scenario: sameTenantScenario(), RunID: "run1",
		StatePath: t.TempDir() + "/s.json", Cloud: cloud, Metrics: &fakeMetrics{env: env}, Log: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	if ref := rs.Projects["T1"]; ref.ID != "existing-T1" || ref.Created {
		t.Errorf("project T1 should be reused, got %+v", ref)
	}
	if len(cloud.createdProjects) != 0 {
		t.Errorf("reused project should not be created, got %v", cloud.createdProjects)
	}
	// The reuse path still grants the admin role (idempotent), so a
	// run that crashed between create and grant heals here.
	granted := false
	for _, g := range cloud.grants {
		if g == "existing-T1" {
			granted = true
		}
	}
	if !granted {
		t.Errorf("reused project did not receive the admin-role grant: %v", cloud.grants)
	}
}

func TestRealize_ForceFreshFailsWhenProjectExists(t *testing.T) {
	env := &fakeEnv{baseAttached: 5}
	cloud := newFakeCloud(env)
	cloud.preProjects["scenariotest-T1"] = "existing-T1"
	sc := sameTenantScenario()
	sc.Projects = ProjectPolicy{"T1": ForceFresh}

	_, err := Realize(context.Background(), RealizeOptions{
		Config: testConfig(), Scenario: sc, RunID: "run1",
		StatePath: t.TempDir() + "/s.json", Cloud: cloud, Metrics: &fakeMetrics{env: env}, Log: slog.New(slog.DiscardHandler),
	})
	if err == nil {
		t.Fatal("want error for ForceFresh on existing project, got nil")
	}
}

func TestRealize_AttachGateTimesOut(t *testing.T) {
	env := &fakeEnv{baseAttached: 5}
	cloud := newFakeCloud(env)
	// Metrics that never report new taps: booted increments but the
	// source ignores it, so the gauge never reaches the target.
	stuck := stuckMetrics{}
	_, err := Realize(context.Background(), RealizeOptions{
		Config: testConfig(), Scenario: sameTenantScenario(), RunID: "run1",
		StatePath: t.TempDir() + "/s.json", Cloud: cloud, Metrics: stuck, Log: slog.New(slog.DiscardHandler),
		AttachTimeout: 50 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("want attach-gate timeout error, got nil")
	}
}

type stuckMetrics struct{ instantMACs }

func (stuckMetrics) Scrape(context.Context, string) (ScrapeResult, error) {
	return ScrapeResult{Present: map[string]bool{metricBytesTotal: true, metricAttachedInterfaces: true}, AttachedInterfaces: 5}, nil
}

// TestRealize_RecordsVMPortMACs: up records each VM port's
// Neutron-assigned MAC in the run-state — the MAC-learn gate's input
// (lachesis#153).
func TestRealize_RecordsVMPortMACs(t *testing.T) {
	_, rs := realizeFixture(t, sameTenantScenario())
	vmPorts := 0
	for _, p := range rs.Ports {
		if p.DSLID == "vm-a" || p.DSLID == "vm-b" {
			vmPorts++
			if p.MAC == "" {
				t.Errorf("VM port %s recorded without a MAC", p.DSLID)
			}
		}
	}
	if vmPorts != 2 {
		t.Fatalf("run-state has %d VM port refs, want 2: %+v", vmPorts, rs.Ports)
	}
}
