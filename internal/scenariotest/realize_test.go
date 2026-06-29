package scenariotest

import (
	"context"
	"fmt"
	"io"
	"testing"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/testenv/scenario"
)

// fakeEnv is shared mutable state between the fake Cloud and fake
// MetricsSource so the attach gate sees taps appear as VMs boot.
type fakeEnv struct {
	baseAttached float64
	booted       int // CreateServer increments; one tap per boot
	failures     float64
}

// fakeCloud is a recording [Cloud]: lookups return configured IDs,
// creates append to typed slices and hand back synthetic IDs.
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
	fips            []FIPCreateSpec
}

type ifaceRec struct{ routerID, subnetID, portID string }
type routeRec struct {
	routerID string
	routes   []RouteSpec
}

func newFakeCloud(env *fakeEnv) *fakeCloud {
	return &fakeCloud{env: env, extNetID: "ext-net-real", hyps: []string{"compute-0"}, preProjects: map[string]string{}, findErrs: map[string]error{}}
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
	return c.id("rtr"), nil
}
func (c *fakeCloud) CreatePort(_ context.Context, _ string, spec PortSpec) (string, error) {
	c.ports = append(c.ports, spec)
	return c.id("port"), nil
}
func (c *fakeCloud) AddRouterInterface(_ context.Context, _, routerID, subnetID, portID string) error {
	c.ifaces = append(c.ifaces, ifaceRec{routerID, subnetID, portID})
	return nil
}
func (c *fakeCloud) SetRouterRoutes(_ context.Context, _, routerID string, routes []RouteSpec) error {
	c.routes = append(c.routes, routeRec{routerID, routes})
	return nil
}
func (c *fakeCloud) CreateServer(_ context.Context, _ string, spec ServerSpec) (string, error) {
	c.servers = append(c.servers, spec)
	c.env.booted++
	return c.id("srv"), nil
}
func (c *fakeCloud) WaitServerActive(context.Context, string, string) error { return nil }
func (c *fakeCloud) CreateFIP(_ context.Context, _ string, spec FIPCreateSpec) (string, string, error) {
	c.fips = append(c.fips, spec)
	return c.id("fip"), fmt.Sprintf("203.0.113.%d", len(c.fips)), nil
}

// fakeMetrics reports an attached-interface count that grows as the
// fake Cloud boots servers, so the attach gate goes green.
type fakeMetrics struct{ env *fakeEnv }

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
		Log:       io.Discard,
	})
	if err != nil {
		t.Fatalf("Realize: %v", err)
	}
	return cloud, rs
}

func sameTenantScenario() *Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.1.0/24", "10.0.1.1").
		VM("vm-a", "T1", "10.0.1.5").
		VM("vm-b", "T1", "10.0.1.6")
	return &Scenario{Name: "same", Builder: b}
}

func TestRealize_SameTenant(t *testing.T) {
	cloud, rs := realizeFixture(t, sameTenantScenario())

	if len(cloud.nets) != 1 {
		t.Errorf("networks: got %d, want 1", len(cloud.nets))
	}
	if len(cloud.subs) != 1 {
		t.Errorf("subnets: got %d, want 1", len(cloud.subs))
	}
	if len(cloud.rtrs) != 0 {
		t.Errorf("routers: got %d, want 0", len(cloud.rtrs))
	}
	if len(cloud.ports) != 2 {
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
	if ref, ok := rs.Projects["T1"]; !ok || !ref.Created {
		t.Errorf("project T1 not recorded as created: %+v", rs.Projects)
	}
	// Name mangling reaches the live resource names.
	if cloud.nets[0].Name != "scenariotest-run1-net-T1" {
		t.Errorf("network name not mangled: %q", cloud.nets[0].Name)
	}
}

// crossTenantRoutedScenario mirrors the registered other_tenant
// topology: two tenants, a transit subnet, routers with static routes.
func crossTenantRoutedScenario() *Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").Subnet("sub-T1", "10.0.0.0/24", "10.0.0.1").VM("vm-a", "T1", "10.0.0.5")
	b.Network("net-T2", "T2").Subnet("sub-T2", "10.50.0.0/24", "10.50.0.1").VM("vm-b", "T2", "10.50.0.5")
	b.SharedNetwork("net-transit", "admin").Subnet("sub-transit", "192.168.100.0/24", "192.168.100.1")
	b.Router("r-T1", "T1").Attach("sub-T1", "10.0.0.1").Attach("sub-transit", "192.168.100.10").
		ExtraRoute("10.50.0.0/24", "192.168.100.20")
	b.Router("r-T2", "T2").Attach("sub-T2", "10.50.0.1").Attach("sub-transit", "192.168.100.20").
		ExtraRoute("10.0.0.0/24", "192.168.100.10")
	return &Scenario{Name: "other", Builder: b}
}

func TestRealize_CrossTenantRouted(t *testing.T) {
	cloud, rs := realizeFixture(t, crossTenantRoutedScenario())

	if len(cloud.nets) != 3 { // T1, T2, transit (all internal/shared, none external)
		t.Errorf("networks: got %d, want 3", len(cloud.nets))
	}
	if len(cloud.rtrs) != 2 {
		t.Errorf("routers: got %d, want 2", len(cloud.rtrs))
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

func TestRealize_ReusesExistingProject(t *testing.T) {
	env := &fakeEnv{baseAttached: 5}
	cloud := newFakeCloud(env)
	cloud.preProjects["scenariotest-T1"] = "existing-T1"

	rs, err := Realize(context.Background(), RealizeOptions{
		Config: testConfig(), Scenario: sameTenantScenario(), RunID: "run1",
		StatePath: t.TempDir() + "/s.json", Cloud: cloud, Metrics: &fakeMetrics{env: env}, Log: io.Discard,
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
}

func TestRealize_ForceFreshFailsWhenProjectExists(t *testing.T) {
	env := &fakeEnv{baseAttached: 5}
	cloud := newFakeCloud(env)
	cloud.preProjects["scenariotest-T1"] = "existing-T1"
	sc := sameTenantScenario()
	sc.Projects = ProjectPolicy{"T1": ForceFresh}

	_, err := Realize(context.Background(), RealizeOptions{
		Config: testConfig(), Scenario: sc, RunID: "run1",
		StatePath: t.TempDir() + "/s.json", Cloud: cloud, Metrics: &fakeMetrics{env: env}, Log: io.Discard,
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
		StatePath: t.TempDir() + "/s.json", Cloud: cloud, Metrics: stuck, Log: io.Discard,
		AttachTimeout: 50 * 1e6, // 50ms
	})
	if err == nil {
		t.Fatal("want attach-gate timeout error, got nil")
	}
}

type stuckMetrics struct{}

func (stuckMetrics) Scrape(context.Context, string) (ScrapeResult, error) {
	return ScrapeResult{Present: map[string]bool{metricBytesTotal: true, metricAttachedInterfaces: true}, AttachedInterfaces: 5}, nil
}
