package realize

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/fake"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

func realizeFixture(t *testing.T, sc *scenariotest.Scenario) (*fake.Cloud, *scenariotest.RunState) {
	t.Helper()
	env := &fake.Env{BaseAttached: 5}
	cloud := fake.NewCloud(env)
	rs, err := Run(context.Background(), Options{
		Config:    fake.Config(),
		Scenario:  sc,
		RunID:     "run1",
		StatePath: t.TempDir() + "/state.json",
		Cloud:     cloud,
		Metrics:   &fake.Metrics{Env: env},
		Log:       slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("Realize: %v", err)
	}
	return cloud, rs
}

func TestRealize_SameTenant(t *testing.T) {
	cloud, rs := realizeFixture(t, fake.SameTenantScenario())

	if len(cloud.Nets) != 1 { // ext net resolves to the provider net, never created
		t.Errorf("networks: got %d, want 1", len(cloud.Nets))
	}
	if len(cloud.Subs) != 1 {
		t.Errorf("subnets: got %d, want 1", len(cloud.Subs))
	}
	if len(cloud.Rtrs) != 1 || cloud.Rtrs[0].ExternalNetworkID != cloud.ExtNetID {
		t.Errorf("routers: got %+v, want 1 gatewayed to %s", cloud.Rtrs, cloud.ExtNetID)
	}
	if len(cloud.Ifaces) != 1 || cloud.Ifaces[0].SubnetID == "" {
		t.Errorf("router interfaces: got %+v, want 1 subnet-based (gateway) attach", cloud.Ifaces)
	}
	if len(cloud.Ports) != 2 { // VM ports only; the gateway attach creates no port
		t.Errorf("ports: got %d, want 2", len(cloud.Ports))
	}
	for _, p := range cloud.Ports {
		if p.SecGroupID != "sg-1" {
			t.Errorf("vm port %q missing secgroup, got %q", p.Name, p.SecGroupID)
		}
	}
	if len(cloud.Servers) != 2 {
		t.Errorf("servers: got %d, want 2", len(cloud.Servers))
	}
	for _, s := range cloud.Servers {
		if s.FlavorID != "flv-1" || s.ImageID != "img-1" || s.KeypairName != "kp" {
			t.Errorf("server boot spec wrong: %+v", s)
		}
	}
	if len(cloud.Fips) != 2 {
		t.Errorf("fips: got %d, want 2 (one per VM)", len(cloud.Fips))
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
	if cloud.Nets[0].Name != "scenariotest-run1-net-T1" {
		t.Errorf("network name not mangled: %q", cloud.Nets[0].Name)
	}
}

// multiNICScenario is a two-NIC VM (vm-a): a primary port on net-T1 and
// an extra NIC on net-T1b, both under one server identity.
func multiNICScenario() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.1.0/24", "10.0.1.1").
		VM("vm-a", "T1", "10.0.1.5").
		VM("vm-b", "T1", "10.0.1.6")
	b.Network("net-T1b", "T1").
		Subnet("sub-T1b", "10.0.2.0/24", "10.0.2.1")
	b.NIC("vm-a", "sub-T1b", "10.0.2.9")
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").
		Attach("sub-T1", "10.0.1.1").
		Attach("sub-T1b", "10.0.2.1").
		ExternalGateway("net-ext")
	return &scenariotest.Scenario{Name: "multi-nic", Builder: b}
}

func TestRealize_MultiNIC(t *testing.T) {
	cloud, rs := realizeFixture(t, multiNICScenario())

	// Two VMs, three VM ports (vm-a primary + vm-a NIC + vm-b), but only
	// TWO servers — the extra NIC shares vm-a's server, not its own.
	if len(cloud.Servers) != 2 {
		t.Fatalf("servers: got %d, want 2 (vm-a with 2 NICs is one server)", len(cloud.Servers))
	}
	if len(cloud.Ports) != 3 {
		t.Errorf("VM ports: got %d, want 3 (vm-a primary + vm-a nic + vm-b)", len(cloud.Ports))
	}
	// vm-a's boot carries the extra NIC; vm-b's does not.
	var vmA scenariotest.ServerSpec
	extraCounts := map[int]int{}
	for _, s := range cloud.Servers {
		extraCounts[len(s.ExtraPortIDs)]++
		if len(s.ExtraPortIDs) == 1 {
			vmA = s
		}
	}
	if extraCounts[1] != 1 || extraCounts[0] != 1 {
		t.Fatalf("want exactly one 2-NIC server and one 1-NIC server, got extra-port counts %v", extraCounts)
	}
	if vmA.PortID == "" || vmA.PortID == vmA.ExtraPortIDs[0] {
		t.Errorf("multi-NIC server must have a distinct primary and extra port: %+v", vmA)
	}
	// One FIP per SERVER (on the primary), not per port.
	if len(cloud.Fips) != 2 {
		t.Errorf("fips: got %d, want 2 (one per server, on the primary NIC)", len(cloud.Fips))
	}
	// Attach gate counts taps (3), not Servers: baseline 5 + 3.
	if rs.Attach.Target != 8 {
		t.Errorf("attach record target = %v, want 8 (5 baseline + 3 taps)", rs.Attach.Target)
	}
	// All three VM ports are recorded, and the extra NIC's ref carries a
	// MAC (so the MAC-learn gate covers it) and shares vm-a's project.
	vmPortRefs := 0
	for _, p := range rs.Ports {
		if p.RouterInterface {
			continue
		}
		vmPortRefs++
		if p.MAC == "" {
			t.Errorf("VM port ref %q carries no MAC", p.DSLID)
		}
	}
	if vmPortRefs != 3 {
		t.Errorf("VM port refs in run-state: got %d, want 3", vmPortRefs)
	}
	// serverIDFor resolves vm-a to its one server across both NICs.
	if _, ok := scenariotest.ServerIDFor(rs, "vm-a"); !ok {
		t.Error("ServerIDFor(vm-a) not resolvable")
	}
}

// TestRealize_DeferredMultiNICRejected: a Deferred VM with an extra NIC
// must fail at realize — BootVMStep boots only the primary port, so the
// extra would vanish silently.
func TestRealize_DeferredMultiNICRejected(t *testing.T) {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.1.0/24", "10.0.1.1").
		VM("vm-a", "T1", "10.0.1.5").
		VM("vm-d", "T1", "10.0.1.9")
	b.Network("net-T1b", "T1").Subnet("sub-T1b", "10.0.2.0/24", "10.0.2.1")
	b.NIC("vm-d", "sub-T1b", "10.0.2.9") // extra NIC on the deferred VM
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").Attach("sub-T1", "10.0.1.1").Attach("sub-T1b", "10.0.2.1").ExternalGateway("net-ext")
	sc := &scenariotest.Scenario{Name: "deferred-multinic", Builder: b, Deferred: []string{"vm-d"}}

	env := &fake.Env{BaseAttached: 5}
	_, err := Run(context.Background(), Options{
		Config:    fake.Config(),
		Scenario:  sc,
		RunID:     "run1",
		StatePath: t.TempDir() + "/state.json",
		Cloud:     fake.NewCloud(env),
		Metrics:   &fake.Metrics{Env: env},
		Log:       slog.New(slog.DiscardHandler),
	})
	if err == nil || !strings.Contains(err.Error(), "single-NIC") {
		t.Fatalf("want a deferred-multi-NIC rejection, got %v", err)
	}
}

// crossTenantRoutedScenario mirrors the registered other_tenant
// topology: two tenants, a transit subnet, routers with static routes
// and external gateways (FIP reachability).
func crossTenantRoutedScenario() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").Subnet("sub-T1", "10.0.0.0/24", "10.0.0.1").VM("vm-a", "T1", "10.0.0.5")
	b.Network("net-T2", "T2").Subnet("sub-T2", "10.50.0.0/24", "10.50.0.1").VM("vm-b", "T2", "10.50.0.5")
	b.SharedNetwork("net-transit", "admin").Subnet("sub-transit", "192.168.100.0/24", "192.168.100.1")
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").Attach("sub-T1", "10.0.0.1").Attach("sub-transit", "192.168.100.10").
		ExtraRoute("10.50.0.0/24", "192.168.100.20").ExternalGateway("net-ext")
	b.Router("r-T2", "T2").Attach("sub-T2", "10.50.0.1").Attach("sub-transit", "192.168.100.20").
		ExtraRoute("10.0.0.0/24", "192.168.100.10").ExternalGateway("net-ext")
	return &scenariotest.Scenario{Name: "other", Builder: b}
}

func TestRealize_PlacementSlotPinsAZ(t *testing.T) {
	sc := fake.SameTenantScenario()
	sc.Placement = scenariotest.Placement{"vm-a": "node:0", "vm-b": "compute-9"}
	cloud, _ := realizeFixture(t, sc)
	byName := map[string]string{}
	for _, s := range cloud.Servers {
		byName[s.Name] = s.AvailabilityZone
	}
	// fake.Config's agents[0] is compute-0; the literal pin passes through.
	if az := byName["scenariotest-run1-vm-a"]; az != "nova:compute-0" {
		t.Errorf("vm-a AZ = %q, want %q (slot node:0)", az, "nova:compute-0")
	}
	if az := byName["scenariotest-run1-vm-b"]; az != "nova:compute-9" {
		t.Errorf("vm-b AZ = %q, want %q (literal)", az, "nova:compute-9")
	}
}

func TestRealize_PersistsResolvedPlacement(t *testing.T) {
	sc := fake.SameTenantScenario()
	sc.Placement = scenariotest.Placement{"vm-a": "node:0", "vm-b": "compute-9"}
	_, rs := realizeFixture(t, sc)
	// The run-state records the RESOLVED map — slots already hosts — so
	// it stands alone as evidence and deferred boots reuse it.
	if rs.Placement["vm-a"] != "compute-0" || rs.Placement["vm-b"] != "compute-9" {
		t.Errorf("run-state placement = %v, want resolved hosts", rs.Placement)
	}
}

func TestRealize_PlacementSlotBeyondAgents_CreatesNothing(t *testing.T) {
	env := &fake.Env{BaseAttached: 5}
	cloud := fake.NewCloud(env)
	sc := fake.SameTenantScenario()
	sc.Placement = scenariotest.Placement{"vm-a": "node:3"} // fake.Config lists one agent
	rs, err := Run(context.Background(), Options{
		Config:    fake.Config(),
		Scenario:  sc,
		RunID:     "run1",
		StatePath: t.TempDir() + "/state.json",
		Cloud:     cloud,
		Metrics:   &fake.Metrics{Env: env},
		Log:       slog.New(slog.DiscardHandler),
	})
	if err == nil {
		t.Fatal("Realize should fail on an unresolvable slot")
	}
	// Resolution precedes every create: nothing to tear down.
	if len(rs.Networks)+len(rs.Subnets)+len(rs.Routers)+len(rs.Ports)+len(rs.Servers) != 0 {
		t.Errorf("resources were created before placement resolution failed: %+v", rs)
	}
	if len(cloud.Servers) != 0 {
		t.Errorf("servers booted = %d, want 0", len(cloud.Servers))
	}
}

func TestRealize_CrossTenantRouted(t *testing.T) {
	cloud, rs := realizeFixture(t, crossTenantRoutedScenario())

	if len(cloud.Nets) != 3 { // T1, T2, transit; the ext net is never created
		t.Errorf("networks: got %d, want 3", len(cloud.Nets))
	}
	if len(cloud.Rtrs) != 2 {
		t.Errorf("routers: got %d, want 2", len(cloud.Rtrs))
	}
	for i, rt := range cloud.Rtrs {
		if rt.ExternalNetworkID != cloud.ExtNetID {
			t.Errorf("router[%d] external gateway = %q, want %q", i, rt.ExternalNetworkID, cloud.ExtNetID)
		}
	}
	if len(cloud.Routes) != 2 {
		t.Errorf("route-sets: got %d, want 2", len(cloud.Routes))
	}
	// Four router-interface attaches: two gateway IPs (subnet-based),
	// two transit IPs (port-based).
	var subnetBased, portBased int
	for _, i := range cloud.Ifaces {
		switch {
		case i.SubnetID != "" && i.PortID == "":
			subnetBased++
		case i.PortID != "" && i.SubnetID == "":
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
	if len(cloud.Servers) != 2 || len(cloud.Fips) != 2 {
		t.Errorf("servers=%d fips=%d, want 2/2", len(cloud.Servers), len(cloud.Fips))
	}
}

// externalScenario mirrors the registered external topology: an
// ExternalNetwork marker plus a router gatewaying to it.
func externalScenario() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").Subnet("sub-T1", "10.0.1.0/24", "10.0.1.1").VM("vm-a", "T1", "10.0.1.5")
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").Attach("sub-T1", "10.0.1.1").ExternalGateway("net-ext")
	return &scenariotest.Scenario{Name: "ext", Builder: b}
}

func TestRealize_ExternalNetworkResolvesToProvider(t *testing.T) {
	cloud, _ := realizeFixture(t, externalScenario())

	// The external network is NOT created — only net-T1 is.
	if len(cloud.Nets) != 1 {
		t.Fatalf("networks created: got %d, want 1 (external net must not be created)", len(cloud.Nets))
	}
	if cloud.Nets[0].Name != "scenariotest-run1-net-T1" {
		t.Errorf("created network is not net-T1: %q", cloud.Nets[0].Name)
	}
	// The router gateways to the real provider external network.
	if len(cloud.Rtrs) != 1 || cloud.Rtrs[0].ExternalNetworkID != cloud.ExtNetID {
		t.Errorf("router external gateway = %q, want provider %q", cloud.Rtrs[0].ExternalNetworkID, cloud.ExtNetID)
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
	sc := &scenariotest.Scenario{Name: "no-router", Builder: b}

	env := &fake.Env{BaseAttached: 5}
	cloud := fake.NewCloud(env)
	_, err := Run(context.Background(), Options{
		Config: fake.Config(), Scenario: sc, RunID: "run1",
		StatePath: t.TempDir() + "/s.json", Cloud: cloud, Metrics: &fake.Metrics{Env: env}, Log: slog.New(slog.DiscardHandler),
	})
	if err == nil || !strings.Contains(err.Error(), "not reachable") {
		t.Fatalf("want FIP reachability error, got %v", err)
	}
}

func TestRealize_ReusesExistingProject(t *testing.T) {
	env := &fake.Env{BaseAttached: 5}
	cloud := fake.NewCloud(env)
	cloud.PreProjects["scenariotest-T1"] = "existing-T1"

	rs, err := Run(context.Background(), Options{
		Config: fake.Config(), Scenario: fake.SameTenantScenario(), RunID: "run1",
		StatePath: t.TempDir() + "/s.json", Cloud: cloud, Metrics: &fake.Metrics{Env: env}, Log: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	if ref := rs.Projects["T1"]; ref.ID != "existing-T1" || ref.Created {
		t.Errorf("project T1 should be reused, got %+v", ref)
	}
	if len(cloud.CreatedProjects) != 0 {
		t.Errorf("reused project should not be created, got %v", cloud.CreatedProjects)
	}
	// The reuse path still grants the admin role (idempotent), so a
	// run that crashed between create and grant heals here.
	granted := false
	for _, g := range cloud.Grants {
		if g == "existing-T1" {
			granted = true
		}
	}
	if !granted {
		t.Errorf("reused project did not receive the admin-role grant: %v", cloud.Grants)
	}
}

func TestRealize_ForceFreshFailsWhenProjectExists(t *testing.T) {
	env := &fake.Env{BaseAttached: 5}
	cloud := fake.NewCloud(env)
	cloud.PreProjects["scenariotest-T1"] = "existing-T1"
	sc := fake.SameTenantScenario()
	sc.Projects = scenariotest.ProjectPolicy{"T1": scenariotest.ForceFresh}

	_, err := Run(context.Background(), Options{
		Config: fake.Config(), Scenario: sc, RunID: "run1",
		StatePath: t.TempDir() + "/s.json", Cloud: cloud, Metrics: &fake.Metrics{Env: env}, Log: slog.New(slog.DiscardHandler),
	})
	if err == nil {
		t.Fatal("want error for ForceFresh on existing project, got nil")
	}
}

func TestRealize_AttachGateTimesOut(t *testing.T) {
	env := &fake.Env{BaseAttached: 5}
	cloud := fake.NewCloud(env)
	// Metrics that never report new taps: booted increments but the
	// source ignores it, so the gauge never reaches the target.
	stuck := stuckMetrics{}
	_, err := Run(context.Background(), Options{
		Config: fake.Config(), Scenario: fake.SameTenantScenario(), RunID: "run1",
		StatePath: t.TempDir() + "/s.json", Cloud: cloud, Metrics: stuck, Log: slog.New(slog.DiscardHandler),
		AttachTimeout: 50 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("want attach-gate timeout error, got nil")
	}
}

type stuckMetrics struct{ fake.InstantMACs }

func (stuckMetrics) Scrape(context.Context, string) (scenariotest.ScrapeResult, error) {
	return scenariotest.ScrapeResult{Present: map[string]bool{scenariotest.MetricBytesTotal: true, scenariotest.MetricAttachedInterfaces: true}, AttachedInterfaces: 5}, nil
}

// TestRealize_RecordsVMPortMACs: up records each VM port's
// Neutron-assigned MAC in the run-state — the MAC-learn gate's input
// (lachesis#153).
func TestRealize_RecordsVMPortMACs(t *testing.T) {
	_, rs := realizeFixture(t, fake.SameTenantScenario())
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
