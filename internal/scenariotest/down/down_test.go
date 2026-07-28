package down

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/fake"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/realize"
)

// downState hand-builds the run-state of a realized two-VM topology
// with a router, so teardown ordering is fully observable.
func downState() *scenariotest.RunState {
	rs := scenariotest.NewRunState("run1", "same", "scenariotest")
	rs.Projects = map[string]scenariotest.ProjectRef{"T1": {Name: "scenariotest-T1", ID: "uuid-t1", Created: true}}
	rs.Networks = []scenariotest.ResourceRef{{DSLID: "net-T1", ID: "net-1", ProjectID: "uuid-t1"}}
	rs.Subnets = []scenariotest.ResourceRef{{DSLID: "sub-T1", ID: "sub-1", ProjectID: "uuid-t1"}}
	rs.Routers = []scenariotest.ResourceRef{{DSLID: "r-T1", ID: "rtr-1", ProjectID: "uuid-t1"}}
	rs.Ports = []scenariotest.ResourceRef{
		{DSLID: "vm-a", ID: "port-a", ProjectID: "uuid-t1"},
		{DSLID: "vm-b", ID: "port-b", ProjectID: "uuid-t1"},
	}
	rs.Servers = []scenariotest.ResourceRef{
		{DSLID: "vm-a", ID: "srv-a", ProjectID: "uuid-t1"},
		{DSLID: "vm-b", ID: "srv-b", ProjectID: "uuid-t1"},
	}
	rs.FIPs = []scenariotest.FIPRef{
		{VMID: "vm-a", ID: "fip-a", Address: "203.0.113.10", ProjectID: "uuid-t1"},
		{VMID: "vm-b", ID: "fip-b", Address: "203.0.113.11", ProjectID: "uuid-t1"},
	}
	return rs
}

func runDownFixture(t *testing.T, rs *scenariotest.RunState, cloud *fake.Cloud) (string, error) {
	t.Helper()
	statePath := t.TempDir() + "/state.json"
	err := Run(context.Background(), Options{
		Config:    fake.Config(),
		State:     rs,
		StatePath: statePath,
		Cloud:     cloud,
		Log:       slog.New(slog.DiscardHandler),
	})
	return statePath, err
}

// TestDown_MultiNIC: a multi-homed VM's extra NIC port is bound to its
// server (refuses deletion while the server lives) and both ports are
// torn down after the server — the server-before-ports ordering holds
// with more than one port per server.
func TestDown_MultiNIC(t *testing.T) {
	rs := downState()
	// vm-a gains a second NIC port; vm-b stays single-NIC.
	rs.Ports = append(rs.Ports, scenariotest.ResourceRef{DSLID: "vm-a-nic-1", ID: "port-a2", ProjectID: "uuid-t1"})

	cloud := fake.NewCloud(&fake.Env{})
	// Prime the live-server model: srv-a carries port-a (primary) and
	// port-a2 (extra) — so port-a2 refuses deletion until srv-a is gone.
	cloud.ServerPort["srv-a"] = "port-a"
	cloud.ServerExtraPorts["srv-a"] = []string{"port-a2"}

	// While the server lives, deleting its extra NIC must be refused.
	if err := cloud.DeletePort(context.Background(), "uuid-t1", "port-a2"); err == nil {
		t.Error("deleting a bound extra NIC must be refused while its server lives")
	}

	if _, err := runDownFixture(t, rs, cloud); err != nil {
		t.Fatalf("Down: %v", err)
	}
	idx := func(op string) int {
		for i, o := range cloud.DownOps {
			if o == op {
				return i
			}
		}
		t.Fatalf("op %q missing from %v", op, cloud.DownOps)
		return -1
	}
	// Both of vm-a's ports come down, and after the server.
	if !(idx("server:srv-a") < idx("port:port-a") && idx("server:srv-a") < idx("port:port-a2")) {
		t.Errorf("multi-NIC teardown order wrong (server must precede both its ports): %v", cloud.DownOps)
	}
}

func TestDown_OrderAndSweep(t *testing.T) {
	cloud := fake.NewCloud(&fake.Env{})
	// A platform port (cube:mgr) sits on the network — in no
	// run-state, but it blocks network deletion until swept.
	cloud.ResidualPorts["net-1"] = []string{"port-mgr"}

	statePath, err := runDownFixture(t, downState(), cloud)
	if err != nil {
		t.Fatalf("Down: %v", err)
	}

	idx := func(op string) int {
		for i, o := range cloud.DownOps {
			if o == op {
				return i
			}
		}
		t.Fatalf("op %q missing from %v", op, cloud.DownOps)
		return -1
	}
	// FIPs → servers → ports → router → residual sweep → subnet → network.
	if !(idx("fip:fip-a") < idx("server:srv-a") &&
		idx("server:srv-b") < idx("port:port-a") &&
		idx("port:port-b") < idx("router:rtr-1") &&
		idx("router:rtr-1") < idx("port:port-mgr") &&
		idx("port:port-mgr") < idx("subnet:sub-1") &&
		idx("subnet:sub-1") < idx("network:net-1")) {
		t.Errorf("teardown order wrong: %v", cloud.DownOps)
	}
	// Projects untouched is unrepresentable (no delete verb on the
	// interface); assert the record is intact anyway.
	saved, lerr := scenariotest.LoadRunState(statePath)
	if lerr != nil {
		t.Fatal(lerr)
	}
	if !saved.TornDown {
		t.Error("TornDown not persisted")
	}
	if len(saved.Projects) != 1 {
		t.Errorf("projects must survive: %+v", saved.Projects)
	}
}

func TestDown_ResidualPortBlocksUntilSwept(t *testing.T) {
	// Sanity-check the fake models the live cube:mgr behavior: with
	// the sweep skipped (no residualPorts listing consumed), network
	// deletion with a live port fails.
	cloud := fake.NewCloud(&fake.Env{})
	cloud.ResidualPorts["net-1"] = []string{"port-mgr"}
	if err := cloud.DeleteNetwork(context.Background(), "uuid-t1", "net-1"); err == nil {
		t.Fatal("fake should refuse to delete a network with live ports")
	}
}

func TestDown_RouteBlocksInterfaceDetach(t *testing.T) {
	// Sanity-check the fake models the live RouterInterfaceInUseByRoute
	// behavior: with a static route still on the router, detaching any
	// of its interfaces fails.
	cloud := fake.NewCloud(&fake.Env{})
	cloud.RouterRoutes["rtr-1"] = []scenariotest.RouteSpec{{Destination: "10.50.0.0/24", Nexthop: "192.168.100.20"}}
	if err := cloud.RemoveRouterInterface(context.Background(), "uuid-t1", "rtr-1", "sub-1", ""); err == nil {
		t.Fatal("fake should refuse to detach an interface while the router carries routes")
	}
}

func TestDown_ClearsRoutesBeforeDetach(t *testing.T) {
	// r-T1 carries a transit static route, so Neutron (and the fake)
	// pin its interfaces until the route is gone — the cross-tenant-
	// routed teardown failure this ordering exists to fix.
	cloud := fake.NewCloud(&fake.Env{})
	cloud.RouterRoutes["rtr-1"] = []scenariotest.RouteSpec{{Destination: "10.50.0.0/24", Nexthop: "192.168.100.20"}}

	statePath, err := runDownFixture(t, downState(), cloud)
	if err != nil {
		t.Fatalf("Down must converge with a routed router: %v", err)
	}
	idx := func(op string) int {
		for i, o := range cloud.DownOps {
			if o == op {
				return i
			}
		}
		t.Fatalf("op %q missing from %v", op, cloud.DownOps)
		return -1
	}
	if !(idx("routes:rtr-1") < idx("detach:rtr-1/sub-1")) {
		t.Errorf("routes must clear before interface detach: %v", cloud.DownOps)
	}
	saved, lerr := scenariotest.LoadRunState(statePath)
	if lerr != nil {
		t.Fatal(lerr)
	}
	if !saved.TornDown {
		t.Error("TornDown not persisted after converged teardown")
	}
}

func TestDown_FailedRouteClearLeavesInterfacePinned(t *testing.T) {
	// A clear that never reached the server must not unpin anything:
	// the routes stand, so the detach still refuses. Guards the fake
	// against unpinning before the call it models has succeeded — which
	// would let a broken teardown order pass under a cancelled context.
	cloud := fake.NewCloud(&fake.Env{})
	cloud.RouterRoutes["rtr-1"] = []scenariotest.RouteSpec{{Destination: "10.50.0.0/24", Nexthop: "192.168.100.20"}}
	cloud.FailDown = map[string]bool{"routes:rtr-1": true}

	if _, err := runDownFixture(t, downState(), cloud); err == nil {
		t.Fatal("Down must report failure when the route clear fails")
	}
	if len(cloud.RouterRoutes["rtr-1"]) == 0 {
		t.Error("a failed clear must leave the routes, and their pin, intact")
	}
	for _, o := range cloud.DownOps {
		if strings.HasPrefix(o, "detach:rtr-1/") {
			t.Errorf("interface detached despite a failed route clear: %v", cloud.DownOps)
		}
	}
}

// TestDown_SweepsServerFromCreateSaveRace is the regression for
// lachesis#212: a server Nova accepted in the window between the boot
// call returning and the state save is recorded nowhere. Realize boots
// the VMs (the fake records them live), but the run-state `down` sees
// predates those boots — it records their ports (saved earlier) yet
// zero servers, exactly the hard-kill-mid-boot case found on staging.
// The recorded-server loop can't reach the orphans; only the
// name-prefix sweep can. Without it, `down` can't even converge: the
// recorded VM ports refuse to delete while their servers are still
// bound.
func TestDown_SweepsServerFromCreateSaveRace(t *testing.T) {
	cloud, rs := realizeFixture(t, fake.SameTenantScenario())
	if len(cloud.ServerIDs) != 2 {
		t.Fatalf("fixture booted %d servers, want 2", len(cloud.ServerIDs))
	}
	// Simulate the create→save race: the on-disk state was written
	// before any server boot was recorded (the reported live case
	// recorded zero servers while a VM was ACTIVE). The ports it
	// recorded stay — that is what makes teardown 409 without the sweep.
	rs.Servers = nil

	statePath, err := runDownFixture(t, rs, cloud)
	if err != nil {
		t.Fatalf("Down must converge by sweeping the unrecorded servers: %v", err)
	}

	// Every booted server — recorded nowhere — is gone.
	for _, id := range cloud.ServerIDs {
		if !cloud.Deleted["server:"+id] {
			t.Errorf("orphan server %s survived down", id)
		}
	}
	// The sweep runs before the port teardown: a server's tap must
	// vanish before `down` deletes the (recorded) port it sat on.
	firstPort, lastServer := -1, -1
	for i, o := range cloud.DownOps {
		if strings.HasPrefix(o, "server:") {
			lastServer = i
		}
		if strings.HasPrefix(o, "port:") && firstPort == -1 {
			firstPort = i
		}
	}
	if firstPort == -1 {
		t.Fatalf("no port was torn down: %v", cloud.DownOps)
	}
	if lastServer > firstPort {
		t.Errorf("server sweep must precede port teardown: %v", cloud.DownOps)
	}
	saved, lerr := scenariotest.LoadRunState(statePath)
	if lerr != nil {
		t.Fatal(lerr)
	}
	if !saved.TornDown {
		t.Error("TornDown not persisted after the sweep converged")
	}
}

// TestDown_ServerSweepScopedToRunPrefix guards the collision-safety
// discipline: the sweep deletes only servers whose name carries this
// run's mangled prefix, never a sibling run's server sharing the reused
// project (projects are run-id-free and kept across runs).
func TestDown_ServerSweepScopedToRunPrefix(t *testing.T) {
	cloud, rs := realizeFixture(t, fake.SameTenantScenario())
	rs.Servers = nil
	// A server from another run, live in the same (reused) project.
	proj := rs.Projects["T1"].ID
	other, _ := cloud.CreateServer(context.Background(), proj, scenariotest.ServerSpec{Name: "scenariotest-other9-vm-z"})

	if _, err := runDownFixture(t, rs, cloud); err != nil {
		t.Fatalf("Down: %v", err)
	}
	if cloud.Deleted["server:"+other] {
		t.Errorf("sweep deleted a sibling run's server %s — must match only this run's prefix", other)
	}
}

func TestDown_Idempotent(t *testing.T) {
	cloud := fake.NewCloud(&fake.Env{})
	cloud.ResidualPorts["net-1"] = []string{"port-mgr"}
	rs := downState()

	if _, err := runDownFixture(t, rs, cloud); err != nil {
		t.Fatalf("first Down: %v", err)
	}
	opsAfterFirst := len(cloud.DownOps)
	// Second pass over the same (now empty) state must succeed and
	// delete nothing new.
	if _, err := runDownFixture(t, rs, cloud); err != nil {
		t.Fatalf("second Down must converge: %v", err)
	}
	if len(cloud.DownOps) != opsAfterFirst {
		t.Errorf("second Down re-deleted: %v", cloud.DownOps[opsAfterFirst:])
	}
}

func TestDown_CollectsErrorsAndContinues(t *testing.T) {
	cloud := fake.NewCloud(&fake.Env{})
	rs := downState()
	rs.Networks = append(rs.Networks, scenariotest.ResourceRef{DSLID: "net-X", ID: "net-x", ProjectID: "uuid-t1"})
	// The phantom port refuses to die: its network's delete then
	// fails too, but every other resource must still be processed.
	cloud.ResidualPorts["net-x"] = []string{"phantom"}
	cloud.FailDown = map[string]bool{"port:phantom": true}

	statePath, err := runDownFixture(t, rs, cloud)
	if err == nil || !strings.Contains(err.Error(), "re-run to converge") {
		t.Fatalf("want accumulated-failure error, got %v", err)
	}
	joined := strings.Join(cloud.DownOps, ",")
	if !strings.Contains(joined, "network:net-1") {
		t.Errorf("healthy network must still be torn down: %v", cloud.DownOps)
	}
	saved, _ := scenariotest.LoadRunState(statePath)
	if saved != nil && saved.TornDown {
		t.Error("a failed pass must not mark TornDown")
	}

	// Clearing the blockage and re-running converges.
	cloud.FailDown = nil
	if _, err := runDownFixture(t, rs, cloud); err != nil {
		t.Fatalf("re-run must converge: %v", err)
	}
}

// realizeFixture stands the scenario up against the fake cloud and
// returns the recording cloud plus the resulting run-state.
func realizeFixture(t *testing.T, sc *scenariotest.Scenario) (*fake.Cloud, *scenariotest.RunState) {
	t.Helper()
	env := &fake.Env{BaseAttached: 5}
	cloud := fake.NewCloud(env)
	rs, err := realize.Run(context.Background(), realize.Options{
		Config:    fake.Config(),
		Scenario:  sc,
		RunID:     "run1",
		StatePath: t.TempDir() + "/state.json",
		Cloud:     cloud,
		Metrics:   &fake.Metrics{Env: env},
		Log:       slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("realize: %v", err)
	}
	return cloud, rs
}
