package scenariotest

import (
	"context"
	"log/slog"
	"strings"
	"testing"
)

// downState hand-builds the run-state of a realized two-VM topology
// with a router, so teardown ordering is fully observable.
func downState() *RunState {
	rs := NewRunState("run1", "same", "scenariotest")
	rs.Projects = map[string]ProjectRef{"T1": {Name: "scenariotest-T1", ID: "uuid-t1", Created: true}}
	rs.Networks = []ResourceRef{{DSLID: "net-T1", ID: "net-1", ProjectID: "uuid-t1"}}
	rs.Subnets = []ResourceRef{{DSLID: "sub-T1", ID: "sub-1", ProjectID: "uuid-t1"}}
	rs.Routers = []ResourceRef{{DSLID: "r-T1", ID: "rtr-1", ProjectID: "uuid-t1"}}
	rs.Ports = []ResourceRef{
		{DSLID: "vm-a", ID: "port-a", ProjectID: "uuid-t1"},
		{DSLID: "vm-b", ID: "port-b", ProjectID: "uuid-t1"},
	}
	rs.Servers = []ResourceRef{
		{DSLID: "vm-a", ID: "srv-a", ProjectID: "uuid-t1"},
		{DSLID: "vm-b", ID: "srv-b", ProjectID: "uuid-t1"},
	}
	rs.FIPs = []FIPRef{
		{VMID: "vm-a", ID: "fip-a", Address: "203.0.113.10", ProjectID: "uuid-t1"},
		{VMID: "vm-b", ID: "fip-b", Address: "203.0.113.11", ProjectID: "uuid-t1"},
	}
	return rs
}

func runDownFixture(t *testing.T, rs *RunState, cloud *fakeCloud) (string, error) {
	t.Helper()
	statePath := t.TempDir() + "/state.json"
	err := Down(context.Background(), DownOptions{
		Config:    testConfig(),
		State:     rs,
		StatePath: statePath,
		Cloud:     cloud,
		Log:       slog.New(slog.DiscardHandler),
	})
	return statePath, err
}

func TestDown_OrderAndSweep(t *testing.T) {
	cloud := newFakeCloud(&fakeEnv{})
	// A platform port (cube:mgr) sits on the network — in no
	// run-state, but it blocks network deletion until swept.
	cloud.residualPorts["net-1"] = []string{"port-mgr"}

	statePath, err := runDownFixture(t, downState(), cloud)
	if err != nil {
		t.Fatalf("Down: %v", err)
	}

	idx := func(op string) int {
		for i, o := range cloud.downOps {
			if o == op {
				return i
			}
		}
		t.Fatalf("op %q missing from %v", op, cloud.downOps)
		return -1
	}
	// FIPs → servers → ports → router → residual sweep → subnet → network.
	if !(idx("fip:fip-a") < idx("server:srv-a") &&
		idx("server:srv-b") < idx("port:port-a") &&
		idx("port:port-b") < idx("router:rtr-1") &&
		idx("router:rtr-1") < idx("port:port-mgr") &&
		idx("port:port-mgr") < idx("subnet:sub-1") &&
		idx("subnet:sub-1") < idx("network:net-1")) {
		t.Errorf("teardown order wrong: %v", cloud.downOps)
	}
	// Projects untouched is unrepresentable (no delete verb on the
	// interface); assert the record is intact anyway.
	saved, lerr := LoadRunState(statePath)
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
	cloud := newFakeCloud(&fakeEnv{})
	cloud.residualPorts["net-1"] = []string{"port-mgr"}
	if err := cloud.DeleteNetwork(context.Background(), "uuid-t1", "net-1"); err == nil {
		t.Fatal("fake should refuse to delete a network with live ports")
	}
}

func TestDown_RouteBlocksInterfaceDetach(t *testing.T) {
	// Sanity-check the fake models the live RouterInterfaceInUseByRoute
	// behavior: with a static route still on the router, detaching any
	// of its interfaces fails.
	cloud := newFakeCloud(&fakeEnv{})
	cloud.routerRoutes["rtr-1"] = []RouteSpec{{Destination: "10.50.0.0/24", Nexthop: "192.168.100.20"}}
	if err := cloud.RemoveRouterInterface(context.Background(), "uuid-t1", "rtr-1", "sub-1", ""); err == nil {
		t.Fatal("fake should refuse to detach an interface while the router carries routes")
	}
}

func TestDown_ClearsRoutesBeforeDetach(t *testing.T) {
	// r-T1 carries a transit static route, so Neutron (and the fake)
	// pin its interfaces until the route is gone — the cross-tenant-
	// routed teardown failure this ordering exists to fix.
	cloud := newFakeCloud(&fakeEnv{})
	cloud.routerRoutes["rtr-1"] = []RouteSpec{{Destination: "10.50.0.0/24", Nexthop: "192.168.100.20"}}

	statePath, err := runDownFixture(t, downState(), cloud)
	if err != nil {
		t.Fatalf("Down must converge with a routed router: %v", err)
	}
	idx := func(op string) int {
		for i, o := range cloud.downOps {
			if o == op {
				return i
			}
		}
		t.Fatalf("op %q missing from %v", op, cloud.downOps)
		return -1
	}
	if !(idx("routes:rtr-1") < idx("detach:rtr-1/sub-1")) {
		t.Errorf("routes must clear before interface detach: %v", cloud.downOps)
	}
	saved, lerr := LoadRunState(statePath)
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
	cloud := newFakeCloud(&fakeEnv{})
	cloud.routerRoutes["rtr-1"] = []RouteSpec{{Destination: "10.50.0.0/24", Nexthop: "192.168.100.20"}}
	cloud.failDown = map[string]bool{"routes:rtr-1": true}

	if _, err := runDownFixture(t, downState(), cloud); err == nil {
		t.Fatal("Down must report failure when the route clear fails")
	}
	if len(cloud.routerRoutes["rtr-1"]) == 0 {
		t.Error("a failed clear must leave the routes, and their pin, intact")
	}
	for _, o := range cloud.downOps {
		if strings.HasPrefix(o, "detach:rtr-1/") {
			t.Errorf("interface detached despite a failed route clear: %v", cloud.downOps)
		}
	}
}

func TestDown_Idempotent(t *testing.T) {
	cloud := newFakeCloud(&fakeEnv{})
	cloud.residualPorts["net-1"] = []string{"port-mgr"}
	rs := downState()

	if _, err := runDownFixture(t, rs, cloud); err != nil {
		t.Fatalf("first Down: %v", err)
	}
	opsAfterFirst := len(cloud.downOps)
	// Second pass over the same (now empty) state must succeed and
	// delete nothing new.
	if _, err := runDownFixture(t, rs, cloud); err != nil {
		t.Fatalf("second Down must converge: %v", err)
	}
	if len(cloud.downOps) != opsAfterFirst {
		t.Errorf("second Down re-deleted: %v", cloud.downOps[opsAfterFirst:])
	}
}

func TestDown_CollectsErrorsAndContinues(t *testing.T) {
	cloud := newFakeCloud(&fakeEnv{})
	rs := downState()
	rs.Networks = append(rs.Networks, ResourceRef{DSLID: "net-X", ID: "net-x", ProjectID: "uuid-t1"})
	// The phantom port refuses to die: its network's delete then
	// fails too, but every other resource must still be processed.
	cloud.residualPorts["net-x"] = []string{"phantom"}
	cloud.failDown = map[string]bool{"port:phantom": true}

	statePath, err := runDownFixture(t, rs, cloud)
	if err == nil || !strings.Contains(err.Error(), "re-run to converge") {
		t.Fatalf("want accumulated-failure error, got %v", err)
	}
	joined := strings.Join(cloud.downOps, ",")
	if !strings.Contains(joined, "network:net-1") {
		t.Errorf("healthy network must still be torn down: %v", cloud.downOps)
	}
	saved, _ := LoadRunState(statePath)
	if saved != nil && saved.TornDown {
		t.Error("a failed pass must not mark TornDown")
	}

	// Clearing the blockage and re-running converges.
	cloud.failDown = nil
	if _, err := runDownFixture(t, rs, cloud); err != nil {
		t.Fatalf("re-run must converge: %v", err)
	}
}
