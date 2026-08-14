package scenario_test

import (
	"testing"

	"github.com/bigstack-oss/lachesis/internal/neutron"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// lbSnap declares one ACTIVE_STANDBY load balancer owned by T1, running
// in the "service" project, with a member on another subnet — the shape
// verified live on OVN-Yoga.
func lbSnap(t *testing.T, topology scenario.LBTopology) neutron.Snapshot {
	t.Helper()
	b := scenario.New()
	// The member's subnet must exist before the load balancer references
	// it — Member resolves the subnet to plug the Amphorae into.
	b.Network("net-back", "T1").
		Subnet("sub-back", "10.0.2.0/24", "10.0.2.1").
		VM("vm-backend", "T1", "10.0.2.10")
	b.Network("net-T1", "T1").
		Subnet("sub-vip", "10.0.1.0/24", "10.0.1.1").
		VM("vm-client", "T1", "10.0.1.5").
		LoadBalancer("lb1", "T1", "service", "10.0.1.50", topology).
		Member("sub-back", "10.0.2.10", 80).
		Done()
	return b.Build()
}

// TestLoadBalancer_ReattributesDataPortsOnly is the DSL's contract with
// the attribution join: the Amphora's data ports move from the service
// project to the load balancer's owner, and nothing else does.
func TestLoadBalancer_ReattributesDataPortsOnly(t *testing.T) {
	snap := lbSnap(t, scenario.Standalone)
	owners := neutron.AmphoraOwnerByPort(&snap)

	byID := make(map[string]neutron.Port, len(snap.Ports))
	for _, p := range snap.Ports {
		byID[p.ID] = p
	}
	for id, owner := range owners {
		if owner != "T1" {
			t.Errorf("port %s re-attributed to %q, want T1", id, owner)
		}
		if got := byID[id].ProjectID; got != "service" {
			t.Errorf("port %s started in %q, want service (nothing to re-attribute otherwise)", id, got)
		}
	}
	// The VIP reservation port already belongs to T1 and never reaches
	// the wire; the management port is control-plane traffic.
	for id := range owners {
		if id == "lb1-vip" {
			t.Error("the VIP reservation port was re-attributed; it is already the owner's")
		}
		if p := byID[id]; p.NetworkID == "net-lb-mgmt" {
			t.Errorf("management port %s was re-attributed; heartbeats are not tenant traffic", id)
		}
	}
	if len(owners) != 2 { // vrrp port + the plugged member-subnet port
		t.Errorf("re-attributed %d ports, want 2: %v", len(owners), owners)
	}
}

// TestLoadBalancer_ActiveStandbyDoublesEverything pins the HA shape: two
// Amphorae, each with its own base address and its own plugged port on
// the member subnet, all billing the one owner.
func TestLoadBalancer_ActiveStandbyDoublesEverything(t *testing.T) {
	snap := lbSnap(t, scenario.ActiveStandby)

	if len(snap.Amphorae) != 2 {
		t.Fatalf("got %d Amphorae, want 2", len(snap.Amphorae))
	}
	if a, b := snap.Amphorae[0], snap.Amphorae[1]; a.ComputeID == b.ComputeID {
		t.Error("both Amphorae share a Nova instance UUID; the join would collapse them")
	}
	owners := neutron.AmphoraOwnerByPort(&snap)
	if len(owners) != 4 { // 2 amphorae × (vrrp + member-subnet port)
		t.Errorf("re-attributed %d ports, want 4: %v", len(owners), owners)
	}

	// Every base address must reach the kernel set, or Segment 2 through
	// whichever Amphora is MASTER would zone as tenant traffic.
	base := neutron.AmphoraBaseIPs(&snap)
	if len(base) != 4 {
		t.Errorf("got %d base IPs, want 4: %+v", len(base), base)
	}
	seen := make(map[string]bool, len(base))
	for _, e := range base {
		if e.ProjectID != "T1" {
			t.Errorf("base IP %s scoped to %q, want T1", e.Addr, e.ProjectID)
		}
		if seen[e.Addr.String()] {
			t.Errorf("duplicate base IP %s across Amphorae", e.Addr)
		}
		seen[e.Addr.String()] = true
	}
	if seen["10.0.1.50"] {
		t.Error("the VIP is in the base-address set; Segment 1 would zone as infra")
	}
}

// TestLoadBalancer_SameSubnetMemberPlugsNothing covers the ordinary
// topology: a member on the VIP's own subnet is already L2-adjacent, so
// Octavia plugs no extra port.
func TestLoadBalancer_SameSubnetMemberPlugsNothing(t *testing.T) {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-vip", "10.0.1.0/24", "10.0.1.1").
		VM("vm-backend", "T1", "10.0.1.10").
		LoadBalancer("lb1", "T1", "service", "10.0.1.50", scenario.Standalone).
		Member("sub-vip", "10.0.1.10", 80).
		Done()
	snap := b.Build()

	if got := len(neutron.AmphoraOwnerByPort(&snap)); got != 1 {
		t.Errorf("re-attributed %d ports, want 1 (the vrrp port alone)", got)
	}
}
