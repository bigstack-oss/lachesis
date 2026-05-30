package neutron

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
)

// fixture is a small declarative builder used by the resolver
// tests. It is intentionally minimal — the production scenario DSL
// (slated for a later slice) supersedes it.
type fixture struct {
	networks []Network
	subnets  []Subnet
	ports    []Port
	routers  []Router
}

func (f *fixture) addNetwork(id, project string, shared, external bool) {
	f.networks = append(f.networks, Network{
		ID: id, ProjectID: project, Shared: shared, IsExternal: external,
	})
}

func (f *fixture) addSubnet(id, networkID, project, cidr string) {
	f.subnets = append(f.subnets, Subnet{
		ID: id, NetworkID: networkID, ProjectID: project, CIDR: cidr, IPVersion: 4,
	})
}

func (f *fixture) addPort(id, networkID, project, owner, device string, fips ...FixedIP) {
	f.ports = append(f.ports, Port{
		ID: id, NetworkID: networkID, ProjectID: project,
		DeviceOwner: owner, DeviceID: device, FixedIPs: fips,
	})
}

func (f *fixture) addRouter(id, project string, routes ...Route) {
	f.routers = append(f.routers, Router{ID: id, ProjectID: project, Routes: routes})
}

func (f *fixture) index() *resolveIndex {
	return newResolveIndex(Snapshot{Networks: f.networks, Subnets: f.subnets, Ports: f.ports, Routers: f.routers})
}

func fip(subnetID, ip string) FixedIP { return FixedIP{SubnetID: subnetID, IPAddress: ip} }
func rte(dst, nh string) Route        { return Route{Destination: dst, Nexthop: nh} }

func TestResolveStaticRoute_SingleHopDirectAttach_OtherTenant(t *testing.T) {
	// R1 (T1) routes 10.50.0.0/16 via R2's IP on a shared transit.
	// R2 (T2) has 10.50.0.0/16 directly attached on net-T2.
	// Expected: OTHER_TENANT (T2's net, source T1).
	var f fixture
	f.addNetwork("net-T1", "T1", false, false)
	f.addNetwork("net-T2", "T2", false, false)
	f.addNetwork("transit", "admin", true, false)
	f.addSubnet("sub-T1", "net-T1", "T1", "10.0.0.0/24")
	f.addSubnet("sub-T2", "net-T2", "T2", "10.50.0.0/16")
	f.addSubnet("sub-tr", "transit", "admin", "192.168.100.0/24")
	f.addRouter("R1", "T1", rte("10.50.0.0/16", "192.168.100.20"))
	f.addRouter("R2", "T2")
	f.addPort("p-R1-T1", "net-T1", "T1", "network:router_interface", "R1", fip("sub-T1", "10.0.0.1"))
	f.addPort("p-R1-tr", "transit", "T1", "network:router_interface", "R1", fip("sub-tr", "192.168.100.10"))
	f.addPort("p-R2-T2", "net-T2", "T2", "network:router_interface", "R2", fip("sub-T2", "10.50.0.1"))
	f.addPort("p-R2-tr", "transit", "T2", "network:router_interface", "R2", fip("sub-tr", "192.168.100.20"))

	got, _ := f.index().resolveStaticRouteZone(f.routers[0],
		netip.MustParsePrefix("10.50.0.0/16"),
		netip.MustParseAddr("192.168.100.20"))
	if got != bpf.ZoneOtherTenant {
		t.Fatalf("zone = %v, want OTHER_TENANT", got)
	}
}

func TestResolveStaticRoute_VMApplianceNexthop_SameTenant(t *testing.T) {
	// R1 (T1) routes 172.16.99.0/24 via a VM appliance at 10.0.1.50 on net-T1.
	// Appliance VM is owned by T1, on T1's non-shared internal net.
	// Expected: SAME_TENANT (appliance owner T1 == source T1, on net-T1).
	var f fixture
	f.addNetwork("net-T1", "T1", false, false)
	f.addSubnet("sub-T1", "net-T1", "T1", "10.0.1.0/24")
	f.addRouter("R1", "T1", rte("172.16.99.0/24", "10.0.1.50"))
	f.addPort("p-R1-T1", "net-T1", "T1", "network:router_interface", "R1", fip("sub-T1", "10.0.1.1"))
	f.addPort("p-vm", "net-T1", "T1", "compute:nova", "instance-uuid", fip("sub-T1", "10.0.1.50"))

	got, _ := f.index().resolveStaticRouteZone(f.routers[0],
		netip.MustParsePrefix("172.16.99.0/24"),
		netip.MustParseAddr("10.0.1.50"))
	if got != bpf.ZoneSameTenant {
		t.Fatalf("zone = %v, want SAME_TENANT", got)
	}
}

func TestResolveStaticRoute_MultiHopChain_OtherTenant(t *testing.T) {
	// 3-router chain: R1 (T1) → R2 (T2) → R3 (T3).
	// transit-A connects R1↔R2, transit-B connects R2↔R3.
	// R3 has net-T3 (10.99.0.0/16) directly attached.
	// R1.extraroute: 10.99.0.0/16 via R2_in_A.
	// R2.extraroute: 10.99.0.0/16 via R3_in_B.
	// Expected: OTHER_TENANT (final owner T3, source T1).
	var f fixture
	f.addNetwork("net-T3", "T3", false, false)
	f.addNetwork("transit-A", "admin", true, false)
	f.addNetwork("transit-B", "admin", true, false)
	f.addSubnet("sub-T3", "net-T3", "T3", "10.99.0.0/16")
	f.addSubnet("sub-A", "transit-A", "admin", "10.10.1.0/24")
	f.addSubnet("sub-B", "transit-B", "admin", "10.10.2.0/24")
	f.addRouter("R1", "T1", rte("10.99.0.0/16", "10.10.1.2"))
	f.addRouter("R2", "T2", rte("10.99.0.0/16", "10.10.2.3"))
	f.addRouter("R3", "T3")
	f.addPort("p-R1-A", "transit-A", "T1", "network:router_interface", "R1", fip("sub-A", "10.10.1.1"))
	f.addPort("p-R2-A", "transit-A", "T2", "network:router_interface", "R2", fip("sub-A", "10.10.1.2"))
	f.addPort("p-R2-B", "transit-B", "T2", "network:router_interface", "R2", fip("sub-B", "10.10.2.2"))
	f.addPort("p-R3-B", "transit-B", "T3", "network:router_interface", "R3", fip("sub-B", "10.10.2.3"))
	f.addPort("p-R3-T3", "net-T3", "T3", "network:router_interface", "R3", fip("sub-T3", "10.99.0.1"))

	got, _ := f.index().resolveStaticRouteZone(f.routers[0],
		netip.MustParsePrefix("10.99.0.0/16"),
		netip.MustParseAddr("10.10.1.2"))
	if got != bpf.ZoneOtherTenant {
		t.Fatalf("zone = %v, want OTHER_TENANT", got)
	}
}

func TestResolveStaticRoute_Cycle_FallsBackExternal(t *testing.T) {
	// R1 ↔ R2 cycle via two transits.
	// R1.extraroute: 10.99.0.0/16 via R2_in_A.
	// R2.extraroute: 10.99.0.0/16 via R1_in_B.
	// Trace: hop 0 → R2; hop 1 → R1 (cycle, already visited).
	// Expected: EXTERNAL (cycle warn logged).
	var f fixture
	f.addNetwork("transit-A", "admin", true, false)
	f.addNetwork("transit-B", "admin", true, false)
	f.addSubnet("sub-A", "transit-A", "admin", "10.10.1.0/24")
	f.addSubnet("sub-B", "transit-B", "admin", "10.10.2.0/24")
	f.addRouter("R1", "admin", rte("10.99.0.0/16", "10.10.1.2"))
	f.addRouter("R2", "admin", rte("10.99.0.0/16", "10.10.2.1"))
	f.addPort("p-R1-A", "transit-A", "admin", "network:router_interface", "R1", fip("sub-A", "10.10.1.1"))
	f.addPort("p-R1-B", "transit-B", "admin", "network:router_interface", "R1", fip("sub-B", "10.10.2.1"))
	f.addPort("p-R2-A", "transit-A", "admin", "network:router_interface", "R2", fip("sub-A", "10.10.1.2"))
	f.addPort("p-R2-B", "transit-B", "admin", "network:router_interface", "R2", fip("sub-B", "10.10.2.2"))

	got, _ := f.index().resolveStaticRouteZone(f.routers[0],
		netip.MustParsePrefix("10.99.0.0/16"),
		netip.MustParseAddr("10.10.1.2"))
	if got != bpf.ZoneExternal {
		t.Fatalf("zone = %v, want EXTERNAL (cycle)", got)
	}
}

func TestResolveStaticRoute_MaxHopsExceeded_FallsBackExternal(t *testing.T) {
	// Chain of (maxStaticRouteHops + 1) routers, each forwarding
	// 10.99.0.0/16 to the next. The loop runs maxStaticRouteHops
	// times, advancing on every iteration; falls out the bottom
	// without ever finding a direct attach → MAX_HOPS exceeded.
	var f fixture
	const chainLen = maxStaticRouteHops + 1
	for i := 0; i < chainLen; i++ {
		// Transit i connects R(i+1) and R(i+2). CIDR 10.10.(i+1).0/24.
		netID := fmt.Sprintf("transit-%d", i)
		subID := fmt.Sprintf("sub-%d", i)
		cidr := fmt.Sprintf("10.10.%d.0/24", i+1)
		f.addNetwork(netID, "admin", true, false)
		f.addSubnet(subID, netID, "admin", cidr)
	}
	for i := 0; i < chainLen; i++ {
		rid := fmt.Sprintf("R%d", i+1)
		var routes []Route
		// Every router (including the last in the test chain) carries an
		// extraroute pointing to the next hop, so Step D always matches
		// and the loop runs the full maxStaticRouteHops iterations.
		// 10.10.(i+1).2 is R(i+2)'s IP on transit-i.
		nh := fmt.Sprintf("10.10.%d.2", i+1)
		routes = []Route{rte("10.99.0.0/16", nh)}
		f.addRouter(rid, "admin", routes...)
	}
	for i := 0; i < chainLen; i++ {
		// R(i+1) has interfaces on transit-(i-1) (incoming) and
		// transit-i (outgoing). Skip the incoming side for i==0
		// (R1 is the source).
		rid := fmt.Sprintf("R%d", i+1)
		if i > 0 {
			prevNetID := fmt.Sprintf("transit-%d", i-1)
			prevSubID := fmt.Sprintf("sub-%d", i-1)
			f.addPort(fmt.Sprintf("p-%s-in", rid), prevNetID, "admin",
				"network:router_interface", rid,
				fip(prevSubID, fmt.Sprintf("10.10.%d.2", i)))
		}
		netID := fmt.Sprintf("transit-%d", i)
		subID := fmt.Sprintf("sub-%d", i)
		f.addPort(fmt.Sprintf("p-%s-out", rid), netID, "admin",
			"network:router_interface", rid,
			fip(subID, fmt.Sprintf("10.10.%d.1", i+1)))
	}

	got, _ := f.index().resolveStaticRouteZone(f.routers[0],
		netip.MustParsePrefix("10.99.0.0/16"),
		netip.MustParseAddr("10.10.1.2"))
	if got != bpf.ZoneExternal {
		t.Fatalf("zone = %v, want EXTERNAL (MAX_HOPS)", got)
	}
}

func TestResolveStaticRoute_AmbiguousOwners_FallsBackExternal(t *testing.T) {
	// R2 has two attached subnets, each on a different network owned
	// by a different tenant, and both supersets of the destination.
	// Step C detects multiple distinct owners → EXTERNAL.
	var f fixture
	f.addNetwork("net-T2", "T2", false, false)
	f.addNetwork("net-T3", "T3", false, false)
	f.addNetwork("transit", "admin", true, false)
	f.addSubnet("sub-T2", "net-T2", "T2", "10.99.0.0/16") // owns 10.99.0.0/16
	f.addSubnet("sub-T3", "net-T3", "T3", "10.99.0.0/16") // also owns 10.99.0.0/16 (different tenant)
	f.addSubnet("sub-tr", "transit", "admin", "192.168.100.0/24")
	f.addRouter("R1", "T1", rte("10.99.50.0/24", "192.168.100.20"))
	f.addRouter("R2", "T2")
	f.addPort("p-R1-tr", "transit", "T1", "network:router_interface", "R1", fip("sub-tr", "192.168.100.10"))
	f.addPort("p-R2-tr", "transit", "T2", "network:router_interface", "R2", fip("sub-tr", "192.168.100.20"))
	f.addPort("p-R2-T2", "net-T2", "T2", "network:router_interface", "R2", fip("sub-T2", "10.99.0.1"))
	f.addPort("p-R2-T3", "net-T3", "T3", "network:router_interface", "R2", fip("sub-T3", "10.99.0.1"))

	got, _ := f.index().resolveStaticRouteZone(f.routers[0],
		netip.MustParsePrefix("10.99.50.0/24"),
		netip.MustParseAddr("192.168.100.20"))
	if got != bpf.ZoneExternal {
		t.Fatalf("zone = %v, want EXTERNAL (ambiguous)", got)
	}
}

func TestResolveStaticRoute_NexthopOffNet_FallsBackExternal(t *testing.T) {
	// Step A miss: nexthop is not contained in any of R1's iface subnets.
	// Operator misconfig — Neutron permits it; we classify EXTERNAL.
	var f fixture
	f.addNetwork("net-T1", "T1", false, false)
	f.addSubnet("sub-T1", "net-T1", "T1", "10.0.0.0/24")
	f.addRouter("R1", "T1", rte("10.99.0.0/16", "192.168.99.99"))
	f.addPort("p-R1-T1", "net-T1", "T1", "network:router_interface", "R1", fip("sub-T1", "10.0.0.1"))

	got, _ := f.index().resolveStaticRouteZone(f.routers[0],
		netip.MustParsePrefix("10.99.0.0/16"),
		netip.MustParseAddr("192.168.99.99"))
	if got != bpf.ZoneExternal {
		t.Fatalf("zone = %v, want EXTERNAL (Step A miss)", got)
	}
}

func TestResolveStaticRoute_PeerUnknownDeviceOwner_FallsBackExternal(t *testing.T) {
	// Step B switch default: peer port at the nexthop IP is neither a
	// router_interface nor a compute:nova — e.g. network:floatingip
	// bookkeeping port. Falls to EXTERNAL.
	var f fixture
	f.addNetwork("transit", "admin", true, false)
	f.addSubnet("sub-tr", "transit", "admin", "10.10.1.0/24")
	f.addRouter("R1", "T1", rte("10.99.0.0/16", "10.10.1.50"))
	f.addPort("p-R1-tr", "transit", "T1", "network:router_interface", "R1", fip("sub-tr", "10.10.1.1"))
	f.addPort("p-fip", "transit", "T1", "network:floatingip", "", fip("sub-tr", "10.10.1.50"))

	got, _ := f.index().resolveStaticRouteZone(f.routers[0],
		netip.MustParsePrefix("10.99.0.0/16"),
		netip.MustParseAddr("10.10.1.50"))
	if got != bpf.ZoneExternal {
		t.Fatalf("zone = %v, want EXTERNAL (unknown peer device)", got)
	}
}

func TestResolveStaticRoute_VMApplianceOnSharedNetwork_Shared(t *testing.T) {
	// VM appliance on a shared network, even when its owner matches
	// the source tenant, must classify SHARED (not SAME). The trie
	// cannot resolve per-VM ownership inside a shared CIDR; SHARED
	// is the honest label for the L3-routed-fallback case. Exercises
	// zoneFor's external/shared/owner precedence at the resolver
	// boundary, separate from the unit-level TestZoneFor.
	var f fixture
	f.addNetwork("shared-net", "admin", true, false) // shared=true
	f.addSubnet("sub-sh", "shared-net", "admin", "10.5.0.0/24")
	f.addRouter("R1", "T1", rte("172.16.99.0/24", "10.5.0.50"))
	f.addPort("p-R1-sh", "shared-net", "T1", "network:router_interface", "R1", fip("sub-sh", "10.5.0.1"))
	f.addPort("p-vm", "shared-net", "T1", "compute:nova", "instance-uuid", fip("sub-sh", "10.5.0.50"))

	got, _ := f.index().resolveStaticRouteZone(f.routers[0],
		netip.MustParsePrefix("172.16.99.0/24"),
		netip.MustParseAddr("10.5.0.50"))
	if got != bpf.ZoneShared {
		t.Fatalf("zone = %v, want SHARED (VM appliance on shared net)", got)
	}
}

func TestResolveStaticRoute_StepD_LPMPicksLongestPrefix(t *testing.T) {
	// R2 has two extraroutes covering destination 10.99.0.0/24:
	//   /16 via a black-hole IP (peer port absent — Step A would
	//        miss next hop, returning EXTERNAL)
	//   /24 via R3's interface (peer R3 has 10.99.0.0/24 directly
	//        attached on T3's network)
	// If LPM picks /24 (correct), final zone is OTHER_TENANT (T3 ≠ T1).
	// If LPM mistakenly picks /16, the trace dead-ends at EXTERNAL.
	var f fixture
	f.addNetwork("net-T3", "T3", false, false)
	f.addNetwork("transit-A", "admin", true, false)
	f.addNetwork("transit-B", "admin", true, false)
	f.addSubnet("sub-T3", "net-T3", "T3", "10.99.0.0/24")
	f.addSubnet("sub-A", "transit-A", "admin", "10.10.1.0/24")
	f.addSubnet("sub-B", "transit-B", "admin", "10.10.2.0/24")
	f.addRouter("R1", "T1", rte("10.99.0.0/24", "10.10.1.2"))
	f.addRouter("R2", "T2",
		rte("10.99.0.0/16", "10.10.2.99"), // black hole, no peer port at .99
		rte("10.99.0.0/24", "10.10.2.3"),  // hits R3
	)
	f.addRouter("R3", "T3")
	f.addPort("p-R1-A", "transit-A", "T1", "network:router_interface", "R1", fip("sub-A", "10.10.1.1"))
	f.addPort("p-R2-A", "transit-A", "T2", "network:router_interface", "R2", fip("sub-A", "10.10.1.2"))
	f.addPort("p-R2-B", "transit-B", "T2", "network:router_interface", "R2", fip("sub-B", "10.10.2.2"))
	f.addPort("p-R3-B", "transit-B", "T3", "network:router_interface", "R3", fip("sub-B", "10.10.2.3"))
	f.addPort("p-R3-T3", "net-T3", "T3", "network:router_interface", "R3", fip("sub-T3", "10.99.0.1"))

	got, _ := f.index().resolveStaticRouteZone(f.routers[0],
		netip.MustParsePrefix("10.99.0.0/24"),
		netip.MustParseAddr("10.10.1.2"))
	if got != bpf.ZoneOtherTenant {
		t.Fatalf("zone = %v, want OTHER_TENANT (LPM should pick /24)", got)
	}
}

func TestResolveStaticRoute_VMApplianceCrossTenant_Other(t *testing.T) {
	// Appliance VM owned by T2 attached to a non-shared internal
	// network (admin-attached), source tenant T1. zoneFor maps to
	// OTHER_TENANT (T2 ≠ T1, not shared, not external).
	var f fixture
	f.addNetwork("net-svc", "admin", false, false) // non-shared, non-external; admin-owned
	f.addSubnet("sub-svc", "net-svc", "admin", "10.20.0.0/24")
	f.addRouter("R1", "T1", rte("10.99.0.0/16", "10.20.0.50"))
	f.addPort("p-R1-svc", "net-svc", "T1", "network:router_interface", "R1", fip("sub-svc", "10.20.0.1"))
	f.addPort("p-vm-T2", "net-svc", "T2", "compute:nova", "instance-uuid", fip("sub-svc", "10.20.0.50"))

	got, _ := f.index().resolveStaticRouteZone(f.routers[0],
		netip.MustParsePrefix("10.99.0.0/16"),
		netip.MustParseAddr("10.20.0.50"))
	if got != bpf.ZoneOtherTenant {
		t.Fatalf("zone = %v, want OTHER_TENANT (cross-tenant appliance)", got)
	}
}

func TestResolveStaticRoute_StepC_SameOwnerAcrossMatches_NoAmbiguity(t *testing.T) {
	// R2 has TWO interfaces on different networks, both owned by T2,
	// both with subnets that supersets the destination. matchedOwners
	// de-dups to a single owner — no ambiguity, single zone returned.
	var f fixture
	f.addNetwork("net-T2-a", "T2", false, false)
	f.addNetwork("net-T2-b", "T2", false, false)
	f.addNetwork("transit", "admin", true, false)
	f.addSubnet("sub-T2-a", "net-T2-a", "T2", "10.99.0.0/16")
	f.addSubnet("sub-T2-b", "net-T2-b", "T2", "10.99.0.0/16") // duplicate CIDR, same owner, different network
	f.addSubnet("sub-tr", "transit", "admin", "192.168.100.0/24")
	f.addRouter("R1", "T1", rte("10.99.50.0/24", "192.168.100.20"))
	f.addRouter("R2", "T2")
	f.addPort("p-R1-tr", "transit", "T1", "network:router_interface", "R1", fip("sub-tr", "192.168.100.10"))
	f.addPort("p-R2-tr", "transit", "T2", "network:router_interface", "R2", fip("sub-tr", "192.168.100.20"))
	f.addPort("p-R2-a", "net-T2-a", "T2", "network:router_interface", "R2", fip("sub-T2-a", "10.99.0.1"))
	f.addPort("p-R2-b", "net-T2-b", "T2", "network:router_interface", "R2", fip("sub-T2-b", "10.99.0.1"))

	got, _ := f.index().resolveStaticRouteZone(f.routers[0],
		netip.MustParsePrefix("10.99.50.0/24"),
		netip.MustParseAddr("192.168.100.20"))
	if got != bpf.ZoneOtherTenant {
		t.Fatalf("zone = %v, want OTHER_TENANT (same-owner merge, no ambiguity)", got)
	}
}

func TestResolveStaticRoute_RouterInterfacePeerWithStaleDeviceID_FallsBackExternal(t *testing.T) {
	// Defensive: a port labelled network:router_interface points
	// (via DeviceID) at a router that's missing from the snapshot
	// (e.g. stale Neutron data after a router delete). Step B's
	// router-lookup fails — falls to EXTERNAL rather than crashing.
	var f fixture
	f.addNetwork("transit", "admin", true, false)
	f.addSubnet("sub-tr", "transit", "admin", "10.10.1.0/24")
	f.addRouter("R1", "T1", rte("10.99.0.0/16", "10.10.1.50"))
	f.addPort("p-R1-tr", "transit", "T1", "network:router_interface", "R1", fip("sub-tr", "10.10.1.1"))
	// Ghost peer: device_owner says router_interface, DeviceID names a router that doesn't exist.
	f.addPort("p-ghost", "transit", "T1", "network:router_interface", "ghost-router", fip("sub-tr", "10.10.1.50"))

	got, _ := f.index().resolveStaticRouteZone(f.routers[0],
		netip.MustParsePrefix("10.99.0.0/16"),
		netip.MustParseAddr("10.10.1.50"))
	if got != bpf.ZoneExternal {
		t.Fatalf("zone = %v, want EXTERNAL (stale router_interface)", got)
	}
}

func TestResolveStaticRoute_NoDirectNoExtraroute_FallsBackExternal(t *testing.T) {
	// Step E: R2 has neither a directly-attached supernet for the
	// destination nor an extraroute matching it. Falls to EXTERNAL.
	var f fixture
	f.addNetwork("net-T2", "T2", false, false)
	f.addNetwork("transit", "admin", true, false)
	f.addSubnet("sub-T2", "net-T2", "T2", "10.50.0.0/16") // does NOT cover 10.99
	f.addSubnet("sub-tr", "transit", "admin", "192.168.100.0/24")
	f.addRouter("R1", "T1", rte("10.99.0.0/16", "192.168.100.20"))
	f.addRouter("R2", "T2") // no extraroute
	f.addPort("p-R1-tr", "transit", "T1", "network:router_interface", "R1", fip("sub-tr", "192.168.100.10"))
	f.addPort("p-R2-tr", "transit", "T2", "network:router_interface", "R2", fip("sub-tr", "192.168.100.20"))
	f.addPort("p-R2-T2", "net-T2", "T2", "network:router_interface", "R2", fip("sub-T2", "10.50.0.1"))

	got, _ := f.index().resolveStaticRouteZone(f.routers[0],
		netip.MustParsePrefix("10.99.0.0/16"),
		netip.MustParseAddr("192.168.100.20"))
	if got != bpf.ZoneExternal {
		t.Fatalf("zone = %v, want EXTERNAL (Step E unreachable)", got)
	}
}

func TestZoneFor(t *testing.T) {
	const (
		t1 = "tenant-1"
		t2 = "tenant-2"
	)
	tests := []struct {
		name    string
		owner   string
		source  string
		network Network
		want    bpf.ZoneCode
	}{
		{
			name:    "external network classifies EXTERNAL regardless of owner",
			owner:   t1,
			source:  t1,
			network: Network{IsExternal: true},
			want:    bpf.ZoneExternal,
		},
		{
			name:    "shared non-external network classifies SHARED",
			owner:   t2,
			source:  t1,
			network: Network{Shared: true},
			want:    bpf.ZoneShared,
		},
		{
			name:    "internal non-shared owned by source tenant classifies SAME_TENANT",
			owner:   t1,
			source:  t1,
			network: Network{},
			want:    bpf.ZoneSameTenant,
		},
		{
			name:    "internal non-shared owned by peer tenant classifies OTHER_TENANT",
			owner:   t2,
			source:  t1,
			network: Network{},
			want:    bpf.ZoneOtherTenant,
		},
		{
			name:    "external precedence: external+shared classifies EXTERNAL (external wins)",
			owner:   t1,
			source:  t1,
			network: Network{IsExternal: true, Shared: true},
			want:    bpf.ZoneExternal,
		},
		{
			name:    "shared precedence: shared owned by source classifies SHARED (shared wins over owner==source)",
			owner:   t1,
			source:  t1,
			network: Network{Shared: true},
			want:    bpf.ZoneShared,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := zoneFor(tc.owner, tc.source, tc.network)
			if got != tc.want {
				t.Errorf("zoneFor(owner=%q, source=%q, network=%+v) = %v, want %v",
					tc.owner, tc.source, tc.network, got, tc.want)
			}
		})
	}
}
