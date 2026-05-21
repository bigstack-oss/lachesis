package neutron

import (
	"reflect"
	"testing"
)

// TestDetectAnomalies_EmptyAndPassthrough covers two trivial cases:
// an entirely-empty snapshot produces zero anomalies, and Detect
// faithfully copies cycle + ambiguity slices through to the result
// (it owns no detection logic for those — BuildTrie does).
func TestDetectAnomalies_EmptyAndPassthrough(t *testing.T) {
	t.Run("empty snapshot", func(t *testing.T) {
		got := DetectAnomalies(Snapshot{}, nil, nil, nil)
		if got.Total() != 0 {
			t.Fatalf("Total() = %d, want 0; anomalies=%+v", got.Total(), got)
		}
	})

	t.Run("cycle and ambiguity pass-through", func(t *testing.T) {
		cycles := []CycleHit{{
			SourceTenant: "T1", SourceRouter: "rA",
			Destination: mustPrefix(t, "10.0.0.0/24"), LoopRouter: "rB",
		}}
		ambigs := []AmbiguityHit{{
			SourceTenant: "T1", RouterID: "rA",
			Destination: mustPrefix(t, "10.0.0.0/24"),
			Owners:      []string{"T2", "T3"},
		}}
		got := DetectAnomalies(Snapshot{}, nil, cycles, ambigs)
		if !reflect.DeepEqual(got.Cycles, cycles) {
			t.Errorf("Cycles = %+v, want %+v", got.Cycles, cycles)
		}
		if !reflect.DeepEqual(got.Ambiguities, ambigs) {
			t.Errorf("Ambiguities = %+v, want %+v", got.Ambiguities, ambigs)
		}
	})
}

// TestDetectAnomalies_DanglingRoutes exercises the four-way matrix
// of a route's nexthop: matches a port (clean), matches no port
// (dangling), empty nexthop (skipped), IPv6 nexthop matching no
// port (still surfaced — operator-visible misconfig regardless of
// kernel-trie eligibility).
func TestDetectAnomalies_DanglingRoutes(t *testing.T) {
	snap := Snapshot{
		Ports: []Port{
			{ID: "p1", DeviceOwner: "network:router_interface", FixedIPs: []FixedIP{{IPAddress: "10.0.0.1"}}},
			{ID: "p2", DeviceOwner: "compute:nova", FixedIPs: []FixedIP{{IPAddress: "10.0.0.50"}}},
		},
		Routers: []Router{
			{ID: "rA", ProjectID: "T1", Routes: []Route{
				{Destination: "192.168.1.0/24", Nexthop: "10.0.0.1"},  // resolves → clean
				{Destination: "192.168.2.0/24", Nexthop: "10.0.0.50"}, // resolves to VM → still clean (any port counts)
				{Destination: "192.168.3.0/24", Nexthop: "10.0.0.99"}, // no match → dangling
				{Destination: "192.168.4.0/24", Nexthop: ""},          // empty → skipped
			}},
			{ID: "rB", ProjectID: "T2", Routes: []Route{
				{Destination: "fd00::/64", Nexthop: "fe80::abcd"}, // IPv6, no port → dangling
			}},
		},
	}
	// Suppress zero-trie hits for T1/T2 by passing trie entries that
	// cover them; otherwise the routers' tenants would surface in
	// ZeroTrieTenants and contaminate this test's scope.
	trie := []TrieEntry{
		{TenantID: "T1", Prefix: mustPrefix(t, "10.0.0.0/24")},
		{TenantID: "T2", Prefix: mustPrefix(t, "10.0.1.0/24")},
	}
	got := DetectAnomalies(snap, trie, nil, nil)
	want := []DanglingRoute{
		{SourceTenant: "T1", SourceRouter: "rA", Destination: "192.168.3.0/24", Nexthop: "10.0.0.99"},
		{SourceTenant: "T2", SourceRouter: "rB", Destination: "fd00::/64", Nexthop: "fe80::abcd"},
	}
	if !reflect.DeepEqual(got.DanglingRoutes, want) {
		t.Fatalf("DanglingRoutes mismatch\n got=%+v\nwant=%+v", got.DanglingRoutes, want)
	}
	if len(got.ZeroTrieTenants) != 0 || len(got.DuplicateRouterMACs) != 0 {
		t.Errorf("unexpected anomalies in other classes: %+v", got)
	}
}

// TestDetectAnomalies_ZeroTrieTenants: tenant T-net owns a network,
// T-port owns a VM port, T-router owns a router; none have a
// matching TrieEntry → all three appear. T-covered owns a network
// AND has a trie entry → omitted. Empty ProjectIDs are ignored
// throughout.
func TestDetectAnomalies_ZeroTrieTenants(t *testing.T) {
	snap := Snapshot{
		Networks: []Network{
			{ID: "n1", ProjectID: "T-net"},
			{ID: "n2", ProjectID: "T-covered"},
			{ID: "n3", ProjectID: ""}, // ignored
		},
		Routers: []Router{
			{ID: "r1", ProjectID: "T-router"},
		},
		Ports: []Port{
			{ID: "p1", ProjectID: "T-port", DeviceOwner: "compute:nova"},
			{ID: "p2", ProjectID: "T-port", DeviceOwner: "compute:nova"},
			{ID: "p3", ProjectID: "T-net", DeviceOwner: "network:router_interface"}, // infra port: doesn't bump Ports
		},
	}
	trie := []TrieEntry{
		{TenantID: "T-covered", Prefix: mustPrefix(t, "10.0.0.0/24")},
		{TenantID: "", Prefix: mustPrefix(t, "0.0.0.0/0")}, // sentinel: should not satisfy any tenant
	}
	got := DetectAnomalies(snap, trie, nil, nil)
	want := []ZeroTrieTenant{
		{TenantID: "T-net", Networks: 1, Routers: 0, Ports: 0},
		{TenantID: "T-port", Networks: 0, Routers: 0, Ports: 2},
		{TenantID: "T-router", Networks: 0, Routers: 1, Ports: 0},
	}
	if !reflect.DeepEqual(got.ZeroTrieTenants, want) {
		t.Fatalf("ZeroTrieTenants mismatch\n got=%+v\nwant=%+v", got.ZeroTrieTenants, want)
	}
}

// TestDetectAnomalies_DuplicateRouterMACs verifies grouping logic
// for router_interface ports. Non-router ports sharing a MAC are
// ignored (a Nova VM duplicating its router's MAC would be a kernel
// problem, not a Neutron-snapshot problem). DeviceID is collapsed
// to the unique RouterIDs slice.
func TestDetectAnomalies_DuplicateRouterMACs(t *testing.T) {
	snap := Snapshot{
		Ports: []Port{
			{ID: "p-A1", DeviceOwner: "network:router_interface", DeviceID: "rA", MACAddress: "fa:16:3e:00:00:01"},
			{ID: "p-A2", DeviceOwner: "network:router_interface", DeviceID: "rA", MACAddress: "fa:16:3e:00:00:01"}, // dup, same router
			{ID: "p-B",  DeviceOwner: "network:router_interface", DeviceID: "rB", MACAddress: "fa:16:3e:00:00:01"}, // dup, different router
			{ID: "p-C",  DeviceOwner: "network:router_interface", DeviceID: "rC", MACAddress: "fa:16:3e:00:00:02"}, // unique
			{ID: "p-vm", DeviceOwner: "compute:nova",             DeviceID: "vmA", MACAddress: "fa:16:3e:00:00:02"}, // VM with same MAC as p-C → ignored
		},
	}
	got := DetectAnomalies(snap, nil, nil, nil)
	want := []DuplicateRouterMAC{
		{MAC: "fa:16:3e:00:00:01", PortIDs: []string{"p-A1", "p-A2", "p-B"}, RouterIDs: []string{"rA", "rB"}},
	}
	if !reflect.DeepEqual(got.DuplicateRouterMACs, want) {
		t.Fatalf("DuplicateRouterMACs mismatch\n got=%+v\nwant=%+v", got.DuplicateRouterMACs, want)
	}
}

// TestDetectAnomalies_StableOrder: two runs over the same snapshot
// must produce identical output, regardless of map iteration order
// inside the detectors. Run the same input five times — anything
// less and a map-order regression hides behind chance.
func TestDetectAnomalies_StableOrder(t *testing.T) {
	snap := Snapshot{
		Networks: []Network{
			{ID: "n-a", ProjectID: "T-a"},
			{ID: "n-b", ProjectID: "T-b"},
			{ID: "n-c", ProjectID: "T-c"},
		},
		Ports: []Port{
			{ID: "p-1", DeviceOwner: "network:router_interface", DeviceID: "rX", MACAddress: "aa:aa:aa:aa:aa:01"},
			{ID: "p-2", DeviceOwner: "network:router_interface", DeviceID: "rY", MACAddress: "aa:aa:aa:aa:aa:01"},
			{ID: "p-3", DeviceOwner: "network:router_interface", DeviceID: "rX", MACAddress: "aa:aa:aa:aa:aa:02"},
			{ID: "p-4", DeviceOwner: "network:router_interface", DeviceID: "rY", MACAddress: "aa:aa:aa:aa:aa:02"},
		},
		Routers: []Router{
			{ID: "rX", ProjectID: "T-a", Routes: []Route{
				{Destination: "192.168.0.0/24", Nexthop: "10.0.0.99"},
				{Destination: "192.168.1.0/24", Nexthop: "10.0.0.98"},
			}},
		},
	}
	first := DetectAnomalies(snap, nil, nil, nil)
	for i := 0; i < 5; i++ {
		got := DetectAnomalies(snap, nil, nil, nil)
		if !reflect.DeepEqual(got, first) {
			t.Fatalf("non-deterministic output at iteration %d\nfirst=%+v\n got=%+v", i, first, got)
		}
	}
}

