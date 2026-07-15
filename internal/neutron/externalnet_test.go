package neutron

import "testing"

// extSnap builds the shared topology for the ExternalNetworkByPort
// tests: two external networks (one named, one nameless), one tenant
// subnet routed via a gateway router, one unrouted subnet.
func extSnap() Snapshot {
	return Snapshot{
		Networks: []Network{
			{ID: "net-pub1", Name: "public-1", IsExternal: true},
			{ID: "net-pub2", Name: "", IsExternal: true}, // nameless → ID fallback
			{ID: "net-priv", Name: "private-a"},
		},
		Subnets: []Subnet{
			{ID: "sub-routed", NetworkID: "net-priv", CIDR: "10.0.1.0/24"},
			{ID: "sub-isolated", NetworkID: "net-priv", CIDR: "10.0.2.0/24"},
		},
		Routers: []Router{
			{ID: "rtr-1", ExternalNetworkID: "net-pub1"},
			{ID: "rtr-nogw", ExternalNetworkID: ""},
		},
		Ports: []Port{
			// rtr-1's interface on sub-routed.
			{ID: "port-rtr1", DeviceOwner: DeviceOwnerRouterInterface, DeviceID: "rtr-1",
				FixedIPs: []FixedIP{{SubnetID: "sub-routed", IPAddress: "10.0.1.1"}}},
			// VM on the routed subnet, no FIP → router-gateway tier.
			{ID: "port-vm-routed", DeviceOwner: "compute:nova", DeviceID: "srv-1",
				FixedIPs: []FixedIP{{SubnetID: "sub-routed", IPAddress: "10.0.1.10"}}},
			// VM with a FIP from net-pub2 → FIP tier wins over its subnet's router.
			{ID: "port-vm-fip", DeviceOwner: "compute:nova", DeviceID: "srv-2",
				FixedIPs: []FixedIP{{SubnetID: "sub-routed", IPAddress: "10.0.1.11"}}},
			// VM on the isolated subnet → no attribution.
			{ID: "port-vm-isolated", DeviceOwner: "compute:nova", DeviceID: "srv-3",
				FixedIPs: []FixedIP{{SubnetID: "sub-isolated", IPAddress: "10.0.2.10"}}},
			// Router interface of a router with no gateway → contributes nothing.
			{ID: "port-rtr-nogw", DeviceOwner: DeviceOwnerRouterInterface, DeviceID: "rtr-nogw",
				FixedIPs: []FixedIP{{SubnetID: "sub-isolated", IPAddress: "10.0.2.1"}}},
		},
		FloatingIPs: []FloatingIP{
			{ID: "fip-1", PortID: "port-vm-fip", FloatingNetworkID: "net-pub2"},
			{ID: "fip-unbound", PortID: "", FloatingNetworkID: "net-pub1"},
		},
	}
}

func TestExternalNetworkByPort(t *testing.T) {
	snap := extSnap()
	got := ExternalNetworkByPort(&snap)

	want := map[string]string{
		"port-vm-routed": "public-1", // router gateway, network name
		"port-vm-fip":    "net-pub2", // FIP wins; nameless network falls back to ID
	}
	for port, ext := range want {
		if got[port] != ext {
			t.Errorf("port %s: external_network = %q, want %q", port, got[port], ext)
		}
	}
	for _, absent := range []string{"port-vm-isolated", "port-rtr1", "port-rtr-nogw"} {
		if v, ok := got[absent]; ok {
			t.Errorf("port %s: unexpected attribution %q, want none", absent, v)
		}
	}
}

func TestExternalNetworkByPortMultiPathDeterministic(t *testing.T) {
	snap := extSnap()
	// Give the FIP VM a second FIP on public-1: candidates are
	// {net-pub2, public-1}; the lexicographically smallest label wins,
	// and repeated calls agree.
	snap.FloatingIPs = append(snap.FloatingIPs,
		FloatingIP{ID: "fip-2", PortID: "port-vm-fip", FloatingNetworkID: "net-pub1"})

	first := ExternalNetworkByPort(&snap)
	if first["port-vm-fip"] != "net-pub2" {
		t.Errorf("multi-FIP pick = %q, want lexicographically smallest %q",
			first["port-vm-fip"], "net-pub2")
	}
	for i := 0; i < 5; i++ {
		again := ExternalNetworkByPort(&snap)
		if again["port-vm-fip"] != first["port-vm-fip"] {
			t.Fatalf("pick flapped across calls: %q vs %q", again["port-vm-fip"], first["port-vm-fip"])
		}
	}
}

func TestExternalNetworkByPortEmptySnapshot(t *testing.T) {
	snap := Snapshot{}
	if got := ExternalNetworkByPort(&snap); len(got) != 0 {
		t.Errorf("empty snapshot: got %v, want empty map", got)
	}
}
