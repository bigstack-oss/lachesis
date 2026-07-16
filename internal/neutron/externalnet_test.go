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
			{ID: "sub-routed", NetworkID: "net-priv", CIDR: "10.0.1.0/24", GatewayIP: "10.0.1.1"},
			{ID: "sub-isolated", NetworkID: "net-priv", CIDR: "10.0.2.0/24", GatewayIP: "10.0.2.1"},
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

// TestDetectMultiExternalPaths: the anomaly-side view of ambiguous
// attribution — VM ports with >1 distinct candidate surface as hits
// (feeding lachesis_neutron_anomalies{class="multi_external_path"} and
// /debug/anomalies), single-path and no-path ports do not, and the
// reported Picked matches what ExternalNetworkByPort attributes.
func TestDetectMultiExternalPaths(t *testing.T) {
	snap := extSnap()
	if hits := detectMultiExternalPaths(snap); len(hits) != 0 {
		t.Fatalf("unambiguous topology produced hits: %+v", hits)
	}

	// Second FIP on another network → port-vm-fip becomes ambiguous.
	snap.FloatingIPs = append(snap.FloatingIPs,
		FloatingIP{ID: "fip-2", PortID: "port-vm-fip", FloatingNetworkID: "net-pub1"})
	hits := detectMultiExternalPaths(snap)
	if len(hits) != 1 {
		t.Fatalf("hits = %+v, want exactly port-vm-fip", hits)
	}
	h := hits[0]
	if h.PortID != "port-vm-fip" || h.ServerID != "srv-2" {
		t.Errorf("hit identity wrong: %+v", h)
	}
	if len(h.Candidates) != 2 || h.Candidates[0] != "net-pub2" || h.Candidates[1] != "public-1" {
		t.Errorf("candidates = %v, want sorted [net-pub2 public-1]", h.Candidates)
	}
	if picked := ExternalNetworkByPort(&snap)["port-vm-fip"]; h.Picked != picked {
		t.Errorf("anomaly Picked %q disagrees with attribution %q", h.Picked, picked)
	}
}

// TestExternalNetworkByPortGatewayIPRule: two routers on one subnet
// with different external gateways is a LEGAL topology that is NOT
// ambiguous — the VM's default route points at the subnet's
// gateway_ip, so the router owning that IP is the deterministic
// egress. The second router must neither win attribution nor raise a
// multi_external_path anomaly.
func TestExternalNetworkByPortGatewayIPRule(t *testing.T) {
	snap := extSnap()
	// Second external network + second router attached to sub-routed
	// at a NON-gateway IP (rtr-1 holds the gateway 10.0.1.1).
	snap.Networks = append(snap.Networks, Network{ID: "net-pub3", Name: "public-3", IsExternal: true})
	snap.Routers = append(snap.Routers, Router{ID: "rtr-2", ExternalNetworkID: "net-pub3"})
	snap.Ports = append(snap.Ports, Port{
		ID: "port-rtr2", DeviceOwner: DeviceOwnerRouterInterface, DeviceID: "rtr-2",
		FixedIPs: []FixedIP{{SubnetID: "sub-routed", IPAddress: "10.0.1.254"}},
	})

	got := ExternalNetworkByPort(&snap)
	if got["port-vm-routed"] != "public-1" {
		t.Errorf("attribution = %q, want the gateway-owning router's %q", got["port-vm-routed"], "public-1")
	}
	if hits := detectMultiExternalPaths(snap); len(hits) != 0 {
		t.Errorf("gateway-IP rule should suppress the dual-router false positive, got %+v", hits)
	}

	// But when NO gateway-owning router has an external gateway
	// (rtr-1 loses its gateway), the non-gateway routers are the only
	// external evidence: both count, and the ambiguity is genuine.
	snap.Routers[0].ExternalNetworkID = ""
	snap.Routers = append(snap.Routers, Router{ID: "rtr-3", ExternalNetworkID: "net-pub2"})
	snap.Ports = append(snap.Ports, Port{
		ID: "port-rtr3", DeviceOwner: DeviceOwnerRouterInterface, DeviceID: "rtr-3",
		FixedIPs: []FixedIP{{SubnetID: "sub-routed", IPAddress: "10.0.1.253"}},
	})
	hits := detectMultiExternalPaths(snap)
	if len(hits) != 1 || hits[0].PortID != "port-vm-routed" {
		t.Fatalf("no-gateway fallback: hits = %+v, want port-vm-routed ambiguous", hits)
	}
}
