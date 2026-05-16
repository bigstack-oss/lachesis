package neutron

// Golden-file scenario tests for BuildTrie. Each test reconstructs
// the Neutron snapshot that would correspond to a documented
// scenario (docs/DESIGN.md §B Scenarios A–L) and asserts the trie
// rows the builder emits.
//
// The scenarios exercise the four implemented trie-builder steps:
//
//	Step 1 (catchall): every test confirms 0.0.0.0/0 → EXTERNAL
//	Step 2 (owned)   : non-shared, non-external subnets → SAME_TENANT
//	Step 3 (shared)  : shared subnets → SHARED (uniform across tenants)
//	Step 4 (infra)   : router/gateway/metadata /32s → INFRA
//
// Step 5 (static-route resolver) is intentionally omitted — that's
// Sprint 4b territory. Scenarios G, H, K, L from DESIGN.md are
// therefore not exercised here.
//
// Fixtures are in-Go struct literals rather than recorded JSON
// because Sprint 4b will land a scenario DSL that replaces these
// tests; minimising the throwaway surface keeps the eventual
// migration small.

import (
	"net/netip"
	"testing"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
)

// expects passes if BuildTrie's output contains every (tenant, prefix, zone)
// row in want. Extra rows are tolerated — the trie may always carry
// catchall + metadata INFRA + infra port /32s alongside the rows the
// scenario specifically cares about.
func expects(t *testing.T, got []TrieEntry, want []TrieEntry) {
	t.Helper()
	for _, w := range want {
		if !containsEntry(got, w) {
			t.Errorf("missing expected row: tenant=%s prefix=%s zone=%v\nactual entries: %v",
				w.TenantID, w.Prefix, w.Zone, got)
		}
	}
}

// rejects fails if BuildTrie's output contains any row in deny.
// Used to assert "this CIDR must NOT appear under this tenant with
// this zone" — e.g. an external CIDR must not surface as OTHER_TENANT.
func rejects(t *testing.T, got []TrieEntry, deny []TrieEntry) {
	t.Helper()
	for _, d := range deny {
		if containsEntry(got, d) {
			t.Errorf("forbidden row present: tenant=%s prefix=%s zone=%v",
				d.TenantID, d.Prefix, d.Zone)
		}
	}
}

func containsEntry(entries []TrieEntry, target TrieEntry) bool {
	for _, e := range entries {
		if e == target {
			return true
		}
	}
	return false
}

func cidr(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func catchallRow(t string) TrieEntry {
	return TrieEntry{TenantID: t, Prefix: cidr("0.0.0.0/0"), Zone: bpf.ZoneExternal}
}

func metadataRow(t string) TrieEntry {
	return TrieEntry{TenantID: t, Prefix: cidr("169.254.169.254/32"), Zone: bpf.ZoneInfra}
}

// ----- Scenario A — Same tenant, same subnet (direct L2) -----

// Single tenant, single network, single /24 subnet, two VMs.
// BuildTrie output for T1 must contain the SAME_TENANT /24 row for
// the subnet — even though A's per-packet path is MAC-first and
// never consults the trie, the trie has to be ready in case L2
// resolution fails.

func TestScenario_A_SameTenantSameSubnet(t *testing.T) {
	snap := scenarioA()
	got := BuildTrie(snap.Networks, snap.Subnets, snap.Ports, snap.Routers)
	expects(t, got, []TrieEntry{
		catchallRow("T1"),
		{TenantID: "T1", Prefix: cidr("10.0.1.0/24"), Zone: bpf.ZoneSameTenant},
		metadataRow("T1"),
	})
}

func scenarioA() Snapshot {
	return Snapshot{
		Networks: []Network{{ID: "n1", ProjectID: "T1"}},
		Subnets: []Subnet{
			{ID: "s1", NetworkID: "n1", ProjectID: "T1", CIDR: "10.0.1.0/24", IPVersion: 4},
		},
		Ports: []Port{
			{ID: "p-vm-a", NetworkID: "n1", ProjectID: "T1", MACAddress: "fa:16:3e:00:00:01", DeviceOwner: "compute:nova",
				FixedIPs: []FixedIP{{SubnetID: "s1", IPAddress: "10.0.1.5"}}},
			{ID: "p-vm-b", NetworkID: "n1", ProjectID: "T1", MACAddress: "fa:16:3e:00:00:02", DeviceOwner: "compute:nova",
				FixedIPs: []FixedIP{{SubnetID: "s1", IPAddress: "10.0.1.6"}}},
		},
	}
}

// ----- Scenario B — Same tenant, different subnets via router -----

// T1 owns two subnets (s1 + s2) on different networks, plus a
// router that interfaces both. BuildTrie produces SAME_TENANT for
// both /24s; the router-interface ports contribute INFRA /32s.

func TestScenario_B_SameTenantViaRouter(t *testing.T) {
	snap := scenarioB()
	got := BuildTrie(snap.Networks, snap.Subnets, snap.Ports, snap.Routers)
	expects(t, got, []TrieEntry{
		catchallRow("T1"),
		{TenantID: "T1", Prefix: cidr("10.0.1.0/24"), Zone: bpf.ZoneSameTenant},
		{TenantID: "T1", Prefix: cidr("10.0.2.0/24"), Zone: bpf.ZoneSameTenant},
		{TenantID: "T1", Prefix: cidr("10.0.1.1/32"), Zone: bpf.ZoneInfra}, // router IF on subnet1
		{TenantID: "T1", Prefix: cidr("10.0.2.1/32"), Zone: bpf.ZoneInfra}, // router IF on subnet2
		metadataRow("T1"),
	})
}

func scenarioB() Snapshot {
	return Snapshot{
		Networks: []Network{
			{ID: "n1", ProjectID: "T1"},
			{ID: "n2", ProjectID: "T1"},
		},
		Subnets: []Subnet{
			{ID: "s1", NetworkID: "n1", ProjectID: "T1", CIDR: "10.0.1.0/24", GatewayIP: "10.0.1.1", IPVersion: 4},
			{ID: "s2", NetworkID: "n2", ProjectID: "T1", CIDR: "10.0.2.0/24", GatewayIP: "10.0.2.1", IPVersion: 4},
		},
		Ports: []Port{
			{ID: "p-r1-if1", NetworkID: "n1", ProjectID: "T1", MACAddress: "fa:16:3e:00:00:10", DeviceOwner: "network:router_interface",
				FixedIPs: []FixedIP{{SubnetID: "s1", IPAddress: "10.0.1.1"}}},
			{ID: "p-r1-if2", NetworkID: "n2", ProjectID: "T1", MACAddress: "fa:16:3e:00:00:11", DeviceOwner: "network:router_interface",
				FixedIPs: []FixedIP{{SubnetID: "s2", IPAddress: "10.0.2.1"}}},
		},
		Routers: []Router{{ID: "r1", ProjectID: "T1"}},
	}
}

// ----- Scenario C — Cross-tenant via shared network -----

// T1 and T2 each own their own subnets; T-shared (admin) owns a
// shared network. From each tenant's view, the shared CIDR is
// SHARED (not OTHER_TENANT — see DESIGN §5.2 Step 3 for why) while
// the tenant's own subnet is SAME_TENANT.

func TestScenario_C_CrossTenantViaShared(t *testing.T) {
	snap := scenarioC()
	got := BuildTrie(snap.Networks, snap.Subnets, snap.Ports, snap.Routers)
	expects(t, got, []TrieEntry{
		// T1's view
		catchallRow("T1"),
		{TenantID: "T1", Prefix: cidr("10.0.1.0/24"), Zone: bpf.ZoneSameTenant},
		{TenantID: "T1", Prefix: cidr("10.10.0.0/24"), Zone: bpf.ZoneShared},
		// T2's view
		catchallRow("T2"),
		{TenantID: "T2", Prefix: cidr("10.0.2.0/24"), Zone: bpf.ZoneSameTenant},
		{TenantID: "T2", Prefix: cidr("10.10.0.0/24"), Zone: bpf.ZoneShared},
	})
	// The shared CIDR must not appear as OTHER_TENANT — the design
	// uses ZONE_SHARED specifically because the trie can't resolve
	// per-VM ownership inside the shared /24.
	rejects(t, got, []TrieEntry{
		{TenantID: "T1", Prefix: cidr("10.10.0.0/24"), Zone: bpf.ZoneOtherTenant},
		{TenantID: "T2", Prefix: cidr("10.10.0.0/24"), Zone: bpf.ZoneOtherTenant},
	})
}

func scenarioC() Snapshot {
	return Snapshot{
		Networks: []Network{
			{ID: "n1", ProjectID: "T1"},
			{ID: "n2", ProjectID: "T2"},
			{ID: "n-shared", ProjectID: "T-admin", Shared: true},
		},
		Subnets: []Subnet{
			{ID: "s1", NetworkID: "n1", ProjectID: "T1", CIDR: "10.0.1.0/24", IPVersion: 4},
			{ID: "s2", NetworkID: "n2", ProjectID: "T2", CIDR: "10.0.2.0/24", IPVersion: 4},
			{ID: "s-shared", NetworkID: "n-shared", ProjectID: "T-admin", CIDR: "10.10.0.0/24", IPVersion: 4},
		},
		Ports: []Port{
			{ID: "p-vm-a", NetworkID: "n1", ProjectID: "T1", MACAddress: "fa:16:3e:00:01:01", DeviceOwner: "compute:nova",
				FixedIPs: []FixedIP{{SubnetID: "s1", IPAddress: "10.0.1.5"}}},
			{ID: "p-vm-x", NetworkID: "n2", ProjectID: "T2", MACAddress: "fa:16:3e:00:02:01", DeviceOwner: "compute:nova",
				FixedIPs: []FixedIP{{SubnetID: "s2", IPAddress: "10.0.2.5"}}},
		},
	}
}

// ----- Scenario D — External egress (VM → internet) -----

// T1 has an internal subnet, a router, and an external gateway
// network (router:external=true). The external network's CIDR must
// NOT appear in the trie at all — it falls through to the Step-1
// catchall as EXTERNAL. The router_gateway port's /32 IS in the
// trie as INFRA (it's the NAT-GW address from T1's perspective).

func TestScenario_D_ExternalEgress(t *testing.T) {
	snap := scenarioD()
	got := BuildTrie(snap.Networks, snap.Subnets, snap.Ports, snap.Routers)
	expects(t, got, []TrieEntry{
		catchallRow("T1"),
		{TenantID: "T1", Prefix: cidr("10.0.1.0/24"), Zone: bpf.ZoneSameTenant},
		{TenantID: "T1", Prefix: cidr("203.0.113.1/32"), Zone: bpf.ZoneInfra}, // router_gateway NAT IP
		metadataRow("T1"),
	})
	// External network's /24 must not surface in the trie.
	rejects(t, got, []TrieEntry{
		{TenantID: "T1", Prefix: cidr("203.0.113.0/24"), Zone: bpf.ZoneSameTenant},
		{TenantID: "T1", Prefix: cidr("203.0.113.0/24"), Zone: bpf.ZoneOtherTenant},
		{TenantID: "T1", Prefix: cidr("203.0.113.0/24"), Zone: bpf.ZoneShared},
	})
}

func scenarioD() Snapshot {
	return Snapshot{
		Networks: []Network{
			{ID: "n1", ProjectID: "T1"},
			{ID: "n-ext", ProjectID: "T-admin", IsExternal: true},
		},
		Subnets: []Subnet{
			{ID: "s1", NetworkID: "n1", ProjectID: "T1", CIDR: "10.0.1.0/24", IPVersion: 4},
			{ID: "s-ext", NetworkID: "n-ext", ProjectID: "T-admin", CIDR: "203.0.113.0/24", IPVersion: 4},
		},
		Ports: []Port{
			{ID: "p-vm-a", NetworkID: "n1", ProjectID: "T1", MACAddress: "fa:16:3e:00:01:01", DeviceOwner: "compute:nova",
				FixedIPs: []FixedIP{{SubnetID: "s1", IPAddress: "10.0.1.5"}}},
			{ID: "p-r1-gw", NetworkID: "n-ext", ProjectID: "T1", MACAddress: "fa:16:3e:00:01:99", DeviceOwner: "network:router_gateway",
				FixedIPs: []FixedIP{{SubnetID: "s-ext", IPAddress: "203.0.113.1"}}},
		},
		Routers: []Router{{ID: "r1", ProjectID: "T1", ExternalNetworkID: "n-ext"}},
	}
}

// ----- Scenario E — External ingress via floating IP -----

// At the VM-A tap, the packet's src is the internet client (DNAT
// already happened upstream); the trie sees `remote_ip=1.2.3.4` and
// falls to catchall EXTERNAL. The FIP port itself (a
// `network:floatingip` bookkeeping row) MUST NOT contribute a /32
// INFRA entry — it's neither infra nor VM-like (see IsInfraPort /
// IsVMPort partition).

func TestScenario_E_ExternalIngressViaFIP(t *testing.T) {
	snap := scenarioE()
	got := BuildTrie(snap.Networks, snap.Subnets, snap.Ports, snap.Routers)
	expects(t, got, []TrieEntry{
		catchallRow("T1"),
		{TenantID: "T1", Prefix: cidr("10.0.1.0/24"), Zone: bpf.ZoneSameTenant},
		metadataRow("T1"),
	})
	// The FIP /32 must NOT be classified — bookkeeping port.
	rejects(t, got, []TrieEntry{
		{TenantID: "T1", Prefix: cidr("203.0.113.5/32"), Zone: bpf.ZoneInfra},
		{TenantID: "T1", Prefix: cidr("203.0.113.5/32"), Zone: bpf.ZoneSameTenant},
	})
}

func scenarioE() Snapshot {
	s := scenarioD()
	// Add a FIP bookkeeping port on the external network.
	s.Ports = append(s.Ports, Port{
		ID: "p-fip", NetworkID: "n-ext", ProjectID: "T1",
		MACAddress: "fa:16:3e:00:fa:01", DeviceOwner: "network:floatingip",
		FixedIPs: []FixedIP{{SubnetID: "s-ext", IPAddress: "203.0.113.5"}},
	})
	return s
}

// ----- Scenario F — Octavia LB ports present in the snapshot -----

// Sprint 4a stops short of full Octavia attribution (Sprint 8). For
// the trie, the relevant check is that Octavia management ports
// don't accidentally classify as INFRA or contribute spurious /32
// rows. They're VM-like by the IsVMPort partition — the kernel
// `mac_tenant_map` will hold their MACs (verified by
// agent.populateMetadataFromPorts), but their IPs do NOT appear in
// the trie.

func TestScenario_F_OctaviaPortsAreVMLikeNotInfra(t *testing.T) {
	snap := scenarioF()
	got := BuildTrie(snap.Networks, snap.Subnets, snap.Ports, snap.Routers)
	// Octavia VIP and health-mgr /32 should NOT appear in the trie.
	rejects(t, got, []TrieEntry{
		{TenantID: "T1", Prefix: cidr("10.0.1.50/32"), Zone: bpf.ZoneInfra}, // Octavia VIP
		{TenantID: "T1", Prefix: cidr("10.0.1.99/32"), Zone: bpf.ZoneInfra}, // health-mgr
	})
	// The owning tenant's subnet IS in the trie (Step 2).
	expects(t, got, []TrieEntry{
		{TenantID: "T1", Prefix: cidr("10.0.1.0/24"), Zone: bpf.ZoneSameTenant},
	})
}

func scenarioF() Snapshot {
	return Snapshot{
		Networks: []Network{{ID: "n1", ProjectID: "T1"}},
		Subnets: []Subnet{
			{ID: "s1", NetworkID: "n1", ProjectID: "T1", CIDR: "10.0.1.0/24", IPVersion: 4},
		},
		Ports: []Port{
			{ID: "p-amphora", NetworkID: "n1", ProjectID: "T1", MACAddress: "fa:16:3e:0c:01:01", DeviceOwner: "Octavia",
				FixedIPs: []FixedIP{{SubnetID: "s1", IPAddress: "10.0.1.50"}}},
			{ID: "p-octavia-hm", NetworkID: "n1", ProjectID: "T1", MACAddress: "fa:16:3e:0c:01:02", DeviceOwner: "Octavia:health-mgr",
				FixedIPs: []FixedIP{{SubnetID: "s1", IPAddress: "10.0.1.99"}}},
		},
	}
}

// ----- Scenarios I, J — Same-host and Cross-host, same-tenant -----

// At the BuildTrie level, scenarios I and J produce the identical
// trie as A. They differ at the kernel datapath level (one uses
// OVS local switching, the other VXLAN-encapsulates between hosts),
// but the trie content the userspace builder writes is the same.
// Asserting the trie shape once is enough; the kernel-side
// behaviour is exercised by the integration tests in
// internal/testenv/classifier and internal/testenv/e2e.

func TestScenario_I_SameHostSameTenant(t *testing.T) {
	snap := scenarioA() // identical trie to A
	got := BuildTrie(snap.Networks, snap.Subnets, snap.Ports, snap.Routers)
	expects(t, got, []TrieEntry{
		catchallRow("T1"),
		{TenantID: "T1", Prefix: cidr("10.0.1.0/24"), Zone: bpf.ZoneSameTenant},
	})
}

func TestScenario_J_CrossHostSameTenant(t *testing.T) {
	// VXLAN is invisible to TC at the tap; from BuildTrie's perspective
	// J is indistinguishable from A. The fixture is identical.
	snap := scenarioA()
	got := BuildTrie(snap.Networks, snap.Subnets, snap.Ports, snap.Routers)
	expects(t, got, []TrieEntry{
		catchallRow("T1"),
		{TenantID: "T1", Prefix: cidr("10.0.1.0/24"), Zone: bpf.ZoneSameTenant},
	})
}
