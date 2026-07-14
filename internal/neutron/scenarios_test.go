package neutron_test

// Golden-file scenario tests for BuildTrie. Each test reconstructs
// the Neutron snapshot that corresponds to a documented scenario
// (docs/DESIGN.md §B Scenarios A–L) and asserts the trie rows the
// builder emits.
//
// Lives in `neutron_test` (external test package) so it can import
// the scenario DSL at internal/testenv/scenario, which itself
// imports internal/neutron — avoiding an import cycle.
//
// Snapshots are built via the [scenario] DSL — a thin declarative
// wrapper around the four Neutron resource slices that hides MAC
// addresses, wires DeviceID on router-interface ports, and links
// VMs to their subnet implicitly. Direct struct literals lurk
// nowhere; if a scenario can't be expressed through the DSL, the
// right move is to grow the DSL, not write fixtures by hand.

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/bigstack-oss/lachesis/internal/bpf"
	"github.com/bigstack-oss/lachesis/internal/neutron"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// expects passes if BuildTrie's output contains every (tenant, prefix, zone)
// row in want. Extra rows are tolerated — the trie may always carry
// catchall + metadata INFRA + infra port /32s alongside the rows the
// scenario specifically cares about.
func expects(t *testing.T, got []neutron.TrieEntry, want []neutron.TrieEntry) {
	t.Helper()
	for _, w := range want {
		if !slices.Contains(got, w) {
			t.Errorf("missing expected row: tenant=%s prefix=%s zone=%v\nactual entries: %v",
				w.TenantID, w.Prefix, w.Zone, got)
		}
	}
}

// rejects fails if BuildTrie's output contains any row in deny.
// Used to assert "this CIDR must NOT appear under this tenant with
// this zone" — e.g. an external CIDR must not surface as OTHER_TENANT.
func rejects(t *testing.T, got []neutron.TrieEntry, deny []neutron.TrieEntry) {
	t.Helper()
	for _, d := range deny {
		if slices.Contains(got, d) {
			t.Errorf("forbidden row present: tenant=%s prefix=%s zone=%v",
				d.TenantID, d.Prefix, d.Zone)
		}
	}
}

func cidr(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// catchallRow and metadataRow build the global rows BuildTrie
// emits exactly once per snapshot under the trie-dedup model. The
// kernel `lookup_zone` reads them via the sentinel-fallback key
// `tenant_id=0`, so they cover every tenant's view from a single
// entry.
func catchallRow() neutron.TrieEntry {
	return neutron.TrieEntry{TenantID: "", Prefix: cidr("0.0.0.0/0"), Zone: bpf.ZoneExternal}
}

func metadataRow() neutron.TrieEntry {
	return neutron.TrieEntry{TenantID: "", Prefix: cidr("169.254.169.254/32"), Zone: bpf.ZoneInfra}
}

func runScenario(snap neutron.Snapshot) []neutron.TrieEntry {
	entries, _, _ := neutron.BuildTrie(snap)
	return entries
}

// ----- Scenario A — Same tenant, same subnet (direct L2) -----

// Single tenant, single network, single /24 subnet, two VMs. The
// trie still emits the SAME_TENANT /24 row even though A's per-
// packet path is MAC-first.
func TestScenario_A_SameTenantSameSubnet(t *testing.T) {
	got := runScenario(scenarioA())
	expects(t, got, []neutron.TrieEntry{
		catchallRow(),
		{TenantID: "T1", Prefix: cidr("10.0.1.0/24"), Zone: bpf.ZoneSameTenant},
		metadataRow(),
	})
}

func scenarioA() neutron.Snapshot {
	b := scenario.New()
	b.Network("n1", "T1").
		Subnet("s1", "10.0.1.0/24", "").
		VM("p-vm-a", "T1", "10.0.1.5").
		VM("p-vm-b", "T1", "10.0.1.6")
	return b.Build()
}

// ----- Scenario B — Same tenant, different subnets via router -----

func TestScenario_B_SameTenantViaRouter(t *testing.T) {
	got := runScenario(scenarioB())
	expects(t, got, []neutron.TrieEntry{
		catchallRow(),
		{TenantID: "T1", Prefix: cidr("10.0.1.0/24"), Zone: bpf.ZoneSameTenant},
		{TenantID: "T1", Prefix: cidr("10.0.2.0/24"), Zone: bpf.ZoneSameTenant},
		{TenantID: "", Prefix: cidr("10.0.1.1/32"), Zone: bpf.ZoneInfra}, // router IF on subnet1 (global)
		{TenantID: "", Prefix: cidr("10.0.2.1/32"), Zone: bpf.ZoneInfra}, // router IF on subnet2 (global)
		metadataRow(),
	})
}

func scenarioB() neutron.Snapshot {
	b := scenario.New()
	b.Network("n1", "T1").Subnet("s1", "10.0.1.0/24", "10.0.1.1")
	b.Network("n2", "T1").Subnet("s2", "10.0.2.0/24", "10.0.2.1")
	b.Router("r1", "T1").Attach("s1", "10.0.1.1").Attach("s2", "10.0.2.1")
	return b.Build()
}

// ----- Scenario C — Cross-tenant via shared network -----

// T1 and T2 each own their own subnets; an admin-owned shared
// network is visible to both. The shared CIDR is SHARED — never
// OTHER_TENANT — for every tenant; the trie cannot resolve per-VM
// ownership inside a shared /24 (DESIGN §5.2 Step 3).
func TestScenario_C_CrossTenantViaShared(t *testing.T) {
	got := runScenario(scenarioC())
	expects(t, got, []neutron.TrieEntry{
		catchallRow(),
		{TenantID: "", Prefix: cidr("10.10.0.0/24"), Zone: bpf.ZoneShared}, // global
		{TenantID: "T1", Prefix: cidr("10.0.1.0/24"), Zone: bpf.ZoneSameTenant},
		{TenantID: "T2", Prefix: cidr("10.0.2.0/24"), Zone: bpf.ZoneSameTenant},
	})
	rejects(t, got, []neutron.TrieEntry{
		// Per-tenant copies of the shared row would defeat the trie dedup.
		{TenantID: "T1", Prefix: cidr("10.10.0.0/24"), Zone: bpf.ZoneShared},
		{TenantID: "T2", Prefix: cidr("10.10.0.0/24"), Zone: bpf.ZoneShared},
		{TenantID: "T1", Prefix: cidr("10.10.0.0/24"), Zone: bpf.ZoneOtherTenant},
		{TenantID: "T2", Prefix: cidr("10.10.0.0/24"), Zone: bpf.ZoneOtherTenant},
	})
}

func scenarioC() neutron.Snapshot {
	b := scenario.New()
	b.Network("n1", "T1").Subnet("s1", "10.0.1.0/24", "").VM("p-vm-a", "T1", "10.0.1.5")
	b.Network("n2", "T2").Subnet("s2", "10.0.2.0/24", "").VM("p-vm-x", "T2", "10.0.2.5")
	b.SharedNetwork("n-shared", "T-admin").Subnet("s-shared", "10.10.0.0/24", "")
	return b.Build()
}

// ----- Scenario D — External egress (VM → internet) -----

// T1 has an internal subnet, a router, and an external gateway
// network. The external network's CIDR must NOT surface in the
// trie — the catchall covers it as EXTERNAL.
func TestScenario_D_ExternalEgress(t *testing.T) {
	got := runScenario(scenarioD())
	expects(t, got, []neutron.TrieEntry{
		catchallRow(),
		{TenantID: "T1", Prefix: cidr("10.0.1.0/24"), Zone: bpf.ZoneSameTenant},
		{TenantID: "", Prefix: cidr("203.0.113.1/32"), Zone: bpf.ZoneInfra}, // external GW IF (global)
		metadataRow(),
	})
	rejects(t, got, []neutron.TrieEntry{
		{TenantID: "T1", Prefix: cidr("203.0.113.0/24"), Zone: bpf.ZoneSameTenant},
		{TenantID: "T1", Prefix: cidr("203.0.113.0/24"), Zone: bpf.ZoneOtherTenant},
		{TenantID: "T1", Prefix: cidr("203.0.113.0/24"), Zone: bpf.ZoneShared},
		{TenantID: "", Prefix: cidr("203.0.113.0/24"), Zone: bpf.ZoneShared},
	})
}

func scenarioD() neutron.Snapshot {
	b := scenario.New()
	b.Network("n1", "T1").Subnet("s1", "10.0.1.0/24", "").VM("p-vm-a", "T1", "10.0.1.5")
	b.ExternalNetwork("n-ext", "T-admin").Subnet("s-ext", "203.0.113.0/24", "")
	b.Router("r1", "T1").
		Attach("s1", "10.0.1.1").
		Attach("s-ext", "203.0.113.1").
		ExternalGateway("n-ext")
	return b.Build()
}

// ----- Scenario E — External ingress via floating IP -----

// FIP /32 must NOT classify as INFRA — `network:floatingip` ports
// are neither infra nor VM-like (bookkeeping only, no L2 endpoint).
func TestScenario_E_ExternalIngressViaFIP(t *testing.T) {
	got := runScenario(scenarioE())
	expects(t, got, []neutron.TrieEntry{
		catchallRow(),
		{TenantID: "T1", Prefix: cidr("10.0.1.0/24"), Zone: bpf.ZoneSameTenant},
		metadataRow(),
	})
	rejects(t, got, []neutron.TrieEntry{
		// FIP /32 must NOT classify as INFRA under any tenant or
		// the global sentinel — `network:floatingip` is bookkeeping,
		// not a real L2 endpoint.
		{TenantID: "", Prefix: cidr("203.0.113.5/32"), Zone: bpf.ZoneInfra},
		{TenantID: "T1", Prefix: cidr("203.0.113.5/32"), Zone: bpf.ZoneInfra},
		{TenantID: "T1", Prefix: cidr("203.0.113.5/32"), Zone: bpf.ZoneSameTenant},
	})
}

func scenarioE() neutron.Snapshot {
	b := scenario.New()
	b.Network("n1", "T1").Subnet("s1", "10.0.1.0/24", "").VM("p-vm-a", "T1", "10.0.1.5")
	ext := b.ExternalNetwork("n-ext", "T-admin").Subnet("s-ext", "203.0.113.0/24", "")
	ext.FIP("p-fip", "203.0.113.5")
	b.Router("r1", "T1").
		Attach("s1", "10.0.1.1").
		Attach("s-ext", "203.0.113.1").
		ExternalGateway("n-ext")
	return b.Build()
}

// ----- Scenario F — Octavia ports present but VM-classified -----

// Octavia management ports (device_owner="Octavia") are VM-like
// for the IsVMPort partition — their MACs land in mac_tenant_map,
// their IPs do NOT contribute /32 INFRA rows.
func TestScenario_F_OctaviaPortsAreVMLikeNotInfra(t *testing.T) {
	got := runScenario(scenarioF())
	rejects(t, got, []neutron.TrieEntry{
		{TenantID: "", Prefix: cidr("10.0.1.50/32"), Zone: bpf.ZoneInfra},
		{TenantID: "", Prefix: cidr("10.0.1.99/32"), Zone: bpf.ZoneInfra},
		{TenantID: "T1", Prefix: cidr("10.0.1.50/32"), Zone: bpf.ZoneInfra},
		{TenantID: "T1", Prefix: cidr("10.0.1.99/32"), Zone: bpf.ZoneInfra},
	})
	expects(t, got, []neutron.TrieEntry{
		{TenantID: "T1", Prefix: cidr("10.0.1.0/24"), Zone: bpf.ZoneSameTenant},
	})
}

func scenarioF() neutron.Snapshot {
	b := scenario.New()
	b.Network("n1", "T1").
		Subnet("s1", "10.0.1.0/24", "").
		Octavia("p-amphora", "T1", "10.0.1.50").
		Octavia("p-octavia-hm", "T1", "10.0.1.99")
	return b.Build()
}

// ----- Scenario G — Single-hop static route (Step 5, simple case) -----

// T1's R1 routes 10.50.0.0/16 via R2's IP on a shared transit;
// R2 (T2) has the destination network directly attached. Step C
// of the resolver returns zone_for(T2, T1, net-T2) → OTHER_TENANT.
func TestScenario_G_SingleHopStaticRoute(t *testing.T) {
	got := runScenario(scenarioG())
	expects(t, got, []neutron.TrieEntry{
		{TenantID: "T1", Prefix: cidr("10.50.0.0/16"), Zone: bpf.ZoneOtherTenant},
	})
}

func scenarioG() neutron.Snapshot {
	b := scenario.New()
	b.Network("n-T1", "T1").Subnet("s-T1", "10.0.0.0/24", "")
	b.Network("n-T2", "T2").Subnet("s-T2", "10.50.0.0/16", "")
	b.SharedNetwork("n-transit", "T-admin").Subnet("s-transit", "192.168.100.0/24", "")
	b.Router("R1", "T1").
		Attach("s-T1", "10.0.0.1").
		Attach("s-transit", "192.168.100.10").
		ExtraRoute("10.50.0.0/16", "192.168.100.20")
	b.Router("R2", "T2").
		Attach("s-T2", "10.50.0.1").
		Attach("s-transit", "192.168.100.20")
	return b.Build()
}

// ----- Scenarios I, J — Same-host / cross-host, same-tenant -----

// At BuildTrie's level I and J produce the identical trie as A.
// They differ at the kernel datapath layer (local vs VXLAN), not
// at the metadata layer.
func TestScenario_I_SameHostSameTenant(t *testing.T) {
	got := runScenario(scenarioA())
	expects(t, got, []neutron.TrieEntry{
		catchallRow(),
		{TenantID: "T1", Prefix: cidr("10.0.1.0/24"), Zone: bpf.ZoneSameTenant},
	})
}

func TestScenario_J_CrossHostSameTenant(t *testing.T) {
	got := runScenario(scenarioA())
	expects(t, got, []neutron.TrieEntry{
		catchallRow(),
		{TenantID: "T1", Prefix: cidr("10.0.1.0/24"), Zone: bpf.ZoneSameTenant},
	})
}

// ----- Scenario K — Multi-hop chain (5 routers, DESIGN §5.5) -----

// Verbatim from the worked example: T1's R1 routes 10.99.0.0/16
// via R2 in transit-A; each Ri.routes forwards onward through
// transit-A/B/C/D until R5, which has the destination network
// (net-T5) directly attached. Final classification:
// zone_for(T5, T1, net-T5) → OTHER_TENANT.
func TestScenario_K_MultiHopChain(t *testing.T) {
	got := runScenario(scenarioK())
	expects(t, got, []neutron.TrieEntry{
		{TenantID: "T1", Prefix: cidr("10.99.0.0/16"), Zone: bpf.ZoneOtherTenant},
	})
	// The chain transits MUST NOT leak into T1's view as anything
	// other than SHARED — they're shared transit networks and the
	// resolver must not mis-classify them as SAME / OTHER on the
	// chain hop.
	rejects(t, got, []neutron.TrieEntry{
		{TenantID: "T1", Prefix: cidr("10.99.0.0/16"), Zone: bpf.ZoneSameTenant},
		{TenantID: "T1", Prefix: cidr("10.99.0.0/16"), Zone: bpf.ZoneShared},
	})
}

func scenarioK() neutron.Snapshot {
	b := scenario.New()
	// Owned tenant networks (each Ti owns its own internal net).
	b.Network("net-T1", "T1").Subnet("sub-T1", "10.1.0.0/24", "")
	b.Network("net-T2", "T2").Subnet("sub-T2", "10.2.0.0/24", "")
	b.Network("net-T3", "T3").Subnet("sub-T3", "10.3.0.0/24", "")
	b.Network("net-T4", "T4").Subnet("sub-T4", "10.4.0.0/24", "")
	b.Network("net-T5", "T5").Subnet("sub-T5", "10.99.0.0/16", "") // destination
	// Shared transits A–D.
	b.SharedNetwork("net-tA", "T-admin").Subnet("sub-tA", "10.10.1.0/24", "")
	b.SharedNetwork("net-tB", "T-admin").Subnet("sub-tB", "10.10.2.0/24", "")
	b.SharedNetwork("net-tC", "T-admin").Subnet("sub-tC", "10.10.3.0/24", "")
	b.SharedNetwork("net-tD", "T-admin").Subnet("sub-tD", "10.10.4.0/24", "")
	// Routers — each chained to next via a transit.
	b.Router("R1", "T1").
		Attach("sub-T1", "10.1.0.1").
		Attach("sub-tA", "10.10.1.10").
		ExtraRoute("10.99.0.0/16", "10.10.1.20")
	b.Router("R2", "T2").
		Attach("sub-T2", "10.2.0.1").
		Attach("sub-tA", "10.10.1.20").
		Attach("sub-tB", "10.10.2.20").
		ExtraRoute("10.99.0.0/16", "10.10.2.30")
	b.Router("R3", "T3").
		Attach("sub-T3", "10.3.0.1").
		Attach("sub-tB", "10.10.2.30").
		Attach("sub-tC", "10.10.3.30").
		ExtraRoute("10.99.0.0/16", "10.10.3.40")
	b.Router("R4", "T4").
		Attach("sub-T4", "10.4.0.1").
		Attach("sub-tC", "10.10.3.40").
		Attach("sub-tD", "10.10.4.40").
		ExtraRoute("10.99.0.0/16", "10.10.4.50")
	b.Router("R5", "T5").
		Attach("sub-T5", "10.99.0.1").
		Attach("sub-tD", "10.10.4.50")
	return b.Build()
}

// ----- Scenario L — VM-appliance nexthop (Step B compute:nova) -----

// T1's R1 routes 172.16.99.0/24 via a VM at 10.0.1.50 on T1's own
// net-T1. The resolver's Step B compute:nova branch returns
// zone_for(T1, T1, net-T1) → SAME_TENANT. Double-billing at the
// appliance's own tap is documented in DESIGN.md §8 Tier 4 but is
// not the trie builder's concern.
func TestScenario_L_VMApplianceNexthop(t *testing.T) {
	got := runScenario(scenarioL())
	expects(t, got, []neutron.TrieEntry{
		{TenantID: "T1", Prefix: cidr("172.16.99.0/24"), Zone: bpf.ZoneSameTenant},
	})
}

func scenarioL() neutron.Snapshot {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.1.0/24", "10.0.1.1").
		VM("vm-appliance", "T1", "10.0.1.50")
	b.Router("R1", "T1").
		Attach("sub-T1", "10.0.1.1").
		ExtraRoute("172.16.99.0/24", "10.0.1.50")
	return b.Build()
}

// Named-AZ variant of Scenario L: Nova writes compute:<az-name> as
// the device_owner — "nova" is only the default AZ's name — so an
// appliance in a named AZ must resolve through the same Step B
// branch, not fall through to EXTERNAL.
func TestScenario_L_VMApplianceNexthopNamedAZ(t *testing.T) {
	got := runScenario(scenarioLNamedAZ())
	expects(t, got, []neutron.TrieEntry{
		{TenantID: "T1", Prefix: cidr("172.16.99.0/24"), Zone: bpf.ZoneSameTenant},
	})
}

func scenarioLNamedAZ() neutron.Snapshot {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.1.0/24", "10.0.1.1").
		VMInAZ("vm-appliance", "T1", "az-east", "10.0.1.50")
	b.Router("R1", "T1").
		Attach("sub-T1", "10.0.1.1").
		ExtraRoute("172.16.99.0/24", "10.0.1.50")
	return b.Build()
}

// ----- Slice-5 boundary: ambiguity surfacing -----

// TestBuildTrie_SurfacesAmbiguityHit asserts BuildTrie's second
// return aggregates every Step C ambiguity-after-scoping incident
// (DESIGN §5.6). R1 (T1) routes 10.99.50.0/24 via R2, which has
// two attached networks both covering the destination but owned
// by different tenants — the resolver returns EXTERNAL and emits
// an AmbiguityHit; BuildTrie collects it for the caller's strict-
// mode policy check.
func TestBuildTrie_SurfacesAmbiguityHit(t *testing.T) {
	b := scenario.New()
	b.Network("net-T2", "T2").Subnet("sub-T2", "10.99.0.0/16", "")
	b.Network("net-T3", "T3").Subnet("sub-T3", "10.99.0.0/16", "")
	b.SharedNetwork("transit", "T-admin").Subnet("sub-tr", "192.168.100.0/24", "")
	b.Router("R1", "T1").
		Attach("sub-tr", "192.168.100.10").
		ExtraRoute("10.99.50.0/24", "192.168.100.20")
	b.Router("R2", "T2").
		Attach("sub-tr", "192.168.100.20").
		Attach("sub-T2", "10.99.0.1").
		Attach("sub-T3", "10.99.0.1")
	snap := b.Build()

	entries, hits, _ := neutron.BuildTrie(snap)

	if len(hits) != 1 {
		t.Fatalf("expected exactly 1 ambiguity hit, got %d: %+v", len(hits), hits)
	}
	hit := hits[0]
	if hit.SourceTenant != "T1" || hit.RouterID != "R2" ||
		hit.Destination != cidr("10.99.50.0/24") {
		t.Errorf("unexpected hit shape: %+v", hit)
	}
	wantOwners := map[string]bool{"T2": true, "T3": true}
	if len(hit.Owners) != 2 {
		t.Errorf("expected 2 distinct owners, got %v", hit.Owners)
	}
	for _, o := range hit.Owners {
		if !wantOwners[o] {
			t.Errorf("unexpected owner %q in hit", o)
		}
	}
	// And the trie entry still records EXTERNAL — the resolver doesn't
	// drop the row, the caller (in strict mode) refuses to start.
	if !slices.Contains(entries, neutron.TrieEntry{
		TenantID: "T1", Prefix: cidr("10.99.50.0/24"), Zone: bpf.ZoneExternal,
	}) {
		t.Errorf("ambiguous route should still emit EXTERNAL row in entries:\n%+v", entries)
	}
}

// TestBuildTrie_GlobalsDedupedAcrossTenants pins the
// emission-uniqueness invariant: every "global" row (catchall,
// SHARED, INFRA, metadata) is emitted exactly once with
// TenantID="" regardless of tenant count, and SAME_TENANT rows
// are emitted exactly per owning tenant. The kernel `lookup_zone`
// sentinel-fallback (tenant_id=0) reads the global rows for any
// tenant whose first lookup misses; per-tenant replication of
// globals would defeat the dedup and re-introduce the O(T × G)
// cardinality blowup.
func TestBuildTrie_GlobalsDedupedAcrossTenants(t *testing.T) {
	// Scenario C carries 3 tenants (T1, T2, T-admin), 1 shared
	// CIDR, and 2 owned subnets — enough to distinguish globals
	// from per-tenant rows.
	got := runScenario(scenarioC())

	cases := []struct {
		name   string
		prefix netip.Prefix
		want   string
	}{
		{"catchall", cidr("0.0.0.0/0"), ""},
		{"metadata", cidr("169.254.169.254/32"), ""},
		{"shared", cidr("10.10.0.0/24"), ""},
		{"T1 owned", cidr("10.0.1.0/24"), "T1"},
		{"T2 owned", cidr("10.0.2.0/24"), "T2"},
	}
	for _, tc := range cases {
		rows := filterByPrefix(got, tc.prefix)
		if len(rows) != 1 {
			t.Errorf("%s: %d rows for %v, want exactly 1\nrows: %+v",
				tc.name, len(rows), tc.prefix, rows)
			continue
		}
		if rows[0].TenantID != tc.want {
			t.Errorf("%s: row tenant = %q, want %q (row: %+v)",
				tc.name, rows[0].TenantID, tc.want, rows[0])
		}
	}
}

func filterByPrefix(entries []neutron.TrieEntry, prefix netip.Prefix) []neutron.TrieEntry {
	var out []neutron.TrieEntry
	for _, e := range entries {
		if e.Prefix == prefix {
			out = append(out, e)
		}
	}
	return out
}
