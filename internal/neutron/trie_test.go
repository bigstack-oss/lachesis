package neutron

import (
	"net/netip"
	"reflect"
	"slices"
	"testing"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
)

func countTenant(entries []TrieEntry, tenant string) int {
	n := 0
	for _, e := range entries {
		if e.TenantID == tenant {
			n++
		}
	}
	return n
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return p
}

func TestBuildTrie_Empty(t *testing.T) {
	got, _ := BuildTrie(nil, nil, nil, nil)
	if len(got) != 0 {
		t.Fatalf("BuildTrie(empty) = %v, want empty", got)
	}
}

// TestBuildTrie_Step1Catchall asserts the global catchall row
// `0.0.0.0/0 → EXTERNAL` is emitted exactly once with TenantID=""
// regardless of which resource type a tenant's ProjectID surfaces
// in. Under the trie-dedup model, per-tenant catchall rows would
// be a regression — the kernel `lookup_zone` sentinel fallback
// covers every tenant's view from the single global row.
func TestBuildTrie_Step1Catchall(t *testing.T) {
	got, _ := BuildTrie(
		[]Network{{ID: "n1", ProjectID: "t-from-net"}},
		nil,
		[]Port{{ID: "p1", ProjectID: "t-from-port"}},
		[]Router{{ID: "r1", ProjectID: "t-from-router"}},
	)
	want := mustPrefix(t, "0.0.0.0/0")
	if !slices.Contains(got,TrieEntry{"", want, bpf.ZoneExternal}) {
		t.Errorf("global catchall row missing")
	}
	for _, tenant := range []string{"t-from-net", "t-from-port", "t-from-router"} {
		if slices.Contains(got,TrieEntry{tenant, want, bpf.ZoneExternal}) {
			t.Errorf("per-tenant catchall row leaked for %q (dedup regression)", tenant)
		}
	}
}

// TestBuildTrie_Step2OwnedSubnets exercises a single-tenant network
// with one non-shared subnet. Expected: catchall + SAME_TENANT for
// the subnet's CIDR + metadata INFRA.
func TestBuildTrie_Step2OwnedSubnets(t *testing.T) {
	got, _ := BuildTrie(
		[]Network{{ID: "n1", ProjectID: "T1", Shared: false}},
		[]Subnet{{ID: "s1", NetworkID: "n1", ProjectID: "T1", CIDR: "10.0.0.0/24", IPVersion: 4}},
		nil, nil,
	)
	if !slices.Contains(got,TrieEntry{"T1", mustPrefix(t, "10.0.0.0/24"), bpf.ZoneSameTenant}) {
		t.Fatalf("missing SAME_TENANT row\n%+v", got)
	}
}

// TestBuildTrie_SharedNetworkEmitsShared asserts a subnet on a
// shared network emits exactly one SHARED row with TenantID="" —
// the kernel sentinel fallback covers every tenant's view, owner
// and non-owner alike. SHARED (not SAME / not OTHER) reflects the
// structural ambiguity: the trie cannot disambiguate per-VM
// ownership inside a shared CIDR, and guessing either side
// systematically mis-bills the wrong direction.
func TestBuildTrie_SharedNetworkEmitsShared(t *testing.T) {
	got, _ := BuildTrie(
		[]Network{
			{ID: "n-shared", ProjectID: "T1", Shared: true},
			{ID: "n-own", ProjectID: "T2"},
		},
		[]Subnet{
			{ID: "s-shared", NetworkID: "n-shared", ProjectID: "T1", CIDR: "192.168.0.0/24", IPVersion: 4},
		},
		nil, nil,
	)
	shared := mustPrefix(t, "192.168.0.0/24")
	if !slices.Contains(got,TrieEntry{"", shared, bpf.ZoneShared}) {
		t.Errorf("global SHARED row missing for %v", shared)
	}
	for _, tenant := range []string{"T1", "T2"} {
		if slices.Contains(got,TrieEntry{tenant, shared, bpf.ZoneShared}) {
			t.Errorf("per-tenant SHARED row leaked for %q (dedup regression)", tenant)
		}
		// SAME/OTHER guesses on shared CIDRs were never allowed.
		if slices.Contains(got,TrieEntry{tenant, shared, bpf.ZoneSameTenant}) {
			t.Errorf("shared subnet emitted as SAME_TENANT under %q", tenant)
		}
		if slices.Contains(got,TrieEntry{tenant, shared, bpf.ZoneOtherTenant}) {
			t.Errorf("shared subnet emitted as OTHER_TENANT under %q", tenant)
		}
	}
}

// TestBuildTrie_ExternalNetworkSkipsStep3 asserts that a network
// marked router:external=true is excluded from the trie even when
// shared=true. A buggy implementation would emit OTHER_TENANT for
// the floating-IP-pool CIDR; the catchall then EXTERNAL-classifies
// any address in that pool correctly via fallthrough.
func TestBuildTrie_ExternalNetworkSkipsStep3(t *testing.T) {
	got, _ := BuildTrie(
		[]Network{
			{ID: "n-ext", ProjectID: "T-admin", Shared: true, IsExternal: true},
			{ID: "n-own", ProjectID: "T1"},
		},
		[]Subnet{
			{ID: "s-ext", NetworkID: "n-ext", CIDR: "203.0.113.0/24", IPVersion: 4},
		},
		nil, nil,
	)
	extCIDR := mustPrefix(t, "203.0.113.0/24")
	for _, e := range got {
		if e.Prefix == extCIDR {
			t.Errorf("external CIDR leaked into trie as %v: %+v", e.Zone, e)
		}
	}
}

// TestBuildTrie_ExternalNetworkSkipsStep2 asserts the symmetric
// case: an owned, non-shared but external network must NOT produce
// a SAME_TENANT row. (Some operators mark an admin-owned external
// network as Shared=false; we still want EXTERNAL classification.)
func TestBuildTrie_ExternalNetworkSkipsStep2(t *testing.T) {
	got, _ := BuildTrie(
		[]Network{
			{ID: "n-ext", ProjectID: "T-admin", Shared: false, IsExternal: true},
		},
		[]Subnet{
			{ID: "s-ext", NetworkID: "n-ext", CIDR: "203.0.113.0/24", IPVersion: 4},
		},
		nil, nil,
	)
	for _, e := range got {
		if e.Prefix == mustPrefix(t, "203.0.113.0/24") {
			t.Errorf("external CIDR leaked into trie: %+v", e)
		}
	}
}

func TestBuildTrie_Step4InfraPorts(t *testing.T) {
	ports := []Port{
		{DeviceOwner: "network:router_interface", FixedIPs: []FixedIP{{IPAddress: "10.0.0.1"}}},
		{DeviceOwner: "network:router_gateway", FixedIPs: []FixedIP{{IPAddress: "192.0.2.1"}}},
		{DeviceOwner: "network:distributed", FixedIPs: []FixedIP{{IPAddress: "10.0.0.2"}}},
		{DeviceOwner: "network:dhcp", FixedIPs: []FixedIP{{IPAddress: "10.0.0.3"}}},
		// DVR FIP gateway and L3-HA VRRP IPs are caught by the
		// prefix rule but were missing from the older explicit
		// allow-list — pin them here so a future regression to
		// allow-list-style filtering fails this test.
		{DeviceOwner: "network:floatingip_agent_gateway", FixedIPs: []FixedIP{{IPAddress: "10.0.0.4"}}},
		{DeviceOwner: "network:ha_router_replicated_interface", FixedIPs: []FixedIP{{IPAddress: "10.0.0.5"}}},
		// compute:nova is NOT infra — must not contribute a /32.
		{DeviceOwner: "compute:nova", FixedIPs: []FixedIP{{IPAddress: "10.0.0.42"}}},
		// network:floatingip is the explicit exception inside the
		// `network:` namespace — the FIP /32 must fall through to
		// catchall EXTERNAL, not INFRA.
		{DeviceOwner: "network:floatingip", FixedIPs: []FixedIP{{IPAddress: "203.0.113.7"}}},
		// Other non-network owners that must NOT be INFRA.
		{DeviceOwner: "Octavia", FixedIPs: []FixedIP{{IPAddress: "10.0.0.99"}}},
		{DeviceOwner: "manila:share", FixedIPs: []FixedIP{{IPAddress: "10.0.0.100"}}},
	}
	got, _ := BuildTrie(
		[]Network{{ID: "n1", ProjectID: "T1"}},
		nil,
		append(ports, Port{ProjectID: "T1"}), // ensure tenant gets enumerated
		nil,
	)
	for _, infraIP := range []string{"10.0.0.1", "192.0.2.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"} {
		want := TrieEntry{"", netip.MustParsePrefix(infraIP + "/32"), bpf.ZoneInfra}
		if !slices.Contains(got,want) {
			t.Errorf("missing global INFRA row for %s\nentries: %+v", infraIP, got)
		}
	}
	for _, notInfra := range []string{"10.0.0.42", "10.0.0.99", "10.0.0.100", "203.0.113.7"} {
		if slices.Contains(got,TrieEntry{"", netip.MustParsePrefix(notInfra + "/32"), bpf.ZoneInfra}) {
			t.Errorf("non-infra IP %s leaked into INFRA", notInfra)
		}
	}
}

func TestIsVMPort(t *testing.T) {
	tests := []struct {
		deviceOwner string
		want        bool
	}{
		{"compute:nova", true},
		{"compute:Octavia", true}, // older Octavia
		{"Octavia", true},
		{"Octavia:health-mgr", true},
		{"manila:share", true},
		{"baremetal:nova", true},
		{"cube:mgr", true}, // CubeCOS internal management VMs
		{"trunk:subport", true},
		// network:* never VM (the partition rule).
		{"network:router_interface", false},
		{"network:dhcp", false},
		{"network:floatingip", false}, // bookkeeping — neither infra nor VM
		{"network:remote_managed", false},
		// Unbound.
		{"", false},
	}
	for _, tc := range tests {
		if got := IsVMPort(tc.deviceOwner); got != tc.want {
			t.Errorf("IsVMPort(%q) = %v, want %v", tc.deviceOwner, got, tc.want)
		}
	}
}

func TestIsKnownVMOwner(t *testing.T) {
	tests := []struct {
		deviceOwner string
		want        bool
	}{
		// Verified known-VM owners.
		{"compute:nova", true},
		{"compute:Octavia", true},
		{"compute:availability-zone-2", true},
		{"Octavia", true},
		{"Octavia:health-mgr", true},
		{"manila:share", true},
		{"baremetal:nova", true},
		{"trunk:subport", true},
		{"cube:mgr", true},

		// Same-prefix but not on the catalogue (`cube:mgr` is exact match).
		{"cube:something-else", false},

		// IsVMPort would admit these but they're vendor / future / unknown.
		{"vendor:weird-thing", false},
		{"oslo:something", false},

		// Already excluded by IsVMPort (network:* + empty).
		{"network:router_interface", false},
		{"network:floatingip", false},
		{"", false},
	}
	for _, tc := range tests {
		if got := IsKnownVMOwner(tc.deviceOwner); got != tc.want {
			t.Errorf("IsKnownVMOwner(%q) = %v, want %v", tc.deviceOwner, got, tc.want)
		}
	}
}

// TestIsKnownVMOwnerImpliesIsVMPort verifies the predicate
// hierarchy: every known VM-owner must also pass the broader
// IsVMPort. The reverse is not required — IsVMPort is intentionally
// more permissive so unknown owners still admit (with a warn-log).
func TestIsKnownVMOwnerImpliesIsVMPort(t *testing.T) {
	for _, owner := range []string{
		"compute:nova", "compute:Octavia", "compute:availability-zone-2",
		"Octavia", "Octavia:health-mgr",
		"manila:share", "baremetal:nova", "trunk:subport", "cube:mgr",
	} {
		if !IsVMPort(owner) {
			t.Errorf("IsKnownVMOwner(%q)=true but IsVMPort(%q)=false (catalogue must be a subset)",
				owner, owner)
		}
	}
}

// TestPortClassPartition asserts the two predicates partition the
// observed `device_owner` space — every value lands in exactly one
// of {infra, VM, neither}.
func TestPortClassPartition(t *testing.T) {
	for _, owner := range []string{
		"compute:nova", "Octavia", "manila:share", "baremetal:nova", "cube:mgr",
		"network:router_interface", "network:dhcp", "network:floatingip",
		"network:remote_managed", "",
	} {
		infra := IsInfraPort(owner)
		vm := IsVMPort(owner)
		if infra && vm {
			t.Errorf("device_owner=%q classified as BOTH infra and VM", owner)
		}
	}
}

func TestIsInfraPort(t *testing.T) {
	tests := []struct {
		deviceOwner string
		want        bool
	}{
		{"network:router_interface", true},
		{"network:router_gateway", true},
		{"network:dhcp", true},
		{"network:metadata", true},
		{"network:distributed", true},
		{"network:floatingip_agent_gateway", true},
		{"network:ha_router_replicated_interface", true},
		{"network:routed", true},
		{"network:floatingip", false}, // explicit exception
		{"compute:nova", false},
		{"compute:Octavia", false},
		{"Octavia", false},
		{"manila:share", false},
		{"baremetal:nova", false},
		{"trunk:subport", false},
		{"", false},
	}
	for _, tc := range tests {
		if got := IsInfraPort(tc.deviceOwner); got != tc.want {
			t.Errorf("IsInfraPort(%q) = %v, want %v", tc.deviceOwner, got, tc.want)
		}
	}
}

func TestBuildTrie_Step4GatewayIPAndMetadata(t *testing.T) {
	got, _ := BuildTrie(
		[]Network{{ID: "n1", ProjectID: "T1"}},
		[]Subnet{{ID: "s1", NetworkID: "n1", CIDR: "10.0.0.0/24", GatewayIP: "10.0.0.1", IPVersion: 4}},
		nil, nil,
	)
	if !slices.Contains(got,TrieEntry{"", netip.MustParsePrefix("10.0.0.1/32"), bpf.ZoneInfra}) {
		t.Errorf("global gateway IP /32 missing as INFRA")
	}
	if !slices.Contains(got,TrieEntry{"", netip.MustParsePrefix("169.254.169.254/32"), bpf.ZoneInfra}) {
		t.Errorf("global Nova metadata IP missing as INFRA")
	}
}

func TestBuildTrie_SkipsIPv6(t *testing.T) {
	got, _ := BuildTrie(
		[]Network{{ID: "n1", ProjectID: "T1"}},
		[]Subnet{
			{ID: "s4", NetworkID: "n1", ProjectID: "T1", CIDR: "10.0.0.0/24", IPVersion: 4},
			{ID: "s6", NetworkID: "n1", ProjectID: "T1", CIDR: "fd00::/64", IPVersion: 6},
		},
		[]Port{{
			DeviceOwner: "network:router_interface",
			FixedIPs: []FixedIP{
				{IPAddress: "10.0.0.1"},
				{IPAddress: "fd00::1"},
			},
		}},
		nil,
	)
	for _, e := range got {
		if !e.Prefix.Addr().Is4() {
			t.Errorf("IPv6 entry leaked: %+v", e)
		}
	}
	// Sanity: the IPv4 sibling should still be present.
	if !slices.Contains(got,TrieEntry{"T1", mustPrefix(t, "10.0.0.0/24"), bpf.ZoneSameTenant}) {
		t.Errorf("IPv4 subnet missing")
	}
}

func TestBuildTrie_MalformedCIDRSkipped(t *testing.T) {
	got, _ := BuildTrie(
		[]Network{{ID: "n1", ProjectID: "T1"}},
		[]Subnet{
			{ID: "s-bad", NetworkID: "n1", ProjectID: "T1", CIDR: "not-a-cidr", IPVersion: 4},
			{ID: "s-good", NetworkID: "n1", ProjectID: "T1", CIDR: "10.0.0.0/24", IPVersion: 4},
		},
		nil, nil,
	)
	if !slices.Contains(got,TrieEntry{"T1", mustPrefix(t, "10.0.0.0/24"), bpf.ZoneSameTenant}) {
		t.Fatalf("good CIDR should still be present after a sibling parse failure")
	}
}

// TestBuildTrie_Step5EmitsExtraroute asserts BuildTrie wires the
// multi-hop static-route resolver (DESIGN §5.3) into Step 5 of
// docs/DESIGN.md §5.2: a router's extraroute reaches the trie as
// a (tenant, destination) entry with the zone the resolver picks.
//
// The setup is the minimal VM-appliance case: R1 (T1) has an
// extraroute 172.16.99.0/24 via a compute:nova port on R1's own
// net-T1. zoneFor(T1, T1, net-T1) returns SAME_TENANT.
func TestBuildTrie_Step5EmitsExtraroute(t *testing.T) {
	got, _ := BuildTrie(
		[]Network{{ID: "net-T1", ProjectID: "T1"}},
		[]Subnet{{ID: "sub-T1", NetworkID: "net-T1", ProjectID: "T1", CIDR: "10.0.1.0/24", IPVersion: 4}},
		[]Port{
			{ID: "p-R1", NetworkID: "net-T1", ProjectID: "T1",
				DeviceOwner: "network:router_interface", DeviceID: "R1",
				FixedIPs: []FixedIP{{SubnetID: "sub-T1", IPAddress: "10.0.1.1"}}},
			{ID: "p-vm", NetworkID: "net-T1", ProjectID: "T1",
				DeviceOwner: "compute:nova", DeviceID: "instance-uuid",
				FixedIPs: []FixedIP{{SubnetID: "sub-T1", IPAddress: "10.0.1.50"}}},
		},
		[]Router{{
			ID: "R1", ProjectID: "T1",
			Routes: []Route{{Destination: "172.16.99.0/24", Nexthop: "10.0.1.50"}},
		}},
	)
	want := TrieEntry{TenantID: "T1", Prefix: mustPrefix(t, "172.16.99.0/24"), Zone: bpf.ZoneSameTenant}
	found := false
	for _, e := range got {
		if e == want {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("extraroute entry missing from trie; got:\n%+v\nwant: %+v", got, want)
	}
}

// TestBuildTrie_Step5UnresolvableFallsBackExternal asserts that a
// route whose nexthop misses Step A (not on any of R1's iface
// subnets) classifies EXTERNAL — the resolver's catchall return —
// rather than being silently dropped.
func TestBuildTrie_Step5UnresolvableFallsBackExternal(t *testing.T) {
	got, _ := BuildTrie(
		nil, nil, nil,
		[]Router{{
			ID: "R1", ProjectID: "T1",
			Routes: []Route{{Destination: "10.99.0.0/16", Nexthop: "10.0.0.2"}},
		}},
	)
	want := TrieEntry{TenantID: "T1", Prefix: mustPrefix(t, "10.99.0.0/16"), Zone: bpf.ZoneExternal}
	found := false
	for _, e := range got {
		if e == want {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("unresolvable extraroute should emit EXTERNAL; got:\n%+v", got)
	}
}

// TestBuildTrie_Step5InvalidRouteSkipped asserts malformed
// destination CIDRs and nexthops are skipped with a warn log
// (matching the Step 2/4 invalid-CIDR pattern), so a single stale
// route can't block boot.
func TestBuildTrie_Step5InvalidRouteSkipped(t *testing.T) {
	got, _ := BuildTrie(
		nil, nil, nil,
		[]Router{{
			ID: "R1", ProjectID: "T1",
			Routes: []Route{
				{Destination: "not-a-cidr", Nexthop: "10.0.0.2"},
				{Destination: "10.99.0.0/16", Nexthop: "not-an-ip"},
			},
		}},
	)
	for _, e := range got {
		if e.TenantID == "T1" && e.Prefix.String() == "10.99.0.0/16" {
			// Permitted: a valid CIDR with an unparseable nexthop is
			// dropped before the resolver runs (warn-logged) — this
			// assertion confirms nothing leaked into the trie.
			t.Errorf("invalid route leaked into trie: %+v", e)
		}
	}
	// T1 has no per-tenant rows: all extraroutes were invalid and
	// no owned subnets exist. Globals (catchall + metadata) emit
	// under TenantID="" not under T1.
	if countTenant(got, "T1") != 0 {
		t.Errorf("T1 expected 0 rows (all extraroutes invalid), got %d", countTenant(got, "T1"))
	}
}

// TestBuildTrie_Deterministic asserts byte-identical output across
// two runs over identical input. Required so the future kernel
// writer can detect "nothing changed" and avoid map churn.
func TestBuildTrie_Deterministic(t *testing.T) {
	nets := []Network{
		{ID: "n2", ProjectID: "T2"},
		{ID: "n1", ProjectID: "T1"},
	}
	subs := []Subnet{
		{ID: "s2", NetworkID: "n2", ProjectID: "T2", CIDR: "10.2.0.0/24", IPVersion: 4},
		{ID: "s1", NetworkID: "n1", ProjectID: "T1", CIDR: "10.1.0.0/24", IPVersion: 4},
	}
	first, _ := BuildTrie(nets, subs, nil, nil)
	second, _ := BuildTrie(nets, subs, nil, nil)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("non-deterministic output:\nfirst:  %+v\nsecond: %+v", first, second)
	}
	// Sanity: also assert sort order is TenantID-major.
	for i := 1; i < len(first); i++ {
		if first[i].TenantID < first[i-1].TenantID {
			t.Errorf("output not TenantID-sorted at index %d: %q before %q",
				i, first[i-1].TenantID, first[i].TenantID)
		}
	}
}

// TestBuildTrie_SingleProjectCollapsesToOneTenant guards against a
// double-enumeration regression: if a single logical project ID
// surfaces on every resource type (network / subnet / port /
// router), collectTenants must dedupe it. A buggy implementation
// that hashed by `(project_id, resource_kind)` would emit a
// per-tenant SAME_TENANT row per kind and inflate trie usage.
// Paired with TestList*_TenantIDFallback (list_test.go), which
// proves preferProjectID collapses `tenant_id`-only inputs to the
// same string this test then sees.
//
// Under the trie-dedup model, globals emit under TenantID="" — so
// the output has TWO distinct TenantID values for any non-empty
// snapshot. The invariant being pinned here is "exactly one
// non-empty tenant for this single-project snapshot".
func TestBuildTrie_SingleProjectCollapsesToOneTenant(t *testing.T) {
	got, _ := BuildTrie(
		[]Network{{ID: "n1", ProjectID: "proj-X"}},
		[]Subnet{{ID: "s1", NetworkID: "n1", ProjectID: "proj-X", CIDR: "10.0.0.0/24", IPVersion: 4}},
		[]Port{{ID: "p1", NetworkID: "n1", ProjectID: "proj-X", DeviceOwner: "compute:nova"}},
		[]Router{{ID: "r1", ProjectID: "proj-X"}},
	)
	nonEmpty := map[string]int{}
	for _, e := range got {
		if e.TenantID != "" {
			nonEmpty[e.TenantID]++
		}
	}
	if len(nonEmpty) != 1 {
		t.Fatalf("expected 1 distinct non-empty tenant, got %d (%v)", len(nonEmpty), nonEmpty)
	}
	if _, ok := nonEmpty["proj-X"]; !ok {
		t.Fatalf("expected tenant proj-X, got %v", nonEmpty)
	}
}

// TestBuildTrie_TenantsFromAllResources pins the contract that
// collectTenants picks up a ProjectID from any resource type
// (network, port, router). Under the trie-dedup model, per-tenant
// emission (Steps 2/5) is the only path that surfaces a tenant in
// BuildTrie's entry slice — and the minimal fixture below
// intentionally triggers neither — so the assertion is on
// collectTenants directly. Globals emit under TenantID="" and tell
// us nothing about which input tenants were recognized.
func TestBuildTrie_TenantsFromAllResources(t *testing.T) {
	got := collectTenants(
		[]Network{{ID: "n1", ProjectID: "T-net"}},
		[]Port{{ProjectID: "T-port"}},
		[]Router{{ProjectID: "T-router"}},
	)
	want := []string{"T-net", "T-port", "T-router"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("collectTenants = %v, want %v", got, want)
	}
}
