package neutron

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
)

// has returns true if entries contains an entry equal to want.
// BuildTrie sorts its output, but tests assert presence of specific
// rows; ordering details are exercised by [TestBuildTrie_Deterministic].
func has(entries []TrieEntry, want TrieEntry) bool {
	for _, e := range entries {
		if e == want {
			return true
		}
	}
	return false
}

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
	got := BuildTrie(nil, nil, nil, nil)
	if len(got) != 0 {
		t.Fatalf("BuildTrie(empty) = %v, want empty", got)
	}
}

// TestBuildTrie_Step1Catchall asserts every tenant gets `0.0.0.0/0
// → EXTERNAL`, regardless of which resource type their ProjectID
// surfaces in.
func TestBuildTrie_Step1Catchall(t *testing.T) {
	got := BuildTrie(
		[]Network{{ID: "n1", ProjectID: "t-from-net"}},
		nil,
		[]Port{{ID: "p1", ProjectID: "t-from-port"}},
		[]Router{{ID: "r1", ProjectID: "t-from-router"}},
	)
	want := mustPrefix(t, "0.0.0.0/0")
	for _, tenant := range []string{"t-from-net", "t-from-port", "t-from-router"} {
		if !has(got, TrieEntry{tenant, want, bpf.ZoneExternal}) {
			t.Errorf("tenant %q missing catchall row", tenant)
		}
	}
}

// TestBuildTrie_Step2OwnedSubnets exercises a single-tenant network
// with one non-shared subnet. Expected: catchall + SAME_TENANT for
// the subnet's CIDR + metadata INFRA.
func TestBuildTrie_Step2OwnedSubnets(t *testing.T) {
	got := BuildTrie(
		[]Network{{ID: "n1", ProjectID: "T1", Shared: false}},
		[]Subnet{{ID: "s1", NetworkID: "n1", ProjectID: "T1", CIDR: "10.0.0.0/24", IPVersion: 4}},
		nil, nil,
	)
	if !has(got, TrieEntry{"T1", mustPrefix(t, "10.0.0.0/24"), bpf.ZoneSameTenant}) {
		t.Fatalf("missing SAME_TENANT row\n%+v", got)
	}
}

// TestBuildTrie_SharedNetworkEmitsShared asserts that subnets on a
// shared network produce a uniform SHARED row for every tenant —
// owner and non-owner alike. SHARED (not SAME / not OTHER) reflects
// the structural ambiguity: the trie cannot disambiguate per-VM
// ownership inside a shared CIDR, and guessing either side
// systematically mis-bills the wrong direction.
func TestBuildTrie_SharedNetworkEmitsShared(t *testing.T) {
	got := BuildTrie(
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
	// Owner T1 — not SAME (would be a guess), not OTHER (would be
	// a guess), must be SHARED.
	if has(got, TrieEntry{"T1", shared, bpf.ZoneSameTenant}) {
		t.Errorf("shared subnet leaked into Step 2 for owner T1 as SAME_TENANT")
	}
	if has(got, TrieEntry{"T1", shared, bpf.ZoneOtherTenant}) {
		t.Errorf("shared subnet emitted as OTHER_TENANT for owner T1; expect SHARED")
	}
	if !has(got, TrieEntry{"T1", shared, bpf.ZoneShared}) {
		t.Errorf("shared subnet not SHARED for owner T1")
	}
	// Non-owner T2 — also SHARED. The schema doesn't distinguish
	// owner from non-owner in shared-network attribution.
	if has(got, TrieEntry{"T2", shared, bpf.ZoneOtherTenant}) {
		t.Errorf("shared subnet emitted as OTHER_TENANT for non-owner T2; expect SHARED")
	}
	if !has(got, TrieEntry{"T2", shared, bpf.ZoneShared}) {
		t.Errorf("shared subnet not SHARED for non-owner T2")
	}
}

// TestBuildTrie_ExternalNetworkSkipsStep3 asserts that a network
// marked router:external=true is excluded from the trie even when
// shared=true. A buggy implementation would emit OTHER_TENANT for
// the floating-IP-pool CIDR; the catchall then EXTERNAL-classifies
// any address in that pool correctly via fallthrough.
func TestBuildTrie_ExternalNetworkSkipsStep3(t *testing.T) {
	got := BuildTrie(
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
	got := BuildTrie(
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
	got := BuildTrie(
		[]Network{{ID: "n1", ProjectID: "T1"}},
		nil,
		append(ports, Port{ProjectID: "T1"}), // ensure tenant gets enumerated
		nil,
	)
	for _, infraIP := range []string{"10.0.0.1", "192.0.2.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"} {
		want := TrieEntry{"T1", netip.MustParsePrefix(infraIP + "/32"), bpf.ZoneInfra}
		if !has(got, want) {
			t.Errorf("missing INFRA row for %s\nentries: %+v", infraIP, got)
		}
	}
	for _, notInfra := range []string{"10.0.0.42", "10.0.0.99", "10.0.0.100", "203.0.113.7"} {
		if has(got, TrieEntry{"T1", netip.MustParsePrefix(notInfra + "/32"), bpf.ZoneInfra}) {
			t.Errorf("non-infra IP %s leaked into INFRA", notInfra)
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
		if got := isInfraPort(tc.deviceOwner); got != tc.want {
			t.Errorf("isInfraPort(%q) = %v, want %v", tc.deviceOwner, got, tc.want)
		}
	}
}

func TestBuildTrie_Step4GatewayIPAndMetadata(t *testing.T) {
	got := BuildTrie(
		[]Network{{ID: "n1", ProjectID: "T1"}},
		[]Subnet{{ID: "s1", NetworkID: "n1", CIDR: "10.0.0.0/24", GatewayIP: "10.0.0.1", IPVersion: 4}},
		nil, nil,
	)
	if !has(got, TrieEntry{"T1", netip.MustParsePrefix("10.0.0.1/32"), bpf.ZoneInfra}) {
		t.Errorf("gateway IP /32 missing as INFRA")
	}
	if !has(got, TrieEntry{"T1", netip.MustParsePrefix("169.254.169.254/32"), bpf.ZoneInfra}) {
		t.Errorf("Nova metadata IP missing as INFRA")
	}
}

func TestBuildTrie_SkipsIPv6(t *testing.T) {
	got := BuildTrie(
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
	if !has(got, TrieEntry{"T1", mustPrefix(t, "10.0.0.0/24"), bpf.ZoneSameTenant}) {
		t.Errorf("IPv4 subnet missing")
	}
}

func TestBuildTrie_MalformedCIDRSkipped(t *testing.T) {
	got := BuildTrie(
		[]Network{{ID: "n1", ProjectID: "T1"}},
		[]Subnet{
			{ID: "s-bad", NetworkID: "n1", ProjectID: "T1", CIDR: "not-a-cidr", IPVersion: 4},
			{ID: "s-good", NetworkID: "n1", ProjectID: "T1", CIDR: "10.0.0.0/24", IPVersion: 4},
		},
		nil, nil,
	)
	if !has(got, TrieEntry{"T1", mustPrefix(t, "10.0.0.0/24"), bpf.ZoneSameTenant}) {
		t.Fatalf("good CIDR should still be present after a sibling parse failure")
	}
}

// TestBuildTrie_Step5Omitted asserts router.Routes are silently
// ignored: the catchall (Step 1) carries the classification as
// EXTERNAL until Sprint 4b's resolver lands.
func TestBuildTrie_Step5Omitted(t *testing.T) {
	got := BuildTrie(
		nil, nil, nil,
		[]Router{{
			ID:        "r1",
			ProjectID: "T1",
			Routes:    []Route{{Destination: "10.99.0.0/16", Nexthop: "10.0.0.2"}},
		}},
	)
	// No row for 10.99.0.0/16 should appear; the only T1 rows are
	// catchall + metadata INFRA.
	for _, e := range got {
		if e.TenantID == "T1" && e.Prefix == mustPrefix(t, "10.99.0.0/16") {
			t.Errorf("extra route leaked into trie: %+v", e)
		}
	}
	if countTenant(got, "T1") != 2 {
		t.Errorf("T1 expected 2 rows (catchall + metadata), got %d", countTenant(got, "T1"))
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
	first := BuildTrie(nets, subs, nil, nil)
	second := BuildTrie(nets, subs, nil, nil)
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
// catchall per kind and inflate kernel-trie usage 4× per active
// tenant. Paired with TestList*_TenantIDFallback (list_test.go),
// which proves preferProjectID collapses `tenant_id`-only inputs
// to the same string this test then sees.
func TestBuildTrie_SingleProjectCollapsesToOneTenant(t *testing.T) {
	got := BuildTrie(
		[]Network{{ID: "n1", ProjectID: "proj-X"}},
		[]Subnet{{ID: "s1", NetworkID: "n1", ProjectID: "proj-X", CIDR: "10.0.0.0/24", IPVersion: 4}},
		[]Port{{ID: "p1", NetworkID: "n1", ProjectID: "proj-X", DeviceOwner: "compute:nova"}},
		[]Router{{ID: "r1", ProjectID: "proj-X"}},
	)
	tenants := map[string]int{}
	for _, e := range got {
		tenants[e.TenantID]++
	}
	if len(tenants) != 1 {
		t.Fatalf("expected 1 tenant in output, got %d (%v)", len(tenants), tenants)
	}
	if _, ok := tenants["proj-X"]; !ok {
		t.Fatalf("expected tenant proj-X, got %v", tenants)
	}
}

func TestBuildTrie_TenantsFromAllResources(t *testing.T) {
	got := BuildTrie(
		[]Network{{ID: "n1", ProjectID: "T-net"}},
		nil,
		[]Port{{ProjectID: "T-port"}},
		[]Router{{ProjectID: "T-router"}},
	)
	for _, t1 := range []string{"T-net", "T-port", "T-router"} {
		if countTenant(got, t1) == 0 {
			t.Errorf("tenant %q produced no entries", t1)
		}
	}
}
