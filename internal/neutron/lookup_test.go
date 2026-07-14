package neutron

import (
	"net/netip"
	"testing"

	"github.com/bigstack-oss/lachesis/internal/bpf"
)

func TestSnapshot_ProjectName(t *testing.T) {
	snap := Snapshot{Projects: []Project{
		{ID: "p-1", Name: "alpha"},
		{ID: "p-2", Name: "beta"},
	}}
	tests := []struct {
		id, want string
	}{
		{"p-1", "alpha"},
		{"p-2", "beta"},
		{"p-unknown", ""},
		{"", ""},
	}
	for _, tc := range tests {
		if got := snap.ProjectName(tc.id); got != tc.want {
			t.Errorf("ProjectName(%q) = %q, want %q", tc.id, got, tc.want)
		}
	}
	if got := (Snapshot{}).ProjectName("p-1"); got != "" {
		t.Errorf("empty snapshot: got %q, want \"\"", got)
	}
}

// TestLookupZone_PerTenantBeatsGlobal asserts the two-pass
// behaviour: a per-tenant SAME_TENANT row covering an IP takes
// precedence over the global catchall, even when the catchall is
// a stricter (longer) prefix than the per-tenant row.
func TestLookupZone_PerTenantBeatsGlobal(t *testing.T) {
	entries := []TrieEntry{
		{TenantID: "", Prefix: mustPrefix(t, "0.0.0.0/0"), Zone: bpf.ZoneExternal},
		{TenantID: "T1", Prefix: mustPrefix(t, "10.0.0.0/24"), Zone: bpf.ZoneSameTenant},
	}
	hit, via := LookupZone(entries, netip.MustParseAddr("10.0.0.5"), "T1")
	if hit == nil || hit.Zone != bpf.ZoneSameTenant || via != "tenant" {
		t.Fatalf("got=(%+v, %q), want SAME_TENANT via=tenant", hit, via)
	}
}

// TestLookupZone_FallsBackToGlobal asserts the second pass:
// a tenant without a matching per-tenant row falls through to the
// global catchall.
func TestLookupZone_FallsBackToGlobal(t *testing.T) {
	entries := []TrieEntry{
		{TenantID: "", Prefix: mustPrefix(t, "0.0.0.0/0"), Zone: bpf.ZoneExternal},
		{TenantID: "T1", Prefix: mustPrefix(t, "10.0.0.0/24"), Zone: bpf.ZoneSameTenant},
	}
	hit, via := LookupZone(entries, netip.MustParseAddr("10.0.0.5"), "T2")
	if hit == nil || hit.Zone != bpf.ZoneExternal || via != "global" {
		t.Fatalf("got=(%+v, %q), want EXTERNAL via=global", hit, via)
	}
}

// TestLookupZone_LongestPrefixWins asserts /32 beats /24 within
// the same tenant scope — same LPM semantics the kernel applies.
func TestLookupZone_LongestPrefixWins(t *testing.T) {
	entries := []TrieEntry{
		{TenantID: "", Prefix: mustPrefix(t, "10.0.0.0/24"), Zone: bpf.ZoneShared},
		{TenantID: "", Prefix: mustPrefix(t, "10.0.0.5/32"), Zone: bpf.ZoneInfra},
	}
	hit, via := LookupZone(entries, netip.MustParseAddr("10.0.0.5"), "")
	if hit == nil || hit.Zone != bpf.ZoneInfra || via != "global" {
		t.Fatalf("got=(%+v, %q), want INFRA via=global", hit, via)
	}
}

// TestLookupZone_EmptyTenantSkipsTenantPass asserts that passing
// tenant="" goes straight to the global pass (no synthetic
// double-match against rows whose TenantID is also "").
func TestLookupZone_EmptyTenantSkipsTenantPass(t *testing.T) {
	entries := []TrieEntry{
		{TenantID: "", Prefix: mustPrefix(t, "0.0.0.0/0"), Zone: bpf.ZoneExternal},
	}
	hit, via := LookupZone(entries, netip.MustParseAddr("1.2.3.4"), "")
	if hit == nil || via != "global" {
		t.Fatalf("got=(%+v, %q), want EXTERNAL via=global", hit, via)
	}
}

// TestLookupResource_SubnetNetworkPort exercises the full chain:
// the IP lives in the most-specific covering subnet, the subnet's
// network is resolved, and the port carrying that fixed_ip is
// found.
func TestLookupResource_SubnetNetworkPort(t *testing.T) {
	snap := &Snapshot{
		Networks: []Network{
			{ID: "n1", Name: "alpha", ProjectID: "T1"},
		},
		Subnets: []Subnet{
			{ID: "s1", NetworkID: "n1", CIDR: "10.0.0.0/16", IPVersion: 4},
			{ID: "s2", NetworkID: "n1", CIDR: "10.0.5.0/24", IPVersion: 4}, // more-specific
		},
		Ports: []Port{
			{ID: "p1", NetworkID: "n1", MACAddress: "fa:16:3e:00:00:01",
				DeviceOwner: "compute:nova", DeviceID: "vm-uuid",
				FixedIPs: []FixedIP{{SubnetID: "s2", IPAddress: "10.0.5.42"}}},
		},
	}
	m := LookupResource(snap, netip.MustParseAddr("10.0.5.42"), "")
	if m.Subnet == nil || m.Subnet.ID != "s2" {
		t.Errorf("Subnet = %+v, want s2", m.Subnet)
	}
	if m.Network == nil || m.Network.ID != "n1" {
		t.Errorf("Network = %+v, want n1", m.Network)
	}
	if m.Port == nil || m.Port.ID != "p1" {
		t.Errorf("Port = %+v, want p1", m.Port)
	}
}

// TestLookupResource_UnallocatedInKnownSubnet: an IP inside a known
// subnet but not on any port resolves Subnet+Network with Port=nil.
func TestLookupResource_UnallocatedInKnownSubnet(t *testing.T) {
	snap := &Snapshot{
		Networks: []Network{{ID: "n1"}},
		Subnets:  []Subnet{{ID: "s1", NetworkID: "n1", CIDR: "10.0.0.0/24", IPVersion: 4}},
	}
	m := LookupResource(snap, netip.MustParseAddr("10.0.0.99"), "")
	if m.Subnet == nil || m.Subnet.ID != "s1" {
		t.Errorf("Subnet = %+v, want s1", m.Subnet)
	}
	if m.Network == nil || m.Network.ID != "n1" {
		t.Errorf("Network = %+v, want n1", m.Network)
	}
	if m.Port != nil {
		t.Errorf("Port = %+v, want nil", m.Port)
	}
}

// TestLookupResource_TenantScopedDisambiguatesSharedCIDR mirrors
// the real dev-cmp condition where many tenants each own their
// own 192.168.0.0/24. Passing tenant=T2 must surface T2's subnet
// and port, not whichever tenant's subnet happens to appear first
// in the snapshot. Empty tenant returns whatever comes first
// (no scoping).
func TestLookupResource_TenantScopedDisambiguatesSharedCIDR(t *testing.T) {
	snap := &Snapshot{
		Networks: []Network{
			{ID: "n-T1", ProjectID: "T1", Name: "T1-private"},
			{ID: "n-T2", ProjectID: "T2", Name: "T2-private"},
		},
		Subnets: []Subnet{
			{ID: "s-T1", NetworkID: "n-T1", ProjectID: "T1", CIDR: "192.168.0.0/24", IPVersion: 4},
			{ID: "s-T2", NetworkID: "n-T2", ProjectID: "T2", CIDR: "192.168.0.0/24", IPVersion: 4},
		},
		Ports: []Port{
			{ID: "p-T1", NetworkID: "n-T1", ProjectID: "T1", DeviceOwner: "compute:nova",
				FixedIPs: []FixedIP{{SubnetID: "s-T1", IPAddress: "192.168.0.10"}}},
			{ID: "p-T2", NetworkID: "n-T2", ProjectID: "T2", DeviceOwner: "compute:nova",
				FixedIPs: []FixedIP{{SubnetID: "s-T2", IPAddress: "192.168.0.10"}}},
		},
	}
	m := LookupResource(snap, netip.MustParseAddr("192.168.0.10"), "T2")
	if m.Subnet == nil || m.Subnet.ID != "s-T2" {
		t.Errorf("Subnet = %+v, want s-T2 (tenant-scoped)", m.Subnet)
	}
	if m.Port == nil || m.Port.ID != "p-T2" {
		t.Errorf("Port = %+v, want p-T2 (tenant-scoped)", m.Port)
	}
	if m.Network == nil || m.Network.ID != "n-T2" {
		t.Errorf("Network = %+v, want n-T2", m.Network)
	}
}

// TestLookupResource_TenantScopedFallsBackToGlobal: an IP outside
// the queried tenant's subnets still surfaces a match if any
// other tenant covers it. Better to show *something* the operator
// can investigate than to return empty.
func TestLookupResource_TenantScopedFallsBackToGlobal(t *testing.T) {
	snap := &Snapshot{
		Networks: []Network{{ID: "n-T1", ProjectID: "T1"}},
		Subnets:  []Subnet{{ID: "s-T1", NetworkID: "n-T1", ProjectID: "T1", CIDR: "10.0.0.0/24", IPVersion: 4}},
	}
	m := LookupResource(snap, netip.MustParseAddr("10.0.0.5"), "T2")
	if m.Subnet == nil || m.Subnet.ID != "s-T1" {
		t.Errorf("Subnet = %+v, want s-T1 (fallback)", m.Subnet)
	}
}

// TestLookupResource_OutsideEverySubnet returns a zero match.
func TestLookupResource_OutsideEverySubnet(t *testing.T) {
	snap := &Snapshot{
		Subnets: []Subnet{{ID: "s1", CIDR: "10.0.0.0/24", IPVersion: 4}},
	}
	m := LookupResource(snap, netip.MustParseAddr("192.168.99.1"), "")
	if m.Subnet != nil || m.Network != nil || m.Port != nil {
		t.Fatalf("expected zero ResourceMatch, got %+v", m)
	}
}

// TestLookupPortByMAC_CaseInsensitive: Neutron emits MACs in either
// case; the lookup must match regardless. Also asserts Network is
// resolved alongside the port.
func TestLookupPortByMAC_CaseInsensitive(t *testing.T) {
	snap := &Snapshot{
		Networks: []Network{{ID: "n1", Name: "alpha"}},
		Ports: []Port{
			{ID: "p1", NetworkID: "n1", MACAddress: "fa:16:3e:AB:cd:01", DeviceOwner: "compute:nova"},
		},
	}
	m := LookupPortByMAC(snap, "FA:16:3e:ab:CD:01")
	if m.Port == nil || m.Port.ID != "p1" {
		t.Errorf("Port = %+v, want p1", m.Port)
	}
	if m.Network == nil || m.Network.ID != "n1" {
		t.Errorf("Network = %+v, want n1", m.Network)
	}
	if m.Subnet != nil {
		t.Errorf("Subnet = %+v, want nil for MAC lookup", m.Subnet)
	}
}

// TestLookupPortByMAC_Miss returns a zero ResourceMatch when no
// port carries the MAC.
func TestLookupPortByMAC_Miss(t *testing.T) {
	snap := &Snapshot{
		Ports: []Port{{ID: "p1", MACAddress: "fa:16:3e:00:00:01"}},
	}
	m := LookupPortByMAC(snap, "fa:16:3e:00:00:99")
	if m.Port != nil || m.Network != nil || m.Subnet != nil {
		t.Fatalf("expected zero ResourceMatch, got %+v", m)
	}
}

// TestLookupNilSnapshot returns zero results without panicking.
func TestLookupNilSnapshot(t *testing.T) {
	if m := LookupResource(nil, netip.MustParseAddr("10.0.0.1"), ""); m.Subnet != nil || m.Port != nil {
		t.Errorf("LookupResource(nil) = %+v, want zero", m)
	}
	if m := LookupPortByMAC(nil, "fa:16:3e:00:00:01"); m.Port != nil {
		t.Errorf("LookupPortByMAC(nil) = %+v, want zero", m)
	}
}
