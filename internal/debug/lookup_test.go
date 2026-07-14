package debug

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/bigstack-oss/lachesis/internal/bpf"
	"github.com/bigstack-oss/lachesis/internal/metadata"
	"github.com/bigstack-oss/lachesis/internal/neutron"
)

// invoke runs the /debug/lookup handler against rawQuery and
// returns the decoded response + status. Tests check the status
// and the populated sub-sections (zone, neutron, mac) rather than
// raw JSON strings; the schema is exercised directly.
func invoke(t *testing.T, s *Server, rawQuery string) (lookupResult, int) {
	t.Helper()
	rec := get(t, s.Handler(), "/debug/lookup?"+rawQuery)
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	var got lookupResult
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode body: %v\n--- body ---\n%s", err, rec.Body.String())
	}
	return got, rec.Code
}

// lookupServer builds a Server over an optional snapshot, trie, and
// userspace MAC map.
func lookupServer(snap *neutron.Snapshot, trie []neutron.TrieEntry, meta *metadata.ShardedMetadataMap) *Server {
	opts := Options{
		Snapshot: func() *neutron.Snapshot { return snap },
		Trie:     func() []neutron.TrieEntry { return trie },
	}
	if meta != nil {
		opts.MACLookup = meta.Lookup
	}
	return New(opts)
}

func TestLookup_MissingParams_400(t *testing.T) {
	rec := get(t, New(Options{}).Handler(), "/debug/lookup")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "?ip=") {
		t.Errorf("error body missing usage hint: %s", rec.Body.String())
	}
}

func TestLookup_BothIPAndMAC_400(t *testing.T) {
	rec := get(t, New(Options{}).Handler(), "/debug/lookup?ip=10.0.0.1&mac=fa:16:3e:00:00:01")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestLookup_InvalidIP_400(t *testing.T) {
	rec := get(t, New(Options{}).Handler(), "/debug/lookup?ip=not-an-ip")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestLookup_InvalidMAC_400(t *testing.T) {
	rec := get(t, New(Options{}).Handler(), "/debug/lookup?mac=not-a-mac")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestLookup_IPWithTenant_HitsPerTenantRow: the IP 10.0.0.5 lives
// in T1's /24, and the snapshot has a port on it. The response
// should populate Zone (via=tenant) and Neutron (Subnet+Network+
// Port+Owner) and omit MAC.
func TestLookup_IPWithTenant_HitsPerTenantRow(t *testing.T) {
	snap := &neutron.Snapshot{
		Networks: []neutron.Network{{ID: "n1", Name: "private", ProjectID: "T1"}},
		Subnets:  []neutron.Subnet{{ID: "s1", NetworkID: "n1", CIDR: "10.0.0.0/24", IPVersion: 4}},
		Ports: []neutron.Port{{
			ID: "p1", NetworkID: "n1", ProjectID: "T1",
			MACAddress:  "fa:16:3e:00:00:01",
			DeviceOwner: "compute:nova", DeviceID: "vm-uuid",
			FixedIPs: []neutron.FixedIP{{SubnetID: "s1", IPAddress: "10.0.0.5"}},
		}},
		Projects: []neutron.Project{{ID: "T1", Name: "alpha-project"}},
	}
	trie := []neutron.TrieEntry{
		{TenantID: "", Prefix: netip.MustParsePrefix("0.0.0.0/0"), Zone: bpf.ZoneExternal},
		{TenantID: "T1", Prefix: netip.MustParsePrefix("10.0.0.0/24"), Zone: bpf.ZoneSameTenant},
	}

	got, status := invoke(t, lookupServer(snap, trie, nil), "ip=10.0.0.5&tenant=T1")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if got.Zone == nil || got.Zone.Code != "same_tenant" || got.Zone.Via != "tenant" {
		t.Errorf("Zone = %+v, want same_tenant via=tenant", got.Zone)
	}
	if got.Zone != nil && got.Zone.Match.TenantName != "alpha-project" {
		t.Errorf("Zone.Match.TenantName = %q, want alpha-project", got.Zone.Match.TenantName)
	}
	if got.Neutron == nil || got.Neutron.Port == nil || got.Neutron.Port.ID != "p1" {
		t.Errorf("Neutron.Port = %+v, want p1", got.Neutron)
	}
	if got.Neutron.Owner == nil || got.Neutron.Owner.Name != "alpha-project" {
		t.Errorf("Neutron.Owner = %+v, want alpha-project", got.Neutron.Owner)
	}
	if got.MAC != nil {
		t.Errorf("MAC = %+v, want nil for IP query", got.MAC)
	}
}

// TestLookup_IPNoTenant_FallsBackToGlobal: omitting the tenant
// takes the global-only path.
func TestLookup_IPNoTenant_FallsBackToGlobal(t *testing.T) {
	trie := []neutron.TrieEntry{
		{TenantID: "", Prefix: netip.MustParsePrefix("0.0.0.0/0"), Zone: bpf.ZoneExternal},
		{TenantID: "T1", Prefix: netip.MustParsePrefix("10.0.0.0/24"), Zone: bpf.ZoneSameTenant},
	}
	got, status := invoke(t, lookupServer(nil, trie, nil), "ip=10.0.0.5")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if got.Zone == nil || got.Zone.Code != "external" || got.Zone.Via != "global" {
		t.Fatalf("Zone = %+v, want external via=global", got.Zone)
	}
}

// TestLookup_IPOutsideSnapshot: a valid IP that no subnet covers
// still resolves via the catchall — Zone populated, Neutron
// section omitted.
func TestLookup_IPOutsideSnapshot(t *testing.T) {
	trie := []neutron.TrieEntry{
		{TenantID: "", Prefix: netip.MustParsePrefix("0.0.0.0/0"), Zone: bpf.ZoneExternal},
	}
	got, status := invoke(t, lookupServer(&neutron.Snapshot{}, trie, nil), "ip=8.8.8.8")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if got.Zone == nil || got.Zone.Code != "external" {
		t.Errorf("Zone = %+v, want external", got.Zone)
	}
	if got.Neutron != nil {
		t.Errorf("Neutron = %+v, want nil (IP outside every subnet)", got.Neutron)
	}
}

// TestLookup_MAC_FindsPortAndMapEntry: a MAC present in both the
// snapshot and the userspace MAC map fills Neutron (port + network
// + owner) and MAC entry (Found=true with TenantID).
func TestLookup_MAC_FindsPortAndMapEntry(t *testing.T) {
	mac := "fa:16:3e:ab:cd:01"
	snap := &neutron.Snapshot{
		Networks: []neutron.Network{{ID: "n1", Name: "alpha"}},
		Ports: []neutron.Port{{
			ID: "p1", NetworkID: "n1", ProjectID: "T1",
			MACAddress: mac, DeviceOwner: "compute:nova", DeviceID: "vm-uuid",
		}},
		Projects: []neutron.Project{{ID: "T1", Name: "alpha-project"}},
	}
	meta := metadata.New()
	meta.Insert(bpf.MACKey([6]uint8{0xfa, 0x16, 0x3e, 0xab, 0xcd, 0x01}),
		&metadata.TenantMeta{ProjectID: "T1", IsAmphora: false})

	got, status := invoke(t, lookupServer(snap, nil, meta), "mac="+mac)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if got.Neutron == nil || got.Neutron.Port == nil || got.Neutron.Port.ID != "p1" {
		t.Errorf("Neutron.Port = %+v, want p1", got.Neutron)
	}
	if got.MAC == nil || !got.MAC.Found || got.MAC.TenantID != "T1" {
		t.Errorf("MAC = %+v, want Found=true tenant=T1", got.MAC)
	}
	if got.MAC != nil && got.MAC.TenantName != "alpha-project" {
		t.Errorf("MAC.TenantName = %q, want alpha-project", got.MAC.TenantName)
	}
	if got.Zone != nil {
		t.Errorf("Zone = %+v, want nil for MAC query", got.Zone)
	}
}

// TestLookup_MAC_NoSnapshotNoMap: a MAC query against a bare
// server (no snapshot, no MAC map) returns Found=false and no
// Neutron section.
func TestLookup_MAC_NoSnapshotNoMap(t *testing.T) {
	got, status := invoke(t, New(Options{}), "mac=fa:16:3e:00:00:99")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if got.MAC == nil || got.MAC.Found {
		t.Errorf("MAC = %+v, want Found=false section", got.MAC)
	}
	if got.Neutron != nil {
		t.Errorf("Neutron = %+v, want nil", got.Neutron)
	}
}

// TestLookup_MAC_CanonicalisesQuery: an uppercase MAC input is
// echoed back in canonical lowercase form, matching the snapshot's
// normalised value.
func TestLookup_MAC_CanonicalisesQuery(t *testing.T) {
	got, status := invoke(t, New(Options{}), "mac=FA:16:3E:00:00:01")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if got.Query.MAC != "fa:16:3e:00:00:01" {
		t.Errorf("Query.MAC = %q, want lowercase canonical form", got.Query.MAC)
	}
}

// TestIndex_LookupForm: the index page runs the same lookup inline.
// A valid query renders the result block; an invalid one renders
// the error inline with HTTP 200 (no 4xx — the operator is on the
// page).
func TestIndex_LookupForm(t *testing.T) {
	snap := &neutron.Snapshot{
		Networks: []neutron.Network{{ID: "n1", Name: "private", ProjectID: "T1"}},
		Subnets:  []neutron.Subnet{{ID: "s1", NetworkID: "n1", CIDR: "10.0.0.0/24", IPVersion: 4}},
		Projects: []neutron.Project{{ID: "T1", Name: "alpha-project"}},
	}
	trie := []neutron.TrieEntry{
		{TenantID: "T1", Prefix: netip.MustParsePrefix("10.0.0.0/24"), Zone: bpf.ZoneSameTenant},
	}
	h := lookupServer(snap, trie, nil).Handler()

	rec := get(t, h, "/debug?ip=10.0.0.7&tenant=T1")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"same_tenant", "10.0.0.0/24", "alpha-project"} {
		if !strings.Contains(body, want) {
			t.Errorf("index lookup result missing %q", want)
		}
	}

	rec = get(t, h, "/debug?ip=garbage")
	if rec.Code != http.StatusOK {
		t.Fatalf("invalid-ip status = %d, want 200 (inline error)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "invalid ip") {
		t.Errorf("index missing inline lookup error")
	}
}
