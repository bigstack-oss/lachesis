package debug

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/bigstack-oss/lachesis/internal/bpf"
	"github.com/bigstack-oss/lachesis/internal/neutron"
)

func zonesServer(entries []neutron.TrieEntry, snap *neutron.Snapshot) *Server {
	return New(Options{
		Snapshot: func() *neutron.Snapshot { return snap },
		Trie:     func() []neutron.TrieEntry { return entries },
		LastSync: func() time.Time { return time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC) },
	})
}

func TestZones_EmptyState(t *testing.T) {
	rec := get(t, New(Options{}).Handler(), "/debug/zones")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "No trie entries yet") {
		t.Errorf("missing empty-state message")
	}
}

func TestZones_RendersEntries(t *testing.T) {
	entries := []neutron.TrieEntry{
		{TenantID: "", Prefix: netip.MustParsePrefix("0.0.0.0/0"), Zone: bpf.ZoneExternal},
		{TenantID: "T1", Prefix: netip.MustParsePrefix("10.0.0.0/24"), Zone: bpf.ZoneSameTenant},
	}
	snap := &neutron.Snapshot{Projects: []neutron.Project{{ID: "T1", Name: "alpha"}}}

	rec := get(t, zonesServer(entries, snap).Handler(), "/debug/zones")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"(global)", "0.0.0.0/0", "external",
		"alpha", "10.0.0.0/24", "same_tenant",
		`data-tenant="T1"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("zones body missing %q", want)
		}
	}
}

func TestZones_JSON(t *testing.T) {
	entries := []neutron.TrieEntry{
		{TenantID: "T1", Prefix: netip.MustParsePrefix("10.0.0.0/24"), Zone: bpf.ZoneSameTenant},
	}
	rec := get(t, zonesServer(entries, nil).Handler(), "/debug/zones?format=json")
	var m zonesModel
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !m.Synced || len(m.Rows) != 1 {
		t.Fatalf("model = %+v, want synced with 1 row", m)
	}
	want := zoneRow{Tenant: "T1", TenantName: "T1", Prefix: "10.0.0.0/24", Zone: "same_tenant"}
	if m.Rows[0] != want {
		t.Errorf("row = %+v, want %+v", m.Rows[0], want)
	}
}

// TestBuildZonesModel_TenantsSortedAndUnique: the dropdown list
// holds one entry per distinct TenantID, sorted, with the global
// sentinel labelled.
func TestBuildZonesModel_TenantsSortedAndUnique(t *testing.T) {
	entries := []neutron.TrieEntry{
		{TenantID: "T2", Prefix: netip.MustParsePrefix("10.2.0.0/24"), Zone: bpf.ZoneSameTenant},
		{TenantID: "", Prefix: netip.MustParsePrefix("0.0.0.0/0"), Zone: bpf.ZoneExternal},
		{TenantID: "T1", Prefix: netip.MustParsePrefix("10.1.0.0/24"), Zone: bpf.ZoneSameTenant},
		{TenantID: "T1", Prefix: netip.MustParsePrefix("10.1.1.0/24"), Zone: bpf.ZoneSameTenant},
	}
	snap := &neutron.Snapshot{Projects: []neutron.Project{{ID: "T1", Name: "alpha"}}}

	m := buildZonesModel(entries, snap, time.Now())
	if len(m.Tenants) != 3 {
		t.Fatalf("Tenants = %d, want 3 (global, T1, T2)", len(m.Tenants))
	}
	if m.Tenants[0].ID != "" || m.Tenants[0].Label != "(global)" {
		t.Errorf("Tenants[0] = %+v, want global sentinel first", m.Tenants[0])
	}
	if m.Tenants[1].ID != "T1" || !strings.Contains(m.Tenants[1].Label, "alpha") {
		t.Errorf("Tenants[1] = %+v, want T1 labelled alpha", m.Tenants[1])
	}
	if m.Tenants[2].ID != "T2" {
		t.Errorf("Tenants[2] = %+v, want T2", m.Tenants[2])
	}
}
