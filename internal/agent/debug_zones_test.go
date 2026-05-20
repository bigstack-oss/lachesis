package agent

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/neutron"
)

func TestHandleDebugZones_EmptyState(t *testing.T) {
	a := &Agent{}

	req := httptest.NewRequest(http.MethodGet, "/debug/zones", nil)
	rec := httptest.NewRecorder()
	a.handleDebugZones(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Zone Map",
		"No trie entries yet",
		"never", // last-sync display when zero
	} {
		if !strings.Contains(body, want) {
			t.Errorf("empty-state body missing %q\n--- body ---\n%s", want, body)
		}
	}
}

func TestHandleDebugZones_RendersEntries(t *testing.T) {
	a := &Agent{}
	a.SetTrieEntries([]neutron.TrieEntry{
		{TenantID: "", Prefix: netip.MustParsePrefix("0.0.0.0/0"), Zone: bpf.ZoneExternal},
		{TenantID: "", Prefix: netip.MustParsePrefix("169.254.169.254/32"), Zone: bpf.ZoneInfra},
		{TenantID: "proj-A", Prefix: netip.MustParsePrefix("10.0.1.0/24"), Zone: bpf.ZoneSameTenant},
		{TenantID: "proj-B", Prefix: netip.MustParsePrefix("10.0.2.0/24"), Zone: bpf.ZoneSameTenant},
	})
	a.MarkNeutronSync(time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC))

	req := httptest.NewRequest(http.MethodGet, "/debug/zones", nil)
	rec := httptest.NewRecorder()
	a.handleDebugZones(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()

	// Sample of expected substrings: every CIDR, every tenant ID,
	// the global-sentinel display, the zone names, and the dropdown
	// scaffolding.
	for _, want := range []string{
		"0.0.0.0/0", "EXTERNAL",
		"169.254.169.254/32", "INFRA",
		"10.0.1.0/24", "SAME_TENANT",
		"10.0.2.0/24",
		"(global)", "proj-A", "proj-B",
		"2026-05-20T12:00:00Z",
		`<select id="tenant">`,
		`data-tenant="proj-A"`,
		`data-tenant=""`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("rendered body missing %q", want)
		}
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
}

func TestBuildZonesPage_TenantsSortedAndUnique(t *testing.T) {
	entries := []neutron.TrieEntry{
		{TenantID: "T2", Prefix: netip.MustParsePrefix("10.0.0.0/24"), Zone: bpf.ZoneSameTenant},
		{TenantID: "", Prefix: netip.MustParsePrefix("0.0.0.0/0"), Zone: bpf.ZoneExternal},
		{TenantID: "T1", Prefix: netip.MustParsePrefix("10.1.0.0/24"), Zone: bpf.ZoneSameTenant},
		{TenantID: "T1", Prefix: netip.MustParsePrefix("10.2.0.0/24"), Zone: bpf.ZoneSameTenant},
	}
	page := buildZonesPage(entries, time.Time{})

	want := []string{"", "T1", "T2"}
	if len(page.Tenants) != len(want) {
		t.Fatalf("Tenants = %v, want %v", page.Tenants, want)
	}
	for i, w := range want {
		if page.Tenants[i] != w {
			t.Errorf("Tenants[%d] = %q, want %q", i, page.Tenants[i], w)
		}
	}
	if got := len(page.Rows); got != len(entries) {
		t.Errorf("Rows len = %d, want %d", got, len(entries))
	}
}

