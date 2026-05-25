package agent

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/metadata"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/neutron"
)

func renderLanding(t *testing.T, a *Agent, rawQuery string) string {
	t.Helper()
	url := "/debug"
	if rawQuery != "" {
		url += "?" + rawQuery
	}
	req := httptest.NewRequest(http.MethodGet, url, nil)
	rec := httptest.NewRecorder()
	a.handleDebugLanding(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", ct)
	}
	return rec.Body.String()
}

func containsAll(t *testing.T, body string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(body, w) {
			t.Errorf("body missing %q\n--- body ---\n%s", w, body)
		}
	}
}

func TestHandleDebugLanding_EmptyState(t *testing.T) {
	a := &Agent{}
	body := renderLanding(t, a, "")
	containsAll(t, body,
		"Telemetry Agent — /debug",
		"never", // sync badge
		"Health",
		"Anomalies",
		"Lookup",
	)
	// All anomaly sections render their "none" placeholder.
	if got := strings.Count(body, ">none<"); got != 5 {
		t.Errorf("expected 5 'none' placeholders (one per anomaly section), got %d", got)
	}
}

func TestHandleDebugLanding_CountsFromSnapshot(t *testing.T) {
	a := &Agent{}
	a.SetNeutronSnapshot(&neutron.Snapshot{
		Networks: []neutron.Network{
			{ID: "n1", ProjectID: "T1"},
			{ID: "n2", ProjectID: "T2"},
		},
		Subnets: []neutron.Subnet{{ID: "s1"}, {ID: "s2"}, {ID: "s3"}},
		Ports:   []neutron.Port{{ID: "p1", ProjectID: "T1"}, {ID: "p2", ProjectID: "T2"}},
		Routers: []neutron.Router{{ID: "r1", ProjectID: "T1"}},
	})
	a.SetTrieEntries([]neutron.TrieEntry{
		{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Zone: bpf.ZoneExternal},
		{Prefix: netip.MustParsePrefix("10.0.0.0/24"), Zone: bpf.ZoneSameTenant, TenantID: "T1"},
	})
	a.MarkNeutronSync(time.Now())

	body := renderLanding(t, a, "")
	containsAll(t, body,
		">2<", // tenants — count appears in cells
		">3<", // subnets
	)
	// Spot-check section labels are present.
	containsAll(t, body, "Tenants", "Networks", "Subnets", "Ports", "Routers", "Trie rows")
}

func TestHandleDebugLanding_RendersEachAnomalyType(t *testing.T) {
	a := &Agent{}
	a.SetNeutronSnapshot(&neutron.Snapshot{
		Projects: []neutron.Project{
			{ID: "T1", Name: "alpha"},
			{ID: "T2", Name: "beta"},
		},
	})
	a.SetAnomalies(&neutron.Anomalies{
		Cycles: []neutron.CycleHit{{
			SourceTenant: "T1", SourceRouter: "rA",
			Destination: netip.MustParsePrefix("10.0.0.0/24"), LoopRouter: "rA",
		}},
		Ambiguities: []neutron.AmbiguityHit{{
			SourceTenant: "T1", RouterID: "rA",
			Destination: netip.MustParsePrefix("10.0.0.0/24"),
			Owners:      []string{"T2"},
		}},
		DanglingRoutes: []neutron.DanglingRoute{{
			SourceTenant: "T1", SourceRouter: "rB",
			Destination: "192.168.99.0/24", Nexthop: "10.0.0.99",
		}},
		ZeroTrieTenants: []neutron.ZeroTrieTenant{{
			TenantID: "T1", Networks: 1, Routers: 0, Ports: 3,
		}},
		DuplicateRouterMACs: []neutron.DuplicateRouterMAC{{
			MAC:       "fa:16:3e:00:00:01",
			PortIDs:   []string{"p-A", "p-B"},
			RouterIDs: []string{"rA", "rB"},
		}},
	})

	body := renderLanding(t, a, "")
	containsAll(t, body,
		"alpha",              // SourceTenantName rendered for cycles + ambiguities + dangling + zero-trie
		"beta",               // ambiguity owners display
		"rA",                 // cycle SourceRouter
		"192.168.99.0/24",    // dangling destination
		"10.0.0.99",          // dangling nexthop
		"fa:16:3e:00:00:01",  // dup MAC
		"p-A, p-B",           // dup MAC port list
	)
	// Anomalies badge shows total = 5
	containsAll(t, body, "Anomalies <span class=\"badge warn\">5")
}

func TestHandleDebugLanding_LookupFormPreFilledAndResultInline(t *testing.T) {
	a := &Agent{meta: metadata.New()}
	a.SetNeutronSnapshot(&neutron.Snapshot{
		Networks: []neutron.Network{{ID: "n1", Name: "private", ProjectID: "T1"}},
		Subnets:  []neutron.Subnet{{ID: "s1", NetworkID: "n1", ProjectID: "T1", CIDR: "10.0.0.0/24", IPVersion: 4}},
		Ports: []neutron.Port{{
			ID: "p1", NetworkID: "n1", ProjectID: "T1",
			MACAddress: "fa:16:3e:00:00:01", DeviceOwner: "compute:nova",
			FixedIPs: []neutron.FixedIP{{SubnetID: "s1", IPAddress: "10.0.0.5"}},
		}},
		Projects: []neutron.Project{{ID: "T1", Name: "alpha"}},
	})
	a.SetTrieEntries([]neutron.TrieEntry{
		{TenantID: "", Prefix: netip.MustParsePrefix("0.0.0.0/0"), Zone: bpf.ZoneExternal},
		{TenantID: "T1", Prefix: netip.MustParsePrefix("10.0.0.0/24"), Zone: bpf.ZoneSameTenant},
	})

	body := renderLanding(t, a, "ip=10.0.0.5&tenant=T1")
	containsAll(t, body,
		`name="ip" value="10.0.0.5"`,           // form pre-fill
		`name="tenant" value="T1"`,             // form pre-fill
		"Result",                                // result block
		"SAME_TENANT",                           // zone code
		"via tenant",                            // via field
		"alpha",                                 // owner name resolved
		"compute:nova",                          // port device_owner
	)
}

func TestHandleDebugLanding_InvalidLookupRendersError(t *testing.T) {
	a := &Agent{}
	body := renderLanding(t, a, "ip=not-an-ip")
	containsAll(t, body,
		"lookup-err",
		"invalid ip",
	)
	if strings.Contains(body, `<div class="lookup-result">`) {
		t.Errorf("expected no result block on error; body contains result div")
	}
}

func TestHandleDebugLanding_StaleBadge(t *testing.T) {
	a := &Agent{}
	a.MarkNeutronSync(time.Now().Add(-10 * time.Minute))
	body := renderLanding(t, a, "")
	containsAll(t, body, `class="badge warn"`, "ago")
}

func TestHumanAge(t *testing.T) {
	cases := map[time.Duration]string{
		0:                  "0s",
		45 * time.Second:   "45s",
		2 * time.Minute:    "2m",
		73 * time.Minute:   "1h13m",
		3 * time.Hour:      "3h",
		-5 * time.Second:   "0s",
	}
	for d, want := range cases {
		if got := humanAge(d); got != want {
			t.Errorf("humanAge(%v) = %q, want %q", d, got, want)
		}
	}
}
