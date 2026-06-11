package debug

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/neutron"
)

// testSnapshot is a small but fully-populated snapshot: two tenants,
// project names, one of each resource kind.
func testSnapshot() *neutron.Snapshot {
	return &neutron.Snapshot{
		Networks: []neutron.Network{
			{ID: "net-1", ProjectID: "T1"},
			{ID: "net-2", ProjectID: "T2", Shared: true},
		},
		Subnets: []neutron.Subnet{
			{ID: "sub-1", NetworkID: "net-1", ProjectID: "T1", CIDR: "10.0.0.0/24", IPVersion: 4},
		},
		Ports: []neutron.Port{
			{ID: "p-1", NetworkID: "net-1", ProjectID: "T1", DeviceOwner: "compute:nova"},
		},
		Routers: []neutron.Router{
			{ID: "r-1", ProjectID: "T1", Name: "edge"},
		},
		Projects: []neutron.Project{
			{ID: "T1", Name: "alpha"},
			{ID: "T2", Name: "beta"},
		},
	}
}

func testAnomalies(t *testing.T) *neutron.Anomalies {
	t.Helper()
	dst := netip.MustParsePrefix("10.99.0.0/16")
	return &neutron.Anomalies{
		Cycles: []neutron.CycleHit{
			{SourceTenant: "T1", SourceRouter: "r-1", Destination: dst, LoopRouter: "r-1"},
		},
		Ambiguities: []neutron.AmbiguityHit{
			{SourceTenant: "T1", RouterID: "r-1", Destination: dst, Owners: []string{"T1", "T2"}},
		},
		DanglingRoutes: []neutron.DanglingRoute{
			{SourceTenant: "T2", SourceRouter: "r-9", Destination: "10.5.0.0/24", Nexthop: "10.0.0.99"},
		},
	}
}

// newTestServer builds a Server over the canned snapshot/anomalies
// with a sync timestamp 30s in the past.
func newTestServer(t *testing.T) *Server {
	t.Helper()
	snap := testSnapshot()
	anoms := testAnomalies(t)
	return New(Options{
		Snapshot:  func() *neutron.Snapshot { return snap },
		Trie:      func() []neutron.TrieEntry { return []neutron.TrieEntry{{TenantID: "T1", Zone: bpf.ZoneSameTenant}} },
		Anomalies: func() *neutron.Anomalies { return anoms },
		LastSync:  func() time.Time { return time.Now().Add(-30 * time.Second) },
	})
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestIndex_HTML(t *testing.T) {
	rec := get(t, newTestServer(t).Handler(), "/debug")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{"Tenants", "Trie rows", "Anomalies", "/debug/anomalies", "s ago"} {
		if !strings.Contains(body, want) {
			t.Errorf("index body missing %q", want)
		}
	}
}

func TestIndex_JSON(t *testing.T) {
	rec := get(t, newTestServer(t).Handler(), "/debug?format=json")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var m indexModel
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("unmarshal: %v\nbody: %s", err, rec.Body.String())
	}
	if !m.Synced || m.SyncStale {
		t.Errorf("synced/stale = %v/%v, want true/false", m.Synced, m.SyncStale)
	}
	want := indexCounts{Tenants: 2, Networks: 2, Subnets: 1, Ports: 1, Routers: 1, TrieRows: 1}
	if m.Counts != want {
		t.Errorf("counts = %+v, want %+v", m.Counts, want)
	}
	if m.Anomalies.Total != 3 || m.Anomalies.Cycles != 1 || m.Anomalies.DanglingRoutes != 1 {
		t.Errorf("anomaly counts = %+v, want total=3 cycles=1 dangling=1", m.Anomalies)
	}
}

// TestIndex_EmptyState: a server with no accessors (Neutron disabled
// or pre-sync) renders the never-synced state with zero counts on
// both encodings.
func TestIndex_EmptyState(t *testing.T) {
	h := New(Options{}).Handler()

	rec := get(t, h, "/debug")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "never") {
		t.Errorf("empty-state body missing \"never\" badge")
	}

	rec = get(t, h, "/debug?format=json")
	var m indexModel
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m.Synced || m.Counts != (indexCounts{}) || m.Anomalies.Total != 0 {
		t.Errorf("empty state = %+v, want zeros", m)
	}
}

func TestAnomalies_JSON(t *testing.T) {
	rec := get(t, newTestServer(t).Handler(), "/debug/anomalies?format=json")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var m anomaliesModel
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m.Total != 3 {
		t.Errorf("total = %d, want 3", m.Total)
	}
	if len(m.Cycles) != 1 || m.Cycles[0].SourceTenantName != "alpha" {
		t.Errorf("cycles = %+v, want one row resolved to alpha", m.Cycles)
	}
	if len(m.Ambiguities) != 1 || len(m.Ambiguities[0].Owners) != 2 {
		t.Errorf("ambiguities = %+v, want one row with 2 owners", m.Ambiguities)
	}
}

func TestAnomalies_HTML(t *testing.T) {
	rec := get(t, newTestServer(t).Handler(), "/debug/anomalies")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	// Resolved names render; ambiguity owners pre-join names + UUIDs.
	for _, want := range []string{"alpha", "alpha (T1), beta (T2)", "10.99.0.0/16", "10.0.0.99"} {
		if !strings.Contains(body, want) {
			t.Errorf("anomalies body missing %q", want)
		}
	}
}

func TestPprofMounted(t *testing.T) {
	rec := get(t, newTestServer(t).Handler(), "/debug/pprof/")
	if rec.Code != http.StatusOK {
		t.Fatalf("pprof index status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "goroutine") {
		t.Errorf("pprof index missing profile directory")
	}
}

// TestFallback: /debug paths this package does not own delegate to
// the injected fallback (the runtime manager's config/log-level
// routes in production).
func TestFallback(t *testing.T) {
	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	h := New(Options{Fallback: fallback}).Handler()

	if rec := get(t, h, "/debug/config"); rec.Code != http.StatusTeapot {
		t.Errorf("fallback status = %d, want 418", rec.Code)
	}
	// Owned routes never reach the fallback.
	if rec := get(t, h, "/debug"); rec.Code != http.StatusOK {
		t.Errorf("index status = %d, want 200", rec.Code)
	}
}

// TestFallbackAbsent: without a fallback, unknown /debug paths 404
// instead of panicking.
func TestFallbackAbsent(t *testing.T) {
	if rec := get(t, New(Options{}).Handler(), "/debug/config"); rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestHumanAge(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{-3 * time.Second, "0s"},
		{47 * time.Second, "47s"},
		{3 * time.Minute, "3m"},
		{2*time.Hour + 13*time.Minute, "2h13m"},
		{3 * time.Hour, "3h"},
	}
	for _, tc := range tests {
		if got := humanAge(tc.d); got != tc.want {
			t.Errorf("humanAge(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}
