package debug

import (
	"net/http"
	"strings"
	"time"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/neutron"
)

var indexTemplate = parsePage("index.html")

// handleIndex renders the /debug index: sync recency, snapshot
// coverage counts, anomaly counts, and links into the detail pages.
// Query params drive the optional lookup section: ?ip=<addr>
// [&tenant=<uuid>] or ?mac=<addr>. Validation errors render inline
// (no HTTP 4xx) — the operator is already on the page and wants the
// error next to the form.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	model := buildIndexModel(
		s.opts.Snapshot(), s.opts.Trie(), s.opts.Anomalies(),
		s.opts.LastSync(), time.Now())

	q := r.URL.Query()
	ip := strings.TrimSpace(q.Get("ip"))
	mac := strings.TrimSpace(q.Get("mac"))
	tenant := strings.TrimSpace(q.Get("tenant"))
	if ip != "" || mac != "" {
		model.LookupQuery = lookupQuery{IP: ip, MAC: mac, Tenant: tenant}
		result, errMsg := s.runLookup(ip, mac, tenant)
		if errMsg != "" {
			model.LookupError = errMsg
		} else {
			model.LookupResult = &result
			// runLookup canonicalised the MAC; mirror that back
			// into the form's echo so the user sees what matched.
			model.LookupQuery.MAC = result.Query.MAC
		}
	}
	render(w, r, indexTemplate, model)
}

// buildIndexModel assembles the index view from the retained sync
// outputs. nil inputs render as zeros — pre-sync the page still
// loads and shows "0 / never". now is injected so tests can pin a
// deterministic SyncAgeText without freezing real time.
func buildIndexModel(snap *neutron.Snapshot, trie []neutron.TrieEntry,
	anomalies *neutron.Anomalies, last, now time.Time) indexModel {

	m := indexModel{LastSync: last}
	if !last.IsZero() {
		age := now.Sub(last)
		m.Synced = true
		m.SyncAgeText = humanAge(age) + " ago"
		m.SyncStale = age > syncStaleThreshold
	}
	if snap != nil {
		m.Counts.Networks = len(snap.Networks)
		m.Counts.Subnets = len(snap.Subnets)
		m.Counts.Ports = len(snap.Ports)
		m.Counts.Routers = len(snap.Routers)
		m.Counts.Tenants = countTenants(snap)
	}
	m.Counts.TrieRows = len(trie)
	if anomalies != nil {
		m.Anomalies = anomalyCounts{
			Total:               anomalies.Total(),
			Cycles:              len(anomalies.Cycles),
			Ambiguities:         len(anomalies.Ambiguities),
			DanglingRoutes:      len(anomalies.DanglingRoutes),
			ZeroTrieTenants:     len(anomalies.ZeroTrieTenants),
			DuplicateRouterMACs: len(anomalies.DuplicateRouterMACs),
		}
	}
	return m
}

// countTenants returns the number of distinct ProjectIDs owning any
// network, router, or port in the snapshot — the same owning-tenant
// notion the trie builder's collectTenants uses.
func countTenants(snap *neutron.Snapshot) int {
	tenants := make(map[string]struct{})
	for _, n := range snap.Networks {
		if n.ProjectID != "" {
			tenants[n.ProjectID] = struct{}{}
		}
	}
	for _, r := range snap.Routers {
		if r.ProjectID != "" {
			tenants[r.ProjectID] = struct{}{}
		}
	}
	for _, p := range snap.Ports {
		if p.ProjectID != "" {
			tenants[p.ProjectID] = struct{}{}
		}
	}
	return len(tenants)
}
