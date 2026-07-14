package debug

import (
	"net/http"
	"sort"
	"time"

	"github.com/bigstack-oss/lachesis/internal/neutron"
)

var zonesTemplate = parsePage("zones.html")

// handleZones renders the per-tenant subnet-to-zone table — the
// userspace mirror of the kernel `subnet_zone_trie`. An empty/nil
// row set renders the not-yet-synced state.
func (s *Server) handleZones(w http.ResponseWriter, r *http.Request) {
	model := buildZonesModel(s.opts.Trie(), s.opts.Snapshot(), s.opts.LastSync())
	render(w, r, zonesTemplate, model)
}

// buildZonesModel shapes the raw trie row slice into the view model:
// sorted unique-tenant list (with resolved project names) for the
// dropdown, plus a row per entry. snap may be nil — project names
// then fall back to the raw UUID.
func buildZonesModel(entries []neutron.TrieEntry, snap *neutron.Snapshot, lastSync time.Time) zonesModel {
	model := zonesModel{LastSync: lastSync, Synced: !lastSync.IsZero()}
	if len(entries) == 0 {
		return model
	}
	seen := make(map[string]struct{}, 8)
	model.Rows = make([]zoneRow, 0, len(entries))
	for _, e := range entries {
		model.Rows = append(model.Rows, zoneRow{
			Tenant:     e.TenantID,
			TenantName: tenantDisplay(e.TenantID, snap),
			Prefix:     e.Prefix.String(),
			Zone:       e.Zone.String(),
		})
		seen[e.TenantID] = struct{}{}
	}
	ids := make([]string, 0, len(seen))
	for t := range seen {
		ids = append(ids, t)
	}
	sort.Strings(ids)
	model.Tenants = make([]tenantOption, len(ids))
	for i, id := range ids {
		model.Tenants[i] = tenantOption{ID: id, Label: tenantLabel(id, snap)}
	}
	return model
}

// tenantDisplay is the per-row display name: the project name when
// snap can resolve id, otherwise the bare id. Empty id → "(global)".
func tenantDisplay(id string, snap *neutron.Snapshot) string {
	if id == "" {
		return "(global)"
	}
	if name := projectName(snap, id); name != "" {
		return name
	}
	return id
}

// tenantLabel is the dropdown-option label: "name (id-prefix…)" when
// the name resolves, "(global)" for the sentinel, otherwise the raw
// id-prefix to keep the dropdown scannable.
func tenantLabel(id string, snap *neutron.Snapshot) string {
	if id == "" {
		return "(global)"
	}
	short := id
	if len(short) > 8 {
		short = short[:8] + "…"
	}
	name := projectName(snap, id)
	if name == "" {
		return short
	}
	return name + " (" + short + ")"
}
