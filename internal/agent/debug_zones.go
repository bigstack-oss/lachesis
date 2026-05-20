package agent

import (
	"html/template"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/neutron"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/web"
)

// zonesPage is the template data for the /debug/zones HTML view.
type zonesPage struct {
	LastSync time.Time
	Tenants  []tenantOption // dropdown entries — name + raw ID for filtering
	Rows     []zoneRow
}

// tenantOption is one entry in the tenant filter dropdown. ID is the
// raw TenantID used by the JS row filter; Label is the human-readable
// string shown to the operator ("acme-prod (abc12345)" or "(global)").
type tenantOption struct {
	ID    string
	Label string
}

// zoneRow is one (tenant, prefix, zone) line in the zones table.
// The Zone field is the typed ZoneCode so html/template renders it
// via [bpf.ZoneCode.String] — the single source of truth for the
// human-readable name.
type zoneRow struct {
	Tenant     string // raw TenantID — empty string for global / sentinel rows
	TenantName string // resolved project name; empty if unresolved or global
	Prefix     string
	Zone       bpf.ZoneCode
}

var zonesTemplate = template.Must(template.New("zones.html").
	ParseFS(web.Templates, "templates/zones.html"))

// handleDebugZones renders the per-tenant subnet-to-zone table. Reads
// the trie row set atomically from the Agent; an empty/nil set renders
// the not-yet-synced state.
func (a *Agent) handleDebugZones(w http.ResponseWriter, r *http.Request) {
	page := buildZonesPage(a.TrieEntries(), a.NeutronSnapshot(), a.lastNeutronSyncTime())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := zonesTemplate.Execute(w, page); err != nil {
		// Headers are already on the wire; we can't change status.
		// Surface the failure so an operator who notices a half-rendered
		// page can find the cause.
		slog.Error("render /debug/zones failed", "component", "debug", "err", err)
	}
}

// buildZonesPage shapes the raw trie row slice into the template's
// view model: sorted unique-tenant list (with resolved project
// names) for the dropdown, plus a row per entry. Zone values keep
// their typed [bpf.ZoneCode] form so the template's Stringer call is
// the single conversion point. snap may be nil — in that case
// project names resolve to the raw UUID.
func buildZonesPage(entries []neutron.TrieEntry, snap *neutron.Snapshot, lastSync time.Time) zonesPage {
	page := zonesPage{LastSync: lastSync}
	if len(entries) == 0 {
		return page
	}
	seen := make(map[string]struct{}, 8)
	page.Rows = make([]zoneRow, 0, len(entries))
	for _, e := range entries {
		page.Rows = append(page.Rows, zoneRow{
			Tenant:     e.TenantID,
			TenantName: tenantDisplay(e.TenantID, snap),
			Prefix:     e.Prefix.String(),
			Zone:       e.Zone,
		})
		seen[e.TenantID] = struct{}{}
	}
	ids := make([]string, 0, len(seen))
	for t := range seen {
		ids = append(ids, t)
	}
	sort.Strings(ids)
	page.Tenants = make([]tenantOption, len(ids))
	for i, id := range ids {
		page.Tenants[i] = tenantOption{ID: id, Label: tenantLabel(id, snap)}
	}
	return page
}

// tenantDisplay is the per-row display name: the project name when
// snap can resolve id, otherwise the bare id. Empty id → "(global)".
func tenantDisplay(id string, snap *neutron.Snapshot) string {
	if id == "" {
		return "(global)"
	}
	if snap == nil {
		return id
	}
	if name := snap.ProjectName(id); name != id {
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
	if snap == nil {
		return short
	}
	name := snap.ProjectName(id)
	if name == id {
		return short
	}
	return name + " (" + short + ")"
}
