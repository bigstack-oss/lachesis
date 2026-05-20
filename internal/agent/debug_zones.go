package agent

import (
	"embed"
	"html/template"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/neutron"
)

//go:embed templates/*.html
var debugTemplatesFS embed.FS

// zonesPage is the template data for the /debug/zones HTML view.
type zonesPage struct {
	LastSync time.Time
	Tenants  []string // unique TenantIDs, sorted; "" sentinel sorts first
	Rows     []zoneRow
}

// zoneRow is one (tenant, prefix, zone) line in the zones table.
// The Zone field is the typed ZoneCode so html/template renders it
// via [bpf.ZoneCode.String] — the single source of truth for the
// human-readable name.
type zoneRow struct {
	Tenant string // raw TenantID — empty string for global / sentinel rows
	Prefix string
	Zone   bpf.ZoneCode
}

var zonesTemplate = template.Must(template.New("zones.html").
	Funcs(template.FuncMap{
		"tenantDisplay": func(id string) string {
			if id == "" {
				return "(global)"
			}
			return id
		},
	}).
	ParseFS(debugTemplatesFS, "templates/zones.html"))

// handleDebugZones renders the per-tenant subnet-to-zone table. Reads
// the trie row set atomically from the Agent; an empty/nil set renders
// the not-yet-synced state.
func (a *Agent) handleDebugZones(w http.ResponseWriter, r *http.Request) {
	page := buildZonesPage(a.TrieEntries(), a.lastNeutronSyncTime())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := zonesTemplate.Execute(w, page); err != nil {
		// Headers are already on the wire; we can't change status.
		// Surface the failure so an operator who notices a half-rendered
		// page can find the cause.
		slog.Error("render /debug/zones failed", "component", "debug", "err", err)
	}
}

// buildZonesPage shapes the raw trie row slice into the template's
// view model: sorted unique-tenant list for the dropdown plus a row
// per entry. Zone values keep their typed [bpf.ZoneCode] form so
// the template's Stringer call is the single conversion point.
func buildZonesPage(entries []neutron.TrieEntry, lastSync time.Time) zonesPage {
	page := zonesPage{LastSync: lastSync}
	if len(entries) == 0 {
		return page
	}
	seen := make(map[string]struct{}, 8)
	page.Rows = make([]zoneRow, 0, len(entries))
	for _, e := range entries {
		page.Rows = append(page.Rows, zoneRow{
			Tenant: e.TenantID,
			Prefix: e.Prefix.String(),
			Zone:   e.Zone,
		})
		seen[e.TenantID] = struct{}{}
	}
	page.Tenants = make([]string, 0, len(seen))
	for t := range seen {
		page.Tenants = append(page.Tenants, t)
	}
	sort.Strings(page.Tenants)
	return page
}
