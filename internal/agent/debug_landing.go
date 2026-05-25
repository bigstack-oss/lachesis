package agent

import (
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/neutron"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/web"
)

// landingPage is the template data for /debug — the landing
// dashboard with health counts, anomaly tables, and the lookup
// form. All five anomaly classes are pre-flattened to row structs
// so the template iterates without calling methods on package
// types.
type landingPage struct {
	LastSync    time.Time
	SyncAgeText string
	SyncStale   bool

	Counts landingCounts

	CycleRows     []landingCycleRow
	AmbiguityRows []landingAmbiguityRow
	DanglingRows  []landingDanglingRow
	ZeroTrieRows  []landingZeroTrieRow
	DupMACRows    []landingDupMACRow

	// Lookup form state. LookupQuery pre-fills the form inputs;
	// LookupResult or LookupError populates the inline result
	// section. Both pointer-typed so the template's `{{ if }}`
	// guards work without coupling to zero-value semantics.
	LookupQuery  lookupQuery
	LookupResult *lookupResult
	LookupError  string
}

type landingCounts struct {
	Tenants   int
	Networks  int
	Subnets   int
	Ports     int
	Routers   int
	TrieRows  int
	Anomalies int
}

type landingCycleRow struct {
	SourceTenant     string
	SourceTenantName string
	SourceRouter     string
	Destination      string
	LoopRouter       string
}

type landingAmbiguityRow struct {
	SourceTenant     string
	SourceTenantName string
	RouterID         string
	Destination      string
	OwnersDisplay    string
}

type landingDanglingRow struct {
	SourceTenant     string
	SourceTenantName string
	SourceRouter     string
	Destination      string
	Nexthop          string
}

type landingZeroTrieRow struct {
	TenantID   string
	TenantName string
	Networks   int
	Routers    int
	Ports      int
}

type landingDupMACRow struct {
	MAC            string
	PortsDisplay   string
	RoutersDisplay string
}

// syncStaleThreshold is the age above which the landing page
// renders the sync badge in the warn (red) style. Picked at 5×
// the typical Kafka resync cadence so a healthy cluster never
// shows warn during quiet periods, but a broken updater surfaces
// within a couple of minutes.
const syncStaleThreshold = 5 * time.Minute

var landingTemplate = template.Must(template.New("landing.html").
	ParseFS(web.Templates, "templates/landing.html"))

// handleDebugLanding renders /debug. Query params drive the
// optional lookup section: ?ip=<addr>[&tenant=<uuid>] or ?mac=<addr>.
// Validation errors render inline (no HTTP 4xx) — the operator is
// already on the page and wants the error next to the form.
func (a *Agent) handleDebugLanding(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ip := strings.TrimSpace(q.Get("ip"))
	mac := strings.TrimSpace(q.Get("mac"))
	tenant := strings.TrimSpace(q.Get("tenant"))

	page := buildLandingPage(a, time.Now())
	if ip != "" || mac != "" {
		page.LookupQuery = lookupQuery{IP: ip, MAC: mac, Tenant: tenant}
		result, errMsg := a.runLookup(ip, mac, tenant)
		if errMsg != "" {
			page.LookupError = errMsg
		} else {
			page.LookupResult = &result
			// runLookup canonicalised the MAC; mirror that back
			// into the form's echo so the user sees what matched.
			page.LookupQuery.MAC = result.Query.MAC
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := landingTemplate.Execute(w, page); err != nil {
		slog.Error("render /debug failed", "component", "debug", "err", err)
	}
}

// buildLandingPage assembles the page data from the agent's
// current state. now is injected so tests can pin a deterministic
// SyncAgeText without freezing real time.
func buildLandingPage(a *Agent, now time.Time) landingPage {
	snap := a.NeutronSnapshot()
	trie := a.TrieEntries()
	anomalies := a.Anomalies()
	last := a.lastNeutronSyncTime()

	page := landingPage{LastSync: last}
	if !last.IsZero() {
		age := now.Sub(last)
		page.SyncAgeText = humanAge(age) + " ago"
		page.SyncStale = age > syncStaleThreshold
	}

	page.Counts = countsFrom(snap, trie, anomalies)
	if anomalies != nil {
		page.CycleRows = flattenCycles(anomalies.Cycles, snap)
		page.AmbiguityRows = flattenAmbiguities(anomalies.Ambiguities, snap)
		page.DanglingRows = flattenDangling(anomalies.DanglingRoutes, snap)
		page.ZeroTrieRows = flattenZeroTrie(anomalies.ZeroTrieTenants, snap)
		page.DupMACRows = flattenDupMACs(anomalies.DuplicateRouterMACs)
	}
	return page
}

// countsFrom aggregates the snapshot + trie + anomaly counts the
// health strip renders. nil inputs render as zeros — pre-sync the
// page should still load and show "0 / never".
func countsFrom(snap *neutron.Snapshot, trie []neutron.TrieEntry, anomalies *neutron.Anomalies) landingCounts {
	var c landingCounts
	if snap != nil {
		c.Networks = len(snap.Networks)
		c.Subnets = len(snap.Subnets)
		c.Ports = len(snap.Ports)
		c.Routers = len(snap.Routers)
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
		c.Tenants = len(tenants)
	}
	c.TrieRows = len(trie)
	if anomalies != nil {
		c.Anomalies = anomalies.Total()
	}
	return c
}

func flattenCycles(in []neutron.CycleHit, snap *neutron.Snapshot) []landingCycleRow {
	if len(in) == 0 {
		return nil
	}
	out := make([]landingCycleRow, 0, len(in))
	for _, h := range in {
		out = append(out, landingCycleRow{
			SourceTenant:     h.SourceTenant,
			SourceTenantName: projectName(snap, h.SourceTenant),
			SourceRouter:     h.SourceRouter,
			Destination:      h.Destination.String(),
			LoopRouter:       h.LoopRouter,
		})
	}
	return out
}

func flattenAmbiguities(in []neutron.AmbiguityHit, snap *neutron.Snapshot) []landingAmbiguityRow {
	if len(in) == 0 {
		return nil
	}
	out := make([]landingAmbiguityRow, 0, len(in))
	for _, h := range in {
		out = append(out, landingAmbiguityRow{
			SourceTenant:     h.SourceTenant,
			SourceTenantName: projectName(snap, h.SourceTenant),
			RouterID:         h.RouterID,
			Destination:      h.Destination.String(),
			OwnersDisplay:    ownersDisplay(h.Owners, snap),
		})
	}
	return out
}

func flattenDangling(in []neutron.DanglingRoute, snap *neutron.Snapshot) []landingDanglingRow {
	if len(in) == 0 {
		return nil
	}
	out := make([]landingDanglingRow, 0, len(in))
	for _, h := range in {
		out = append(out, landingDanglingRow{
			SourceTenant:     h.SourceTenant,
			SourceTenantName: projectName(snap, h.SourceTenant),
			SourceRouter:     h.SourceRouter,
			Destination:      h.Destination,
			Nexthop:          h.Nexthop,
		})
	}
	return out
}

func flattenZeroTrie(in []neutron.ZeroTrieTenant, snap *neutron.Snapshot) []landingZeroTrieRow {
	if len(in) == 0 {
		return nil
	}
	out := make([]landingZeroTrieRow, 0, len(in))
	for _, h := range in {
		out = append(out, landingZeroTrieRow{
			TenantID:   h.TenantID,
			TenantName: projectName(snap, h.TenantID),
			Networks:   h.Networks,
			Routers:    h.Routers,
			Ports:      h.Ports,
		})
	}
	return out
}

func flattenDupMACs(in []neutron.DuplicateRouterMAC) []landingDupMACRow {
	if len(in) == 0 {
		return nil
	}
	out := make([]landingDupMACRow, 0, len(in))
	for _, h := range in {
		out = append(out, landingDupMACRow{
			MAC:            h.MAC,
			PortsDisplay:   strings.Join(h.PortIDs, ", "),
			RoutersDisplay: strings.Join(h.RouterIDs, ", "),
		})
	}
	return out
}

// ownersDisplay formats AmbiguityHit.Owners with resolved names
// where available. "T2, T3" is unreadable; "proj-alpha (T2), proj-beta (T3)"
// is what an operator scanning anomalies actually wants.
func ownersDisplay(ids []string, snap *neutron.Snapshot) string {
	if len(ids) == 0 {
		return ""
	}
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		if name := projectName(snap, id); name != "" {
			parts = append(parts, name+" ("+id+")")
		} else {
			parts = append(parts, id)
		}
	}
	return strings.Join(parts, ", ")
}

// humanAge formats a duration as a short, fixed-width string.
// "47s", "3m", "2h13m". Days roll up into hours — the landing
// page expects sync ages in minutes-to-hours, not days. A days-
// old sync is broken, not stale.
func humanAge(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	h := int(d / time.Hour)
	m := int((d % time.Hour) / time.Minute)
	if m == 0 {
		return fmt.Sprintf("%dh", h)
	}
	return fmt.Sprintf("%dh%dm", h, m)
}
