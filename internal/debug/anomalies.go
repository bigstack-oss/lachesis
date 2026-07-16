package debug

import (
	"net/http"
	"strings"

	"github.com/bigstack-oss/lachesis/internal/neutron"
)

var anomaliesTemplate = parsePage("anomalies.html")

// handleAnomalies renders /debug/anomalies: every health issue from
// the last detection pass, flattened to per-class tables. This page
// is the drill-down behind the lachesis_neutron_anomalies gauge —
// the gauge says "3 cycles", this page says which routers.
func (s *Server) handleAnomalies(w http.ResponseWriter, r *http.Request) {
	model := buildAnomaliesModel(s.opts.Anomalies(), s.opts.Snapshot())
	render(w, r, anomaliesTemplate, model)
}

// buildAnomaliesModel flattens the six anomaly classes to display
// rows, resolving tenant UUIDs to Keystone names where the snapshot
// knows them. nil anomalies (never synced) renders all-empty.
func buildAnomaliesModel(a *neutron.Anomalies, snap *neutron.Snapshot) anomaliesModel {
	var m anomaliesModel
	if a == nil {
		return m
	}
	m.Total = a.Total()
	for _, h := range a.Cycles {
		m.Cycles = append(m.Cycles, cycleRow{
			SourceTenant:     h.SourceTenant,
			SourceTenantName: projectName(snap, h.SourceTenant),
			SourceRouter:     h.SourceRouter,
			Destination:      h.Destination.String(),
			LoopRouter:       h.LoopRouter,
		})
	}
	for _, h := range a.Ambiguities {
		m.Ambiguities = append(m.Ambiguities, ambiguityRow{
			SourceTenant:     h.SourceTenant,
			SourceTenantName: projectName(snap, h.SourceTenant),
			RouterID:         h.RouterID,
			Destination:      h.Destination.String(),
			Owners:           h.Owners,
			OwnersDisplay:    ownersDisplay(h.Owners, snap),
		})
	}
	for _, h := range a.DanglingRoutes {
		m.DanglingRoutes = append(m.DanglingRoutes, danglingRow{
			SourceTenant:     h.SourceTenant,
			SourceTenantName: projectName(snap, h.SourceTenant),
			SourceRouter:     h.SourceRouter,
			Destination:      h.Destination,
			Nexthop:          h.Nexthop,
		})
	}
	for _, h := range a.ZeroTrieTenants {
		m.ZeroTrieTenants = append(m.ZeroTrieTenants, zeroTrieRow{
			TenantID:   h.TenantID,
			TenantName: projectName(snap, h.TenantID),
			Networks:   h.Networks,
			Routers:    h.Routers,
			Ports:      h.Ports,
		})
	}
	for _, h := range a.DuplicateRouterMACs {
		m.DuplicateRouterMACs = append(m.DuplicateRouterMACs, dupMACRow{
			MAC:            h.MAC,
			PortIDs:        h.PortIDs,
			RouterIDs:      h.RouterIDs,
			PortsDisplay:   strings.Join(h.PortIDs, ", "),
			RoutersDisplay: strings.Join(h.RouterIDs, ", "),
		})
	}
	for _, h := range a.MultiExternalPaths {
		m.MultiExternalPaths = append(m.MultiExternalPaths, multiExternalPathRow{
			PortID:            h.PortID,
			ServerID:          h.ServerID,
			ProjectID:         h.ProjectID,
			TenantName:        projectName(snap, h.ProjectID),
			Candidates:        h.Candidates,
			Picked:            h.Picked,
			CandidatesDisplay: strings.Join(h.Candidates, ", "),
		})
	}
	return m
}

// projectName resolves id via the snapshot's Keystone project list;
// "" when the snapshot is nil or doesn't know the project (the
// templates fall back to rendering the bare UUID).
func projectName(snap *neutron.Snapshot, id string) string {
	if snap == nil {
		return ""
	}
	return snap.ProjectName(id)
}

// ownersDisplay formats AmbiguityHit.Owners with resolved names
// where available. "T2, T3" is unreadable; "proj-alpha (T2),
// proj-beta (T3)" is what an operator scanning anomalies wants.
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
