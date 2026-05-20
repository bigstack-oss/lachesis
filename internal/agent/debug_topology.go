package agent

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/neutron"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/web"
)

// topologyDirectoryPage is the template data for /debug/topology —
// the per-tenant directory table. The page deliberately omits any
// graph: at dev-cmp scale (36 tenants, 130+ networks) a global
// canvas is unreadable. Operators drill into a tenant via the
// linked detail view.
type topologyDirectoryPage struct {
	LastSync time.Time
	Rows     []directoryRow
}

// directoryRow summarises one tenant's footprint plus its
// cross-tenant edge counts. CrossTotal is the default sort key
// (descending) so hubs surface first.
type directoryRow struct {
	TenantID   string
	TenantName string
	Networks   int
	Routers    int
	OutAttach  int // my routers attach to other tenants' networks
	InAttach   int // other tenants' routers attach to my networks
	OutExtra   int // my routers extraroute via other tenants' routers
	InExtra    int // other tenants' routers extraroute via my routers
	CrossTotal int // sum of the four cross-tenant counts
}

// topologyTenantPage is the template data for /debug/topology/{tenant}.
// Text-first layout: tables for networks / routers / extraroutes,
// plus a small focused graph at the top that shows only cross-tenant
// attachments and extraroutes (the relationships where a spatial
// visualisation actually pays off). Internal gateway edges live in
// the tables; they would dominate the graph otherwise — admin's
// `Public` external network is connected to ~50 routers and a graph
// of those is unreadable.
type topologyTenantPage struct {
	LastSync   time.Time
	TenantID   string
	TenantName string // resolved project name; empty if unresolved
	NotFound   bool   // true if the tenant has no Neutron resources at all
	Summary    tenantSummary

	Networks    []tenantNetworkRow
	Routers     []tenantRouterCard
	Extraroutes []extrarouteRow

	// CrossGraph holds only cross-tenant attach + extraroute edges
	// and the nodes that participate in them. Empty when the tenant
	// has no cross-tenant relationships — the template hides the
	// graph section in that case.
	CrossGraph     topologyGraph
	CrossGraphJSON template.JS
}

// tenantSummary is the counts strip rendered under the page header.
type tenantSummary struct {
	Networks       int
	Routers        int
	Attachments    int // total router_interface attachments (internal + cross)
	Extraroutes    int // total extraroutes
	CrossAttach    int // cross-tenant attachments only
	CrossExtraroute int // cross-tenant extraroutes only
}

// tenantNetworkRow is one row in the per-tenant Networks table.
type tenantNetworkRow struct {
	ID    string
	Name  string
	CIDRs []string
	Kind  string // "" (regular) / "shared" / "external"
}

// tenantRouterCard groups one router's metadata with its inline
// attachment + extraroute lists.
type tenantRouterCard struct {
	ID                  string
	ExternalGatewayID   string // empty when not set
	ExternalGatewayName string // network name when resolvable
	Attachments         []routerAttachmentRow
	Extraroutes         []routerExtrarouteRow
}

// routerAttachmentRow describes one router_interface attachment from
// a particular router's perspective. CrossTenant is true when the
// router and the network have different ProjectIDs.
type routerAttachmentRow struct {
	NetworkID         string
	NetworkName       string
	NetworkTenantID   string
	NetworkTenantName string // resolved
	IP                string
	CrossTenant       bool
}

// routerExtrarouteRow is one extraroute entry. NextRouterID is empty
// when the nexthop IP did not resolve to a known router_interface
// port (e.g. nexthop is a VM appliance or a dangling reference).
type routerExtrarouteRow struct {
	Destination          string
	Nexthop              string
	NextRouterID         string
	NextRouterTenantID   string
	NextRouterTenantName string
	CrossTenant          bool
}

// extrarouteRow is the flat extraroutes table at the page bottom —
// each tenant-relevant extraroute (outgoing or incoming) gets one
// row regardless of which router it belongs to.
type extrarouteRow struct {
	Direction          string // "out" (my router) or "in" (other tenant's router)
	SourceRouterID     string
	SourceTenantID     string
	SourceTenantName   string
	Destination        string
	Nexthop            string
	TargetRouterID     string
	TargetTenantID     string
	TargetTenantName   string
}

// topologyGraph is the wire format the Cytoscape client consumes.
type topologyGraph struct {
	Nodes []topologyNode `json:"nodes"`
	Edges []topologyEdge `json:"edges"`
}

// topologyNode is one Neutron network or router rendered as a graph
// vertex. Kind selects the style: "network" / "network-shared" /
// "network-external" / "router" for internal nodes,
// "network-boundary" / "router-boundary" for neighbour nodes drawn
// at the edge of the focused view.
//
// Label is the short, human-readable form rendered inside the node.
// The Name / TenantName / CIDRs fields carry the same data in
// machine-friendly form so the on-hover info panel can format
// detail (id, owner project, subnets) without re-parsing the label.
type topologyNode struct {
	ID         string   `json:"id"`
	Label      string   `json:"label"`
	Kind       string   `json:"kind"`
	Tenant     string   `json:"tenant"`
	Name       string   `json:"name,omitempty"`       // operator-assigned name, empty if none
	TenantName string   `json:"tenantName,omitempty"` // resolved project name; empty if unresolved
	CIDRs      []string `json:"cidrs,omitempty"`      // subnet CIDRs (networks only)
}

// topologyEdge is one (source, target) line. Kind is one of "attach",
// "gateway", "extraroute" — same vocabulary as the previous global
// view. Edges that cross the tenant boundary get the same style as
// internal ones; the boundary marker lives on the neighbour node.
type topologyEdge struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	Target string `json:"target"`
	Kind   string `json:"kind"`
	Label  string `json:"label"`
}

var (
	topologyDirectoryTemplate = template.Must(template.New("topology_directory.html").
		ParseFS(web.Templates, "templates/topology_directory.html"))

	topologyTenantTemplate = template.Must(template.New("topology_tenant.html").
		ParseFS(web.Templates, "templates/topology_tenant.html"))
)

// handleDebugTopology renders the tenant directory — the entry point
// when an operator opens /debug/topology. Each row links to a focused
// per-tenant graph view that stays readable at production scale.
func (a *Agent) handleDebugTopology(w http.ResponseWriter, r *http.Request) {
	page := buildTopologyDirectoryPage(a.NeutronSnapshot(), a.lastNeutronSyncTime())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := topologyDirectoryTemplate.Execute(w, page); err != nil {
		slog.Error("render /debug/topology failed", "component", "debug", "err", err)
	}
}

// handleDebugTopologyTenant renders the focused per-tenant graph,
// including boundary nodes for any neighbour-tenant resources
// connected via cross-tenant attachments or resolved extraroutes.
// The tenant id is taken from the URL path; unknown tenants render
// an empty-state page rather than 404 so an operator who pastes an
// ID into the URL still gets a clear "no resources" answer.
func (a *Agent) handleDebugTopologyTenant(w http.ResponseWriter, r *http.Request) {
	tenant := r.PathValue("tenant")
	page, err := buildTopologyTenantPage(a.NeutronSnapshot(), tenant, a.lastNeutronSyncTime())
	if err != nil {
		slog.Error("build /debug/topology/{tenant} failed", "component", "debug", "tenant", tenant, "err", err)
		http.Error(w, "topology render failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := topologyTenantTemplate.Execute(w, page); err != nil {
		slog.Error("render /debug/topology/{tenant} failed", "component", "debug", "tenant", tenant, "err", err)
	}
}

// buildTopologyDirectoryPage counts per-tenant resources and
// cross-tenant edges so the directory can sort by activity. The
// classification mirrors the per-tenant view: an edge is
// cross-tenant when its two endpoints have different ProjectIDs.
func buildTopologyDirectoryPage(snap *neutron.Snapshot, lastSync time.Time) topologyDirectoryPage {
	page := topologyDirectoryPage{LastSync: lastSync}
	if snap == nil {
		return page
	}

	networkByID := indexNetworks(snap)
	routerByID := indexRouters(snap)
	portByIP := indexPortsByIP(snap)

	type stats struct {
		networks, routers                              int
		outAttach, inAttach, outExtra, inExtra         int
	}
	perTenant := map[string]*stats{}
	get := func(t string) *stats {
		s, ok := perTenant[t]
		if !ok {
			s = &stats{}
			perTenant[t] = s
		}
		return s
	}

	for _, n := range snap.Networks {
		get(n.ProjectID).networks++
	}
	for _, r := range snap.Routers {
		get(r.ProjectID).routers++
	}

	// Cross-tenant attachments: router_interface ports where the
	// router's tenant differs from the network's tenant.
	for _, p := range snap.Ports {
		if p.DeviceOwner != "network:router_interface" {
			continue
		}
		router, rok := routerByID[p.DeviceID]
		network, nok := networkByID[p.NetworkID]
		if !rok || !nok || router.ProjectID == network.ProjectID {
			continue
		}
		get(router.ProjectID).outAttach++
		get(network.ProjectID).inAttach++
	}

	// Cross-tenant extraroutes: the nexthop IP resolves to a router
	// owned by a different tenant.
	for _, r := range snap.Routers {
		for _, route := range r.Routes {
			np, ok := portByIP[route.Nexthop]
			if !ok || np.DeviceOwner != "network:router_interface" {
				continue
			}
			next, ok := routerByID[np.DeviceID]
			if !ok || r.ProjectID == next.ProjectID {
				continue
			}
			get(r.ProjectID).outExtra++
			get(next.ProjectID).inExtra++
		}
	}

	for tid, s := range perTenant {
		page.Rows = append(page.Rows, directoryRow{
			TenantID:   tid,
			TenantName: tenantDisplay(tid, snap),
			Networks:   s.networks,
			Routers:    s.routers,
			OutAttach:  s.outAttach,
			InAttach:   s.inAttach,
			OutExtra:   s.outExtra,
			InExtra:    s.inExtra,
			CrossTotal: s.outAttach + s.inAttach + s.outExtra + s.inExtra,
		})
	}
	sort.Slice(page.Rows, func(i, j int) bool {
		if page.Rows[i].CrossTotal != page.Rows[j].CrossTotal {
			return page.Rows[i].CrossTotal > page.Rows[j].CrossTotal
		}
		return page.Rows[i].TenantName < page.Rows[j].TenantName
	})
	return page
}

// buildTopologyTenantPage assembles the text-first per-tenant view.
// Tables carry the bulk of the data (networks, routers + their
// attachments + their extraroutes, flat extraroute list). The
// small Cytoscape graph at the top includes only cross-tenant
// attach + extraroute edges plus the resources they touch — a focused
// "where do I connect to other tenants" view. Internal gateway edges
// are recorded in tables; rendering all of them would re-create the
// admin starburst we just walked away from.
func buildTopologyTenantPage(snap *neutron.Snapshot, tenant string, lastSync time.Time) (topologyTenantPage, error) {
	page := topologyTenantPage{LastSync: lastSync, TenantID: tenant}
	if snap == nil {
		page.NotFound = true
		return page, nil
	}
	if name := snap.ProjectName(tenant); name != tenant {
		page.TenantName = name
	}

	networkByID := indexNetworks(snap)
	routerByID := indexRouters(snap)
	portByIP := indexPortsByIP(snap)
	subnetsByNet := indexSubnetsByNetwork(snap)

	// --- Networks table (owned by this tenant) ---
	for _, n := range snap.Networks {
		if n.ProjectID != tenant {
			continue
		}
		row := tenantNetworkRow{
			ID:    n.ID,
			Name:  n.Name,
			CIDRs: append([]string(nil), subnetsByNet[n.ID]...),
		}
		if row.Name == "" {
			row.Name = n.ID
		}
		switch {
		case n.IsExternal:
			row.Kind = "external"
		case n.Shared:
			row.Kind = "shared"
		}
		page.Networks = append(page.Networks, row)
	}
	sort.Slice(page.Networks, func(i, j int) bool { return page.Networks[i].Name < page.Networks[j].Name })

	// --- Router cards (owned by this tenant) ---
	// Group attachments + extraroutes per router ID so the template
	// renders one card per router.
	routerCards := map[string]*tenantRouterCard{}
	for _, r := range snap.Routers {
		if r.ProjectID != tenant {
			continue
		}
		card := &tenantRouterCard{ID: r.ID}
		if r.ExternalNetworkID != "" {
			card.ExternalGatewayID = r.ExternalNetworkID
			if ext, ok := networkByID[r.ExternalNetworkID]; ok && ext.Name != "" {
				card.ExternalGatewayName = ext.Name
			}
		}
		routerCards[r.ID] = card
	}

	// Walk router_interface ports to populate attachments. Track
	// summary counts as we go.
	for _, p := range snap.Ports {
		if p.DeviceOwner != "network:router_interface" {
			continue
		}
		router, rok := routerByID[p.DeviceID]
		network, nok := networkByID[p.NetworkID]
		if !rok || !nok {
			continue
		}
		// Relevant when router or network belongs to this tenant.
		if router.ProjectID != tenant && network.ProjectID != tenant {
			continue
		}
		cross := router.ProjectID != network.ProjectID
		if cross {
			page.Summary.CrossAttach++
		}
		page.Summary.Attachments++

		// If the router is ours, add the attachment row to its card.
		if router.ProjectID == tenant {
			card := routerCards[router.ID]
			if card == nil {
				continue
			}
			ip := ""
			if len(p.FixedIPs) > 0 {
				ip = p.FixedIPs[0].IPAddress
			}
			row := routerAttachmentRow{
				NetworkID:         network.ID,
				NetworkName:       displayName(network.Name, network.ID),
				NetworkTenantID:   network.ProjectID,
				NetworkTenantName: snap.ProjectName(network.ProjectID),
				IP:                ip,
				CrossTenant:       cross,
			}
			card.Attachments = append(card.Attachments, row)
		}
	}

	// Walk routers' extraroutes to populate per-card extraroute lists
	// plus the flat page-level extraroute table.
	for _, r := range snap.Routers {
		for _, route := range r.Routes {
			np, ok := portByIP[route.Nexthop]
			var nextRouter neutron.Router
			var resolved bool
			if ok && np.DeviceOwner == "network:router_interface" {
				nextRouter, resolved = routerByID[np.DeviceID]
			}

			involves := r.ProjectID == tenant || (resolved && nextRouter.ProjectID == tenant)
			if !involves {
				continue
			}

			cross := resolved && r.ProjectID != nextRouter.ProjectID
			if cross {
				page.Summary.CrossExtraroute++
			}
			page.Summary.Extraroutes++

			// Per-router card line, only on the source router's card
			// when the source router belongs to this tenant.
			if r.ProjectID == tenant {
				card := routerCards[r.ID]
				if card != nil {
					line := routerExtrarouteRow{
						Destination: route.Destination,
						Nexthop:     route.Nexthop,
						CrossTenant: cross,
					}
					if resolved {
						line.NextRouterID = nextRouter.ID
						line.NextRouterTenantID = nextRouter.ProjectID
						line.NextRouterTenantName = snap.ProjectName(nextRouter.ProjectID)
					}
					card.Extraroutes = append(card.Extraroutes, line)
				}
			}

			// Flat extraroute table — only the cross-tenant entries
			// belong here. Internal extraroutes show up under their
			// router's card; replicating them in the flat table
			// is noise.
			if cross {
				row := extrarouteRow{
					SourceRouterID:   r.ID,
					SourceTenantID:   r.ProjectID,
					SourceTenantName: snap.ProjectName(r.ProjectID),
					Destination:      route.Destination,
					Nexthop:          route.Nexthop,
					TargetRouterID:   nextRouter.ID,
					TargetTenantID:   nextRouter.ProjectID,
					TargetTenantName: snap.ProjectName(nextRouter.ProjectID),
				}
				if r.ProjectID == tenant {
					row.Direction = "out"
				} else {
					row.Direction = "in"
				}
				page.Extraroutes = append(page.Extraroutes, row)
			}
		}
	}

	// Sort: outgoing first, then by source router id for stability.
	sort.Slice(page.Extraroutes, func(i, j int) bool {
		if page.Extraroutes[i].Direction != page.Extraroutes[j].Direction {
			return page.Extraroutes[i].Direction == "out"
		}
		return page.Extraroutes[i].SourceRouterID < page.Extraroutes[j].SourceRouterID
	})

	// Order router cards: cards with cross-tenant relationships first
	// (operators usually want to inspect those), then alphabetically.
	cards := make([]tenantRouterCard, 0, len(routerCards))
	for _, c := range routerCards {
		cards = append(cards, *c)
	}
	sort.Slice(cards, func(i, j int) bool {
		ci := cardCrossCount(cards[i])
		cj := cardCrossCount(cards[j])
		if ci != cj {
			return ci > cj
		}
		return cards[i].ID < cards[j].ID
	})
	page.Routers = cards

	page.Summary.Networks = len(page.Networks)
	page.Summary.Routers = len(page.Routers)

	// --- Cross-tenant focused graph ---
	// Only attach + extraroute cross-tenant edges. Gateway edges to
	// shared external networks form the hub-and-spoke we want to
	// avoid visualising.
	buildCrossGraph(snap, tenant, networkByID, routerByID, portByIP, subnetsByNet, &page)

	// If nothing belongs to this tenant at all, render not-found.
	if page.Summary.Networks == 0 && page.Summary.Routers == 0 &&
		page.Summary.CrossAttach == 0 && page.Summary.CrossExtraroute == 0 {
		page.NotFound = true
		return page, nil
	}

	if len(page.CrossGraph.Nodes) > 0 {
		b, err := json.Marshal(page.CrossGraph)
		if err != nil {
			return page, fmt.Errorf("marshal cross-graph: %w", err)
		}
		page.CrossGraphJSON = template.JS(b)
	}
	return page, nil
}

// buildCrossGraph populates page.CrossGraph with only the
// cross-tenant attach and extraroute relationships. Endpoints that
// belong to this tenant render as full nodes; the other-tenant
// endpoints render as boundary nodes (dashed). Gateway edges are
// intentionally excluded — they form a hub-and-spoke that would
// dominate the graph at any tenant owning a popular external network.
func buildCrossGraph(snap *neutron.Snapshot, tenant string,
	networkByID map[string]neutron.Network,
	routerByID map[string]neutron.Router,
	portByIP map[string]neutron.Port,
	subnetsByNet map[string][]string,
	page *topologyTenantPage) {

	added := map[string]bool{}
	addNode := func(node topologyNode) {
		if added[node.ID] {
			return
		}
		added[node.ID] = true
		page.CrossGraph.Nodes = append(page.CrossGraph.Nodes, node)
	}
	addNetwork := func(n neutron.Network, boundary bool) {
		kind := networkKind(n)
		if boundary {
			kind = "network-boundary"
		}
		addNode(topologyNode{
			ID:         n.ID,
			Label:      displayName(n.Name, n.ID),
			Kind:       kind,
			Tenant:     n.ProjectID,
			Name:       n.Name,
			TenantName: snap.ProjectName(n.ProjectID),
			CIDRs:      subnetsByNet[n.ID],
		})
	}
	addRouter := func(r neutron.Router, boundary bool) {
		kind := "router"
		if boundary {
			kind = "router-boundary"
		}
		addNode(topologyNode{
			ID:         r.ID,
			Label:      displayName(r.Name, r.ID),
			Kind:       kind,
			Tenant:     r.ProjectID,
			Name:       r.Name,
			TenantName: snap.ProjectName(r.ProjectID),
		})
	}

	seq := 0
	addEdge := func(src, tgt, kind, label string) {
		seq++
		page.CrossGraph.Edges = append(page.CrossGraph.Edges, topologyEdge{
			ID: fmt.Sprintf("e%d", seq), Source: src, Target: tgt, Kind: kind, Label: label,
		})
	}

	// Cross-tenant attach edges (router T → network T', T != T').
	for _, p := range snap.Ports {
		if p.DeviceOwner != "network:router_interface" {
			continue
		}
		router, rok := routerByID[p.DeviceID]
		network, nok := networkByID[p.NetworkID]
		if !rok || !nok || router.ProjectID == network.ProjectID {
			continue
		}
		if router.ProjectID != tenant && network.ProjectID != tenant {
			continue
		}
		addRouter(router, router.ProjectID != tenant)
		addNetwork(network, network.ProjectID != tenant)
		ip := ""
		if len(p.FixedIPs) > 0 {
			ip = p.FixedIPs[0].IPAddress
		}
		addEdge(router.ID, network.ID, "attach", ip)
	}

	// Cross-tenant extraroute edges (router T extraroutes via router T').
	for _, r := range snap.Routers {
		for _, route := range r.Routes {
			np, ok := portByIP[route.Nexthop]
			if !ok || np.DeviceOwner != "network:router_interface" {
				continue
			}
			next, ok := routerByID[np.DeviceID]
			if !ok || r.ProjectID == next.ProjectID {
				continue
			}
			if r.ProjectID != tenant && next.ProjectID != tenant {
				continue
			}
			addRouter(r, r.ProjectID != tenant)
			addRouter(next, next.ProjectID != tenant)
			addEdge(r.ID, next.ID, "extraroute",
				fmt.Sprintf("%s via %s", route.Destination, route.Nexthop))
		}
	}
}

// cardCrossCount returns how many cross-tenant relationships a
// router card carries. Used to sort cards so the cross-tenant ones
// surface first.
func cardCrossCount(c tenantRouterCard) int {
	n := 0
	for _, a := range c.Attachments {
		if a.CrossTenant {
			n++
		}
	}
	for _, e := range c.Extraroutes {
		if e.CrossTenant {
			n++
		}
	}
	return n
}

// displayName returns name when non-empty, otherwise id (or its
// first 8 chars when long). Centralised so all builders agree on
// the fallback rule.
func displayName(name, id string) string {
	if name != "" {
		return name
	}
	if len(id) > 8 {
		return id[:8] + "…"
	}
	return id
}

// --- shared helpers ---

func indexNetworks(snap *neutron.Snapshot) map[string]neutron.Network {
	m := make(map[string]neutron.Network, len(snap.Networks))
	for _, n := range snap.Networks {
		m[n.ID] = n
	}
	return m
}

func indexRouters(snap *neutron.Snapshot) map[string]neutron.Router {
	m := make(map[string]neutron.Router, len(snap.Routers))
	for _, r := range snap.Routers {
		m[r.ID] = r
	}
	return m
}

func indexPortsByIP(snap *neutron.Snapshot) map[string]neutron.Port {
	m := make(map[string]neutron.Port, len(snap.Ports))
	for _, p := range snap.Ports {
		for _, fip := range p.FixedIPs {
			m[fip.IPAddress] = p
		}
	}
	return m
}

func indexSubnetsByNetwork(snap *neutron.Snapshot) map[string][]string {
	m := make(map[string][]string, len(snap.Networks))
	for _, s := range snap.Subnets {
		m[s.NetworkID] = append(m[s.NetworkID], s.CIDR)
	}
	return m
}

// networkKind maps the (Shared, IsExternal) flags to the template
// style selector. External wins over shared — operators identify a
// network by its public-vs-private status first.
func networkKind(n neutron.Network) string {
	switch {
	case n.IsExternal:
		return "network-external"
	case n.Shared:
		return "network-shared"
	}
	return "network"
}
