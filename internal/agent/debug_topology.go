package agent

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/neutron"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/web"
)

// topologyPage is the template data for the /debug/topology HTML view.
// The graph is also marshalled to JSON for the Cytoscape script — both
// representations live on the same struct so the template renders the
// JSON literal without a second pass over the data.
type topologyPage struct {
	LastSync  time.Time
	Tenants   []string // unique tenant IDs across networks + routers, sorted
	Graph     topologyGraph
	GraphJSON template.JS
}

// topologyGraph is the wire format the Cytoscape client consumes.
// Field names are lower-case to match Cytoscape's expectations
// (it reads `data: { id, label, ... }` per element).
type topologyGraph struct {
	Nodes []topologyNode `json:"nodes"`
	Edges []topologyEdge `json:"edges"`
}

// topologyNode is one Neutron network or router rendered as a graph
// vertex. Kind is one of "network", "network-shared", "network-external",
// "router" — the template's stylesheet keys colour off this value.
type topologyNode struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Kind   string `json:"kind"`
	Tenant string `json:"tenant"`
}

// topologyEdge is one (source, target) line. Kind is "attach"
// (router → network via router_interface port), "gateway" (router →
// external network via ExternalNetworkID), or "extraroute" (router →
// router resolved via nexthop port). Label carries the IP or CIDR
// detail.
type topologyEdge struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	Target string `json:"target"`
	Kind   string `json:"kind"`
	Label  string `json:"label"`
}

var topologyTemplate = template.Must(template.New("topology.html").
	Funcs(template.FuncMap{
		"tenantDisplay": func(id string) string {
			if id == "" {
				return "(global)"
			}
			return id
		},
	}).
	ParseFS(web.Templates, "templates/topology.html"))

// handleDebugTopology renders the cross-tenant network graph from
// the retained Neutron snapshot. A nil snapshot (Neutron disabled or
// pre-cold-start) renders the empty-state page.
func (a *Agent) handleDebugTopology(w http.ResponseWriter, r *http.Request) {
	page, err := buildTopologyPage(a.NeutronSnapshot(), a.lastNeutronSyncTime())
	if err != nil {
		slog.Error("build /debug/topology page failed", "component", "debug", "err", err)
		http.Error(w, "topology render failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := topologyTemplate.Execute(w, page); err != nil {
		slog.Error("render /debug/topology failed", "component", "debug", "err", err)
	}
}

// buildTopologyPage shapes a Neutron snapshot into the cross-tenant
// graph the template renders. The view intentionally shows the
// global topology — networks span tenants via shared transits and
// external gateways, and the static-route resolver crosses tenant
// edges. Per-tenant partitioning would hide exactly the relationships
// an operator needs to debug.
func buildTopologyPage(snap *neutron.Snapshot, lastSync time.Time) (topologyPage, error) {
	page := topologyPage{LastSync: lastSync}
	if snap == nil {
		return page, nil
	}

	// Indices reused across edge-builder passes.
	portByIP := make(map[string]neutron.Port, len(snap.Ports))
	for _, p := range snap.Ports {
		for _, fip := range p.FixedIPs {
			portByIP[fip.IPAddress] = p
		}
	}
	subnetsByNet := make(map[string][]string, len(snap.Networks))
	for _, s := range snap.Subnets {
		subnetsByNet[s.NetworkID] = append(subnetsByNet[s.NetworkID], s.CIDR)
	}

	tenants := make(map[string]struct{}, 16)
	for _, n := range snap.Networks {
		page.Graph.Nodes = append(page.Graph.Nodes, topologyNode{
			ID:     n.ID,
			Label:  networkLabel(n, subnetsByNet[n.ID]),
			Kind:   networkKind(n),
			Tenant: n.ProjectID,
		})
		tenants[n.ProjectID] = struct{}{}
	}
	for _, r := range snap.Routers {
		page.Graph.Nodes = append(page.Graph.Nodes, topologyNode{
			ID:     r.ID,
			Label:  r.ID,
			Kind:   "router",
			Tenant: r.ProjectID,
		})
		tenants[r.ProjectID] = struct{}{}
	}

	// Edge builders. Each kind gets its own pass so the visit order
	// is predictable for tests; the final element order in the page
	// is irrelevant to the layout (Cytoscape lays out from scratch).
	seq := 0
	addEdge := func(src, tgt, kind, label string) {
		seq++
		page.Graph.Edges = append(page.Graph.Edges, topologyEdge{
			ID:     fmt.Sprintf("e%d", seq),
			Source: src,
			Target: tgt,
			Kind:   kind,
			Label:  label,
		})
	}

	// Router-interface attachments: every port with that device_owner
	// joins a router (DeviceID) to a network (NetworkID).
	for _, p := range snap.Ports {
		if p.DeviceOwner != "network:router_interface" {
			continue
		}
		ip := ""
		if len(p.FixedIPs) > 0 {
			ip = p.FixedIPs[0].IPAddress
		}
		addEdge(p.DeviceID, p.NetworkID, "attach", ip)
	}

	// External gateways: Router.ExternalNetworkID points at the
	// upstream network if set.
	for _, r := range snap.Routers {
		if r.ExternalNetworkID == "" {
			continue
		}
		addEdge(r.ID, r.ExternalNetworkID, "gateway", "ext-gw")
	}

	// Extraroutes resolved via nexthop port. Only emit when the
	// nexthop IP belongs to a router_interface port; nexthops that
	// land on VM appliances are visualisation noise and would
	// require resolver-like multi-hop walking the page does not do.
	for _, r := range snap.Routers {
		for _, route := range r.Routes {
			np, ok := portByIP[route.Nexthop]
			if !ok || np.DeviceOwner != "network:router_interface" {
				continue
			}
			addEdge(r.ID, np.DeviceID, "extraroute",
				fmt.Sprintf("%s via %s", route.Destination, route.Nexthop))
		}
	}

	page.Tenants = make([]string, 0, len(tenants))
	for t := range tenants {
		page.Tenants = append(page.Tenants, t)
	}
	sort.Strings(page.Tenants)

	b, err := json.Marshal(page.Graph)
	if err != nil {
		return page, fmt.Errorf("marshal graph: %w", err)
	}
	page.GraphJSON = template.JS(b)
	return page, nil
}

// networkLabel composes the multi-line node label: network name (or
// ID fallback) on top, comma-separated subnet CIDRs underneath. The
// CIDR list lets operators spot the "which network owns 10.0.1.0/24"
// question without a second tab on /debug/zones.
func networkLabel(n neutron.Network, cidrs []string) string {
	name := n.Name
	if name == "" {
		name = n.ID
	}
	if len(cidrs) == 0 {
		return name
	}
	return name + "\n" + strings.Join(cidrs, ", ")
}

// networkKind maps Neutron's (Shared, IsExternal) flags to the
// template's style selector. The order matters: a network can be
// flagged both shared and external in API responses; external wins
// because operators visually parse "this is the public network"
// first, "this is shared" second.
func networkKind(n neutron.Network) string {
	switch {
	case n.IsExternal:
		return "network-external"
	case n.Shared:
		return "network-shared"
	}
	return "network"
}
