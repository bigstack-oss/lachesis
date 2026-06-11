package debug

import (
	"net/http"
	"sort"
	"time"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/neutron"
)

var topologyDirectoryTemplate = parsePage("topology_directory.html")

// handleTopology renders the tenant directory — the entry point when
// an operator opens /debug/topology. Each row links to a focused
// per-tenant view that stays readable at production scale.
func (s *Server) handleTopology(w http.ResponseWriter, r *http.Request) {
	model := buildTopologyDirectoryModel(s.opts.Snapshot(), s.opts.LastSync())
	render(w, r, topologyDirectoryTemplate, model)
}

// buildTopologyDirectoryModel counts per-tenant resources and
// cross-tenant edges so the directory can sort by activity. The
// classification mirrors the per-tenant view: an edge is
// cross-tenant when its two endpoints have different ProjectIDs.
func buildTopologyDirectoryModel(snap *neutron.Snapshot, lastSync time.Time) topologyDirectoryModel {
	model := topologyDirectoryModel{LastSync: lastSync, Synced: !lastSync.IsZero()}
	if snap == nil {
		return model
	}

	networkByID := indexNetworks(snap)
	routerByID := indexRouters(snap)
	portByIP := indexPortsByIP(snap)

	type stats struct {
		networks, routers                      int
		outAttach, inAttach, outExtra, inExtra int
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
		if p.DeviceOwner != neutron.DeviceOwnerRouterInterface {
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
			if !ok || np.DeviceOwner != neutron.DeviceOwnerRouterInterface {
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
		model.Rows = append(model.Rows, directoryRow{
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
	sort.Slice(model.Rows, func(i, j int) bool {
		if model.Rows[i].CrossTotal != model.Rows[j].CrossTotal {
			return model.Rows[i].CrossTotal > model.Rows[j].CrossTotal
		}
		return model.Rows[i].TenantName < model.Rows[j].TenantName
	})
	return model
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

// --- snapshot indexes shared by the topology builders ---

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
