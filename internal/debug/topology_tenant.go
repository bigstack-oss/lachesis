package debug

import (
	"net/http"
	"sort"
	"time"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/neutron"
)

var topologyTenantTemplate = parsePage("topology_tenant.html")

// handleTopologyTenant renders the focused per-tenant view. The
// tenant id is taken from the URL path; unknown tenants render an
// empty-state page rather than 404 so an operator who pastes an ID
// into the URL still gets a clear "no resources" answer.
func (s *Server) handleTopologyTenant(w http.ResponseWriter, r *http.Request) {
	tenant := r.PathValue("tenant")
	model := buildTopologyTenantModel(s.opts.Snapshot(), tenant, s.opts.LastSync())
	render(w, r, topologyTenantTemplate, model)
}

// buildTopologyTenantModel assembles the text-first per-tenant view:
// the networks table, one card per router (attachments +
// extraroutes inline), and the flat cross-tenant extraroutes table.
// Cross-tenant rows are marked inline and link to the other
// tenant's view.
func buildTopologyTenantModel(snap *neutron.Snapshot, tenant string, lastSync time.Time) topologyTenantModel {
	model := topologyTenantModel{LastSync: lastSync, Synced: !lastSync.IsZero(), TenantID: tenant}
	if snap == nil {
		model.NotFound = true
		return model
	}
	model.TenantName = snap.ProjectName(tenant)

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
			Name:  displayName(n.Name, n.ID),
			CIDRs: append([]string(nil), subnetsByNet[n.ID]...),
		}
		switch {
		case n.IsExternal:
			row.Kind = "external"
		case n.Shared:
			row.Kind = "shared"
		}
		model.Networks = append(model.Networks, row)
	}
	sort.Slice(model.Networks, func(i, j int) bool { return model.Networks[i].Name < model.Networks[j].Name })

	// --- Router cards (owned by this tenant) ---
	// Group attachments + extraroutes per router ID so the template
	// renders one card per router.
	routerCards := map[string]*tenantRouterCard{}
	for _, r := range snap.Routers {
		if r.ProjectID != tenant {
			continue
		}
		card := &tenantRouterCard{ID: r.ID, Name: r.Name}
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
		if p.DeviceOwner != neutron.DeviceOwnerRouterInterface {
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
			model.Summary.CrossAttach++
		}
		model.Summary.Attachments++

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
			card.Attachments = append(card.Attachments, routerAttachmentRow{
				NetworkID:         network.ID,
				NetworkName:       displayName(network.Name, network.ID),
				NetworkTenantID:   network.ProjectID,
				NetworkTenantName: snap.ProjectName(network.ProjectID),
				IP:                ip,
				CrossTenant:       cross,
			})
		}
	}

	// Walk routers' extraroutes to populate per-card extraroute lists
	// plus the flat page-level cross-tenant extraroute table.
	for _, r := range snap.Routers {
		for _, route := range r.Routes {
			np, ok := portByIP[route.Nexthop]
			var nextRouter neutron.Router
			var resolved bool
			if ok && np.DeviceOwner == neutron.DeviceOwnerRouterInterface {
				nextRouter, resolved = routerByID[np.DeviceID]
			}

			involves := r.ProjectID == tenant || (resolved && nextRouter.ProjectID == tenant)
			if !involves {
				continue
			}

			cross := resolved && r.ProjectID != nextRouter.ProjectID
			if cross {
				model.Summary.CrossExtraroute++
			}
			model.Summary.Extraroutes++

			// Per-router card line, only on the source router's card
			// when the source router belongs to this tenant.
			if r.ProjectID == tenant {
				if card := routerCards[r.ID]; card != nil {
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
					row.Direction = extrarouteOut
				} else {
					row.Direction = extrarouteIn
				}
				model.Extraroutes = append(model.Extraroutes, row)
			}
		}
	}

	// Sort: outgoing first, then by source router id for stability.
	sort.Slice(model.Extraroutes, func(i, j int) bool {
		if model.Extraroutes[i].Direction != model.Extraroutes[j].Direction {
			return model.Extraroutes[i].Direction == extrarouteOut
		}
		return model.Extraroutes[i].SourceRouterID < model.Extraroutes[j].SourceRouterID
	})

	// Order router cards: cards with cross-tenant relationships first
	// (operators usually want to inspect those), then alphabetically.
	cards := make([]tenantRouterCard, 0, len(routerCards))
	for _, c := range routerCards {
		cards = append(cards, *c)
	}
	sort.Slice(cards, func(i, j int) bool {
		ci, cj := cardCrossCount(cards[i]), cardCrossCount(cards[j])
		if ci != cj {
			return ci > cj
		}
		return cards[i].ID < cards[j].ID
	})
	model.Routers = cards

	model.Summary.Networks = len(model.Networks)
	model.Summary.Routers = len(model.Routers)

	// If nothing belongs to this tenant at all, render not-found.
	if model.Summary.Networks == 0 && model.Summary.Routers == 0 &&
		model.Summary.CrossAttach == 0 && model.Summary.CrossExtraroute == 0 {
		model.NotFound = true
	}
	return model
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
