package neutron

import "sort"

// Anomalies bundles every health issue derivable from a Neutron
// snapshot plus the trie BuildTrie produced from it. Computed once
// per cold-start (and per future incremental resync) so the /debug
// pages and the lachesis_neutron_anomalies gauge can surface
// misconfigurations before they corrupt billing.
//
// The classes are independent — a single misconfigured router can
// appear in more than one slice (e.g. a dangling extraroute on a
// router that also participates in a cycle). The per-hit record
// types (CycleHit, AmbiguityHit, DanglingRoute, ZeroTrieTenant,
// DuplicateRouterMAC) live in schema.go.
type Anomalies struct {
	// Cycles aggregates static-route cycles BuildTrie's resolver
	// encountered while tracing extraroutes. Each hit corresponds to
	// one (router, destination) pair whose nexthop chain revisited
	// a previously-seen router; the resolver fell back to EXTERNAL.
	Cycles []CycleHit
	// Ambiguities aggregates Step-C "multiple owners" incidents from
	// the same trace — re-exposed here so /debug can render every
	// health issue from a single source.
	Ambiguities []AmbiguityHit
	// DanglingRoutes lists extraroutes whose immediate nexthop does
	// not match any port in the snapshot. Stale Neutron data,
	// hand-edited routers, and nexthops pointing at devices outside
	// Neutron's view all surface here.
	DanglingRoutes []DanglingRoute
	// ZeroTrieTenants names tenants that own Neutron resources but
	// have zero trie rows. Indicates a cold-start gap or builder
	// bug: this tenant's intra-cluster traffic will fall through to
	// the global catchall and classify as EXTERNAL.
	ZeroTrieTenants []ZeroTrieTenant
	// DuplicateRouterMACs lists MACs shared by two or more
	// router_interface ports. On pure-OVN deployments every logical
	// router interface has a unique MAC; duplicates indicate DVR
	// (not supported), a snapshot defect, or a Neutron schema drift.
	DuplicateRouterMACs []DuplicateRouterMAC
	// MultiExternalPaths lists VM ports whose external-network
	// attribution was ambiguous (several FIPs / gateway routers on
	// different external networks). Their external_network label and
	// per-server export dimension are the deterministic pick, not
	// necessarily where every byte really egressed — per-network
	// external billing for these VMs is approximate (the documented
	// first-cut limitation of docs/architecture/billing.md attribution).
	MultiExternalPaths []MultiExternalPathHit
}

// Total returns the combined count across all anomaly classes.
// Used by the /debug landing page to render a single "N anomalies"
// header before drilling into per-class detail.
func (a Anomalies) Total() int {
	return len(a.Cycles) + len(a.Ambiguities) + len(a.DanglingRoutes) +
		len(a.ZeroTrieTenants) + len(a.DuplicateRouterMACs) +
		len(a.MultiExternalPaths)
}

// DetectAnomalies aggregates the cycle + ambiguity hits BuildTrie
// already produced and adds four more post-pass checks: dangling
// extraroutes, tenants with zero trie rows, duplicate
// router_interface MACs, and VM ports with ambiguous external-network
// attribution. Pure function over its inputs — no I/O, no goroutines.
//
// cycles and ambiguities may be nil (no hits during BuildTrie); the
// returned [Anomalies] mirrors that with nil/empty slices in the
// corresponding fields rather than synthesising entries.
func DetectAnomalies(snap Snapshot, trie []TrieEntry, cycles []CycleHit, ambiguities []AmbiguityHit) Anomalies {
	return Anomalies{
		Cycles:              append([]CycleHit(nil), cycles...),
		Ambiguities:         append([]AmbiguityHit(nil), ambiguities...),
		DanglingRoutes:      detectDanglingRoutes(snap),
		ZeroTrieTenants:     detectZeroTrieTenants(snap, trie),
		DuplicateRouterMACs: detectDuplicateRouterMACs(snap),
		MultiExternalPaths:  detectMultiExternalPaths(snap),
	}
}

// detectDanglingRoutes walks every router's Routes and reports
// those whose Nexthop does not match any FixedIP across the
// snapshot's ports. Both IPv4 and IPv6 routes are checked — the
// trie builder skips non-IPv4 nexthops, but a dangling IPv6
// extraroute is still operator-visible misconfiguration.
//
// Output order: by SourceRouter, then by Destination — stable
// across runs on identical input.
func detectDanglingRoutes(snap Snapshot) []DanglingRoute {
	if len(snap.Routers) == 0 {
		return nil
	}
	known := make(map[string]struct{}, len(snap.Ports))
	for _, p := range snap.Ports {
		for _, fip := range p.FixedIPs {
			if fip.IPAddress != "" {
				known[fip.IPAddress] = struct{}{}
			}
		}
	}
	var out []DanglingRoute
	for _, r := range snap.Routers {
		for _, route := range r.Routes {
			if route.Nexthop == "" {
				continue
			}
			if _, ok := known[route.Nexthop]; ok {
				continue
			}
			out = append(out, DanglingRoute{
				SourceTenant: r.ProjectID,
				SourceRouter: r.ID,
				Destination:  route.Destination,
				Nexthop:      route.Nexthop,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SourceRouter != out[j].SourceRouter {
			return out[i].SourceRouter < out[j].SourceRouter
		}
		return out[i].Destination < out[j].Destination
	})
	return out
}

// detectZeroTrieTenants compares the set of tenants that own
// resources in the snapshot against the set of TenantIDs present
// in the trie. A tenant in the first set but missing from the
// second is reported with its owned-resource counts.
//
// Tenants that own only VM ports (no networks, no routers) still
// count: their VMs will be billed against an empty trie and
// classify as EXTERNAL on every L3-routed flow. Tenants that own
// nothing are not reported — they have nothing to classify.
//
// Output order: by TenantID ascending.
func detectZeroTrieTenants(snap Snapshot, trie []TrieEntry) []ZeroTrieTenant {
	trieTenants := make(map[string]struct{}, len(trie))
	for _, e := range trie {
		if e.TenantID != "" {
			trieTenants[e.TenantID] = struct{}{}
		}
	}
	owned := make(map[string]*ZeroTrieTenant)
	bump := func(id string, fn func(*ZeroTrieTenant)) {
		if id == "" {
			return
		}
		z, ok := owned[id]
		if !ok {
			z = &ZeroTrieTenant{TenantID: id}
			owned[id] = z
		}
		fn(z)
	}
	for _, n := range snap.Networks {
		bump(n.ProjectID, func(z *ZeroTrieTenant) { z.Networks++ })
	}
	for _, r := range snap.Routers {
		bump(r.ProjectID, func(z *ZeroTrieTenant) { z.Routers++ })
	}
	for _, p := range snap.Ports {
		if !IsVMPort(p.DeviceOwner) {
			continue
		}
		bump(p.ProjectID, func(z *ZeroTrieTenant) { z.Ports++ })
	}
	var out []ZeroTrieTenant
	for id, z := range owned {
		if _, ok := trieTenants[id]; ok {
			continue
		}
		out = append(out, *z)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TenantID < out[j].TenantID })
	return out
}

// detectDuplicateRouterMACs groups router_interface ports by MAC
// and emits one entry per group with size > 1. The MAC string is
// taken verbatim from the snapshot — Neutron normalises to
// lowercase colon-separated form on the wire, but the check is
// case-sensitive (a mismatched case would still be a real defect).
//
// Output order: by MAC ascending. PortIDs and RouterIDs within
// each entry are sorted ascending for stable rendering.
func detectDuplicateRouterMACs(snap Snapshot) []DuplicateRouterMAC {
	groups := make(map[string][]Port)
	for _, p := range snap.Ports {
		if p.DeviceOwner != DeviceOwnerRouterInterface || p.MACAddress == "" {
			continue
		}
		groups[p.MACAddress] = append(groups[p.MACAddress], p)
	}
	var out []DuplicateRouterMAC
	for mac, ports := range groups {
		if len(ports) < 2 {
			continue
		}
		entry := DuplicateRouterMAC{MAC: mac}
		routerSet := make(map[string]struct{}, len(ports))
		for _, p := range ports {
			entry.PortIDs = append(entry.PortIDs, p.ID)
			if p.DeviceID != "" {
				routerSet[p.DeviceID] = struct{}{}
			}
		}
		for rid := range routerSet {
			entry.RouterIDs = append(entry.RouterIDs, rid)
		}
		sort.Strings(entry.PortIDs)
		sort.Strings(entry.RouterIDs)
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MAC < out[j].MAC })
	return out
}
