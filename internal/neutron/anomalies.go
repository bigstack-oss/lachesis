package neutron

import "sort"

// Anomalies bundles every health issue derivable from a snapshot and
// its trie, so /debug and the anomalies gauge surface misconfiguration
// before it corrupts billing. The classes are independent: one bad
// router can appear in several slices.
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
	// attribution was ambiguous. Their label is the deterministic
	// pick, not necessarily where the bytes egressed, so per-network
	// external billing for them is approximate.
	//
	// docs/architecture/billing.md
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

// DetectAnomalies aggregates BuildTrie's cycle and ambiguity hits and
// adds four post-pass checks: dangling extraroutes, tenants with zero
// trie rows, duplicate router MACs, and ambiguous external attribution.
// Pure function; nil inputs stay nil in the result.
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

// detectDanglingRoutes reports routes whose Nexthop matches no FixedIP
// in the snapshot. IPv6 included: the trie skips those nexthops, but a
// dangling one is still real misconfiguration. Output is sorted.
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

// detectZeroTrieTenants reports tenants that own resources but have no
// trie rows — their VMs classify EXTERNAL on every L3-routed flow.
// Port-only tenants count; tenants owning nothing do not. Sorted.
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

// detectDuplicateRouterMACs reports router_interface MACs shared by
// more than one port. Case-sensitive on purpose: Neutron normalises on
// the wire, so a case mismatch is itself a defect. Sorted.
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
