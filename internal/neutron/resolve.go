package neutron

import (
	"log/slog"
	"net/netip"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
)

// maxStaticRouteHops bounds the multi-hop trace. Real OpenStack
// deployments rarely exceed 3–4 hops; 16 is generous and an
// exceedance almost certainly indicates a routing misconfig (per
// docs/DESIGN.md §5.3).
const maxStaticRouteHops = 16

// resolveIndex bundles the Neutron snapshot in lookup-optimised
// form so the per-route resolver runs in O(1) per step. Built once
// per BuildTrie invocation and shared across every
// resolveStaticRouteZone call. All fields are immutable after
// construction.
type resolveIndex struct {
	routers       map[string]Router          // by router ID
	subnets       map[string]Subnet          // by subnet ID
	networks      map[string]Network         // by network ID
	routerSubnets map[string][]string        // routerID → subnet IDs attached via network:router_interface
	portsInSubnet map[string]map[string]Port // subnetID → IPAddress → Port
}

// newResolveIndex builds the lookup tables from the raw Neutron
// snapshot. IPv6 fixed-IPs and subnets are admitted to the maps
// without filtering — anchorSubnet checks IPVersion at lookup time
// so resolveStaticRouteZone safely operates only on IPv4 chains.
func newResolveIndex(networks []Network, subnets []Subnet, ports []Port, routers []Router) *resolveIndex {
	ri := &resolveIndex{
		routers:       make(map[string]Router, len(routers)),
		subnets:       make(map[string]Subnet, len(subnets)),
		networks:      make(map[string]Network, len(networks)),
		routerSubnets: make(map[string][]string),
		portsInSubnet: make(map[string]map[string]Port),
	}
	for _, n := range networks {
		ri.networks[n.ID] = n
	}
	for _, s := range subnets {
		ri.subnets[s.ID] = s
	}
	for _, r := range routers {
		ri.routers[r.ID] = r
	}
	for _, p := range ports {
		if p.DeviceOwner == "network:router_interface" && p.DeviceID != "" {
			for _, fip := range p.FixedIPs {
				if fip.SubnetID == "" {
					continue
				}
				ri.routerSubnets[p.DeviceID] = append(ri.routerSubnets[p.DeviceID], fip.SubnetID)
			}
		}
		for _, fip := range p.FixedIPs {
			if fip.SubnetID == "" || fip.IPAddress == "" {
				continue
			}
			sub, ok := ri.portsInSubnet[fip.SubnetID]
			if !ok {
				sub = make(map[string]Port)
				ri.portsInSubnet[fip.SubnetID] = sub
			}
			sub[fip.IPAddress] = p
		}
	}
	return ri
}

// resolveStaticRouteZone implements the multi-hop trace of
// docs/DESIGN.md §5.3 for one (destination, nexthop) pair on
// router r. Returns the zone code to record in the trie. Any
// unresolvable case (misconfig, cycle, MAX_HOPS exceeded, unknown
// peer device type, ambiguity) returns ZoneExternal — the strict-
// mode operator override that turns ambiguity into a startup
// failure lives in BuildTrie's call site (added in a later slice),
// not here.
func (ri *resolveIndex) resolveStaticRouteZone(
	r Router,
	destination netip.Prefix,
	initialNexthop netip.Addr,
) bpf.ZoneCode {
	sourceTenant := r.ProjectID
	currentRouter := r
	currentNexthop := initialNexthop
	visited := map[string]struct{}{r.ID: {}}

	for hop := 0; hop < maxStaticRouteHops; hop++ {
		// Step A — anchor on the iface subnet whose CIDR contains currentNexthop.
		ifaceSubnet, ok := ri.anchorSubnet(currentRouter.ID, currentNexthop)
		if !ok {
			return bpf.ZoneExternal
		}

		// Step B — identify the peer device at currentNexthop within the iface subnet.
		port, ok := ri.portAt(ifaceSubnet.ID, currentNexthop.String())
		if !ok {
			return bpf.ZoneExternal
		}
		switch port.DeviceOwner {
		case "network:router_interface":
			nextRouter, ok := ri.routers[port.DeviceID]
			if !ok {
				return bpf.ZoneExternal
			}
			if _, seen := visited[nextRouter.ID]; seen {
				slog.Warn("static-route cycle detected; falling back to EXTERNAL",
					"component", componentNeutron,
					"source_tenant", sourceTenant,
					"destination", destination.String(),
					"router", nextRouter.ID)
				return bpf.ZoneExternal
			}
			visited[nextRouter.ID] = struct{}{}

			// Step C — is destination directly attached on nextRouter?
			if zone, resolved := ri.resolveAtNextRouter(
				nextRouter, ifaceSubnet, destination, sourceTenant); resolved {
				return zone
			}

			// Step D — follow nextRouter's own extraroutes (LPM among matches).
			if nextRoute, ok := lpmMatchRoute(nextRouter.Routes, destination); ok {
				nh, err := netip.ParseAddr(nextRoute.Nexthop)
				if err != nil || !nh.Is4() {
					return bpf.ZoneExternal
				}
				currentRouter = nextRouter
				currentNexthop = nh
				continue
			}

			// Step E — default-route fallback. EXTERNAL whether or not nextRouter
			// has external_gateway_info; the destination is unreachable per
			// Neutron's topology view either way.
			return bpf.ZoneExternal

		case "compute:nova":
			// VM-appliance nexthop: classify by the appliance's tenant
			// relative to the source tenant on the iface network. The
			// destination beyond the appliance is opaque to Neutron, so
			// the trace stops here. Double-billing at the appliance's own
			// tap is documented in DESIGN.md §8 Tier 4 and Scenario L.
			ifaceNetwork, ok := ri.networks[ifaceSubnet.NetworkID]
			if !ok {
				return bpf.ZoneExternal
			}
			return zoneFor(port.ProjectID, sourceTenant, ifaceNetwork)

		default:
			return bpf.ZoneExternal
		}
	}

	slog.Warn("static-route MAX_HOPS exceeded; falling back to EXTERNAL",
		"component", componentNeutron,
		"source_tenant", sourceTenant,
		"destination", destination.String(),
		"max_hops", maxStaticRouteHops)
	return bpf.ZoneExternal
}

// anchorSubnet picks the router's interface subnet whose CIDR
// contains nexthop. Returns the first match.
func (ri *resolveIndex) anchorSubnet(routerID string, nexthop netip.Addr) (Subnet, bool) {
	for _, sid := range ri.routerSubnets[routerID] {
		s, ok := ri.subnets[sid]
		if !ok || s.IPVersion != 4 {
			continue
		}
		p, err := netip.ParsePrefix(s.CIDR)
		if err != nil {
			continue
		}
		if p.Contains(nexthop) {
			return s, true
		}
	}
	return Subnet{}, false
}

// portAt returns the port whose fixed_ip == ip on the given subnet.
func (ri *resolveIndex) portAt(subnetID, ip string) (Port, bool) {
	sub, ok := ri.portsInSubnet[subnetID]
	if !ok {
		return Port{}, false
	}
	p, ok := sub[ip]
	return p, ok
}

// resolveAtNextRouter implements Step C: search nextRouter's
// interface subnets for one whose CIDR supersets the destination,
// excluding the network we entered through. If exactly one
// candidate (or several all with the same project_id) matches,
// return that zone. If candidates have multiple distinct owners,
// log the ambiguity and return EXTERNAL.
func (ri *resolveIndex) resolveAtNextRouter(
	nextRouter Router,
	enteredThrough Subnet,
	destination netip.Prefix,
	sourceTenant string,
) (bpf.ZoneCode, bool) {
	var matchedNet Network
	var matchedOwners []string
	matched := false
	for _, sid := range ri.routerSubnets[nextRouter.ID] {
		s, ok := ri.subnets[sid]
		if !ok || s.IPVersion != 4 || s.NetworkID == enteredThrough.NetworkID {
			continue
		}
		sp, err := netip.ParsePrefix(s.CIDR)
		if err != nil || sp.Bits() > destination.Bits() || !sp.Contains(destination.Addr()) {
			continue
		}
		n, ok := ri.networks[s.NetworkID]
		if !ok {
			continue
		}
		if !matched {
			matchedNet = n
			matched = true
		}
		if !containsString(matchedOwners, n.ProjectID) {
			matchedOwners = append(matchedOwners, n.ProjectID)
		}
	}
	if !matched {
		return 0, false
	}
	if len(matchedOwners) > 1 {
		slog.Warn("static-route ambiguous owner; falling back to EXTERNAL",
			"component", componentNeutron,
			"source_tenant", sourceTenant,
			"destination", destination.String(),
			"router", nextRouter.ID,
			"owners", matchedOwners)
		return bpf.ZoneExternal, true
	}
	return zoneFor(matchedNet.ProjectID, sourceTenant, matchedNet), true
}

// lpmMatchRoute returns the entry in routes whose Destination CIDR
// is a supernet of (or equal to) destination, picking the longest
// matching prefix.
func lpmMatchRoute(routes []Route, destination netip.Prefix) (Route, bool) {
	best := Route{}
	bestBits := -1
	for _, r := range routes {
		rp, err := netip.ParsePrefix(r.Destination)
		if err != nil || rp.Bits() > destination.Bits() || !rp.Contains(destination.Addr()) {
			continue
		}
		if rp.Bits() > bestBits {
			bestBits = rp.Bits()
			best = r
		}
	}
	return best, bestBits >= 0
}

// containsString is a tiny linear lookup for the small (typically ≤2)
// owner slice maintained by resolveAtNextRouter. A map would be
// heavier for the expected size.
func containsString(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// zoneFor classifies a destination network from the source tenant's
// perspective. Per docs/DESIGN.md §5.3.
//
// The check order is significant: external first, then shared, then
// the owner comparison. External wins over shared because some
// deployments mark a public FIP pool with both flags — traffic to
// those CIDRs is leaving the cloud and must classify as EXTERNAL.
// Shared wins over the owner comparison so that a shared network
// owned by the source tenant still emits SHARED; the trie cannot
// resolve per-VM ownership inside a shared CIDR, so labelling those
// flows SAME would systematically under-bill the owner's traffic to
// non-owner VMs attached to the same shared network. The MAC-first
// hot path classifies intra-tenant L2 traffic on shared networks as
// SAME_TENANT exactly; SHARED labels the L3-routed-fallback case.
func zoneFor(ownerTenant, sourceTenant string, network Network) bpf.ZoneCode {
	switch {
	case network.IsExternal:
		return bpf.ZoneExternal
	case network.Shared:
		return bpf.ZoneShared
	case ownerTenant == sourceTenant:
		return bpf.ZoneSameTenant
	default:
		return bpf.ZoneOtherTenant
	}
}
