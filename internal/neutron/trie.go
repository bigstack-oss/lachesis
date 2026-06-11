package neutron

import (
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
)

// BuildOpt configures optional behaviour of [BuildTrie] without
// changing its required arguments. The variadic form keeps tests
// (which don't observe metrics) free of extra parameters while
// letting production callers opt into instrumentation.
type BuildOpt func(*buildOpts)

type buildOpts struct {
	metrics *Metrics
}

// WithMetrics attaches a [*Metrics] sink that BuildTrie will use
// to observe per-step durations via the
// `cubecos_neutron_builder_step_duration_seconds` histogram.
// Pass the *Metrics owned by the Agent; nil receivers no-op.
func WithMetrics(m *Metrics) BuildOpt {
	return func(o *buildOpts) { o.metrics = m }
}

// TrieEntry is one row destined for the kernel `subnet_zone_trie`:
// the tenant whose perspective the entry applies to, the IPv4
// prefix to match, and the resolved zone code. TenantID is the
// Keystone project UUID; the u32 mapping the kernel actually keys
// on is handled by a separate interner closer to the map writer.
type TrieEntry struct {
	TenantID string
	Prefix   netip.Prefix
	Zone     bpf.ZoneCode
}

// IsInfraPort classifies a Neutron port as infrastructure when its
// `device_owner` lives in Neutron's reserved `network:` namespace,
// with one explicit exception: `network:floatingip`.
//
// This predicate and [IsVMPort] together partition the
// `device_owner` space: a port is either infra (its IPs go into the
// trie as /32 INFRA rows) or VM-like (its MAC goes into the kernel
// `mac_tenant_map`). The exception `network:floatingip` is in
// neither — FIP ports are pure bookkeeping with no L2 endpoint, so
// kernel state for them is wasted capacity. See the comment on
// [IsVMPort] for the partition table.
//
// # Why prefix-match, not an allow-list
//
// docs/DESIGN.md §5.2 Step 4 lists five infra owners by name. The
// prefix rule captures those plus future and deployment-specific
// values without code change:
//
//   - network:router_interface, network:router_gateway
//   - network:dhcp, network:metadata, network:distributed
//   - network:floatingip_agent_gateway     (DVR FIP gateway)
//   - network:ha_router_replicated_interface (L3-HA VRRP)
//   - network:routed                       (segmented network access)
//
// Non-network device_owners — `compute:*`, `Octavia`, `manila:*`,
// `baremetal:*`, `trunk:*`, "" — never match. Misclassifying a VM
// port as INFRA would corrupt SAME_TENANT billing; the prefix rule
// keeps that boundary clean.
//
// # The floatingip exception
//
// A `network:floatingip` port carries the FIP itself as its
// fixed_ip — i.e. an address on the external network used to NAT
// into a tenant VM. Marking the /32 as INFRA would label any
// VM-to-FIP traffic as infrastructure; letting the catchall handle
// it (EXTERNAL) is more honest. In practice dst=FIP rarely reaches
// the trie at the VM tap (NAT translation usually intervenes
// upstream), but the distinction matters when it does.
func IsInfraPort(deviceOwner string) bool {
	if !strings.HasPrefix(deviceOwner, deviceOwnerNetworkPrefix) {
		return false
	}
	if deviceOwner == "network:floatingip" {
		return false
	}
	return true
}

// IsVMPort classifies a Neutron port as VM-like — i.e. its MAC
// belongs in the kernel `mac_tenant_map` because tenant-VM traffic
// terminates at this port.
//
// Partition table over observed `device_owner` values (dev-cmp,
// OVN-Yoga):
//
//	device_owner                    IsInfraPort  IsVMPort
//	network:router_interface        true         false
//	network:router_gateway          true         false
//	network:distributed             true         false
//	network:dhcp                    true         false
//	network:metadata                true         false
//	network:floatingip              false        false   ← bookkeeping
//	compute:nova                    false        true
//	Octavia / Octavia:health-mgr    false        true
//	manila:share                    false        true
//	baremetal:nova                  false        true
//	cube:mgr                        false        true    ← CubeCOS
//	(empty)                         false        false   ← unbound
//
// `cube:mgr` (observed on dev-cmp with project_id set) is treated
// as VM-like by default; revisit if CubeCOS management traffic
// should be billed differently.
func IsVMPort(deviceOwner string) bool {
	if deviceOwner == "" {
		return false
	}
	if strings.HasPrefix(deviceOwner, deviceOwnerNetworkPrefix) {
		return false
	}
	return true
}

// IsKnownVMOwner returns true for `device_owner` values empirically
// confirmed VM-like in OpenStack OVN-Yoga (the deployment target).
// Stricter than [IsVMPort]: an unknown vendor / third-party plugin
// owner passes [IsVMPort] (the conservative billing-safety default)
// but fails [IsKnownVMOwner].
//
// Bootstrap uses this to warn-log at cold-start whenever an admitted
// MAC came from an owner outside the known set, so operators can
// spot drift without classification semantics changing. The
// catalogue here is the verified ground truth on the deployment
// target (OpenStack OVN-Yoga):
//
//   - compute:* (Nova VMs, including AZ-specific suffixes)
//   - Octavia / Octavia:* (Octavia management + health-mgr ports)
//   - manila:* (Manila shares)
//   - baremetal:* (Ironic instances)
//   - trunk:* (VM trunk subports)
//   - cube:mgr (CubeCOS internal management VMs, dev-cmp empirical)
//
// Anything else — `vendor:foo`, `oslo:*`, future-Neutron strings —
// admits via [IsVMPort] but lights up a warn-log here.
func IsKnownVMOwner(deviceOwner string) bool {
	switch {
	case strings.HasPrefix(deviceOwner, "compute:"):
		return true
	case deviceOwner == "Octavia" || strings.HasPrefix(deviceOwner, "Octavia:"):
		return true
	case strings.HasPrefix(deviceOwner, "manila:"):
		return true
	case strings.HasPrefix(deviceOwner, "baremetal:"):
		return true
	case strings.HasPrefix(deviceOwner, "trunk:"):
		return true
	case deviceOwner == "cube:mgr":
		return true
	}
	return false
}

// BuildTrie runs the cold-start 5-step algorithm of
// docs/DESIGN.md §5.2 (Step 5 delegates to the multi-hop static-
// route resolver of §5.3) and returns a flat slice of [TrieEntry]
// in two shapes:
//
//   - Global rows (Steps 1, 3, 4): catchall, shared subnets,
//     infrastructure /32s, and the Nova metadata /32 are emitted
//     exactly once with TenantID="" (the writer resolves this to
//     [metadata.TenantIDUnset], the kernel sentinel u32 = 0).
//     The kernel `lookup_zone` consults these rows on first-
//     lookup miss using `tenant_id=0` as the fallback key — see
//     `bpf/telemetry.c` and `docs/DESIGN.md` §3.1.
//   - Per-tenant rows (Steps 2, 5): owned subnets and extraroutes
//     emit one [TrieEntry] per (owning-tenant, prefix). These are
//     the only entries that scale with tenant count, so total
//     trie cardinality is `O(G + Σ O_t)` rather than the
//     pre-dedup `O(T × G + Σ O_t)`.
//
// Globals are skipped entirely when no tenants are present —
// there is no kernel consumer (`mac_tenant_map` is empty) and
// writing them would waste trie capacity.
//
// The second return aggregates every Step C ambiguity-after-scoping
// incident encountered while resolving extraroutes (DESIGN §5.6).
// Callers running in strict mode (the default) refuse to start when
// the slice is non-empty; callers running with
// --unsafe-allow-ambiguous-routes log + accept the EXTERNAL
// fallback that the resolver already emitted for each affected route.
//
// The third return aggregates every static-route cycle the resolver
// encountered (a trace attempted to revisit a router on its path).
// These do not block boot — the resolver already fell back to
// EXTERNAL for each — but [DetectAnomalies] surfaces them via the
// /debug pages and the cubecos_neutron_anomalies gauge so an
// operator can fix the underlying misconfiguration.
//
// # Step coverage
//
//  1. Catchall:   `0.0.0.0/0 → EXTERNAL`, emitted once with
//     TenantID="".
//  2. Owned:      each tenant's non-shared, non-external subnets →
//     SAME_TENANT. Per-tenant.
//  3. Shared:     every non-external shared subnet → SHARED,
//     emitted once with TenantID="". SHARED is a distinct
//     zone (not SAME / not OTHER) because the LPM trie
//     cannot resolve per-VM ownership inside a shared
//     /24; the MAC-first hot path classifies L2 traffic
//     correctly, and SHARED labels the L3-routed-fallback
//     case honestly rather than guessing. See
//     docs/DESIGN.md §5.2 Step 3.
//  4. Infra:      router / DHCP / metadata port IPs + subnet gateway
//     IPs + 169.254.169.254 → INFRA, emitted once with
//     TenantID="".
//  5. Extraroutes: for each router R owned by the tenant, walk
//     every (destination, nexthop) entry in R.Routes through
//     [resolveStaticRouteZone] (docs/DESIGN.md §5.3). The resolver
//     iterates router-interface peers until it lands on a directly-
//     attached subnet or a compute:nova appliance, then classifies
//     via [zoneFor]. Misconfig (Step A miss), cycle, MAX_HOPS
//     exceeded, and ambiguity-after-scoping all fall back to
//     EXTERNAL with a warn-level log.
//
// # IPv6
//
// Subnets and fixed-IP entries with IPv6 addresses are skipped:
// the kernel `subnet_zone_trie` is keyed on u32 IPv4. IPv6 zone
// resolution is deferred (docs/DESIGN.md §13.2).
//
// # Error handling
//
// Malformed CIDRs / IPs are logged at warn-level and skipped. The
// alternative — refusing to start because one stale subnet has a
// bad CIDR — would block boot on otherwise-healthy data.
//
// The returned slice is sorted by (TenantID, prefix-string, Zone)
// so that consecutive reconciliations against identical input
// produce identical output, simplifying the change-detection logic
// the kernel map writer will use. Global rows (TenantID="") sort
// first; per-tenant runs follow in tenant-ID order.
func BuildTrie(snap Snapshot, opts ...BuildOpt) ([]TrieEntry, []AmbiguityHit, []CycleHit) {
	var bo buildOpts
	for _, o := range opts {
		o(&bo)
	}
	networks, subnets, ports, routers := snap.Networks, snap.Subnets, snap.Ports, snap.Routers

	subnetsByNetwork := groupSubnetsByNetwork(subnets)
	tenants := collectTenants(networks, ports, routers)
	sharedPrefixes := buildSharedPrefixes(networks, subnetsByNetwork)
	infraPrefixes := buildInfraPrefixes(subnets, ports)
	ri := newResolveIndex(snap)

	// Capacity hint: globals + an over-approximation of per-tenant
	// rows (every IPv4 subnet may emit one SAME_TENANT row). Extra-
	// routes are typically few; append will grow if not enough.
	entries := make([]TrieEntry, 0,
		2+len(sharedPrefixes)+len(infraPrefixes)+len(subnets))
	var ambiguities []AmbiguityHit
	var cycles []CycleHit
	// Per-step durations. Steps 1/3/4 are emitted once (single
	// observation each); Steps 2/5 are summed across tenants.
	var d1, d2, d3, d4, d5 time.Duration

	// Steps 1, 3, 4 — global rows emitted once with TenantID="".
	// Skipped when no tenants exist: the kernel `mac_tenant_map`
	// would be empty, so `lookup_zone` returns ZONE_MISS at the
	// MAC-first probe before the trie is ever consulted.
	if len(tenants) > 0 {
		t0 := time.Now()
		entries = append(entries, TrieEntry{"", catchall, bpf.ZoneExternal})
		d1 = time.Since(t0)

		// Step 3: shared subnets → SHARED, single row each. The
		// trie cannot resolve per-VM ownership inside the shared
		// CIDR; the billing engine treats SHARED as its own
		// category.
		t0 = time.Now()
		for _, p := range sharedPrefixes {
			entries = append(entries, TrieEntry{"", p, bpf.ZoneShared})
		}
		d3 = time.Since(t0)

		// Step 4: infra /32s, single row each.
		t0 = time.Now()
		for _, p := range infraPrefixes {
			entries = append(entries, TrieEntry{"", p, bpf.ZoneInfra})
		}
		entries = append(entries, TrieEntry{"", metadataPrefix, bpf.ZoneInfra})
		d4 = time.Since(t0)
	}

	// Steps 2, 5 — per-tenant rows.
	for _, tenant := range tenants {
		// Step 2: owned, non-shared, non-external subnets. External
		// networks (router:external=true) fall through to the
		// Step-1 catchall — they classify as EXTERNAL even when an
		// operator has marked them owned by some admin project.
		t0 := time.Now()
		for _, n := range networks {
			if n.ProjectID != tenant || n.Shared || n.IsExternal {
				continue
			}
			for _, s := range subnetsByNetwork[n.ID] {
				p, ok := parsePrefixV4(s.CIDR)
				if !ok {
					continue
				}
				entries = append(entries, TrieEntry{tenant, p, bpf.ZoneSameTenant})
			}
		}
		d2 += time.Since(t0)

		// Step 5: extraroutes on this tenant's routers. The resolver
		// returns a zone for each (destination, nexthop) by tracing
		// router-interface peers until it lands on a directly-attached
		// subnet or a compute:nova appliance (docs/DESIGN.md §5.3).
		t0 = time.Now()
		for _, r := range routers {
			if r.ProjectID != tenant {
				continue
			}
			for _, route := range r.Routes {
				destination, ok := parsePrefixV4(route.Destination)
				if !ok {
					continue
				}
				nh, err := netip.ParseAddr(route.Nexthop)
				if err != nil {
					slog.Warn("invalid extraroute nexthop; skipped",
						"component", componentNeutron,
						"tenant", tenant,
						"destination", route.Destination,
						"nexthop", route.Nexthop,
						"err", err)
					continue
				}
				if !nh.Is4() {
					continue // IPv6 nexthops deferred (DESIGN §13.2).
				}
				zone, ambHit, cycHit := ri.resolveStaticRouteZone(r, destination, nh)
				entries = append(entries, TrieEntry{tenant, destination, zone})
				if ambHit != nil {
					ambiguities = append(ambiguities, *ambHit)
				}
				if cycHit != nil {
					cycles = append(cycles, *cycHit)
				}
			}
		}
		d5 += time.Since(t0)
	}

	bo.metrics.ObserveBuilderStep(stepCatchall, d1)
	bo.metrics.ObserveBuilderStep(stepOwned, d2)
	bo.metrics.ObserveBuilderStep(stepShared, d3)
	bo.metrics.ObserveBuilderStep(stepInfra, d4)
	bo.metrics.ObserveBuilderStep(stepExtraRoutes, d5)

	sortEntries(entries)
	return entries, ambiguities, cycles
}

// groupSubnetsByNetwork indexes IPv4 subnets by their parent network
// ID. IPv6 subnets are filtered out here once so callers can iterate
// without re-checking IPVersion.
func groupSubnetsByNetwork(subnets []Subnet) map[string][]Subnet {
	out := make(map[string][]Subnet, len(subnets))
	for _, s := range subnets {
		if s.IPVersion != 4 {
			continue
		}
		out[s.NetworkID] = append(out[s.NetworkID], s)
	}
	return out
}

// collectTenants returns the sorted union of ProjectIDs that own any
// resource in the snapshot. Sorted so [BuildTrie] emits per-tenant
// runs in a stable order.
func collectTenants(networks []Network, ports []Port, routers []Router) []string {
	set := make(map[string]struct{})
	for _, n := range networks {
		if n.ProjectID != "" {
			set[n.ProjectID] = struct{}{}
		}
	}
	for _, p := range ports {
		if p.ProjectID != "" {
			set[p.ProjectID] = struct{}{}
		}
	}
	for _, r := range routers {
		if r.ProjectID != "" {
			set[r.ProjectID] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// buildSharedPrefixes returns CIDRs for networks that are shared but
// NOT external. External networks (router:external=true) are
// intentionally excluded — even when shared=true some deployments
// mark the public-FIP pool that way — because traffic to those
// CIDRs is leaving the cloud and should classify as EXTERNAL, not
// OTHER_TENANT. Step-1 catchall covers them.
func buildSharedPrefixes(networks []Network, subnetsByNetwork map[string][]Subnet) []netip.Prefix {
	seen := make(map[netip.Prefix]struct{})
	var out []netip.Prefix
	for _, n := range networks {
		if !n.Shared || n.IsExternal {
			continue
		}
		for _, s := range subnetsByNetwork[n.ID] {
			p, ok := parsePrefixV4(s.CIDR)
			if !ok {
				continue
			}
			if _, dup := seen[p]; dup {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	return out
}

// buildInfraPrefixes collects the global INFRA /32s from infra-port
// fixed IPs and subnet gateway IPs. These two sources overlap heavily:
// a router-interface port's fixed IP is almost always the subnet's
// gateway IP, so a naive append emits each gateway /32 twice. We
// de-duplicate so the global INFRA rows stay single-copy, keeping the
// trie's deduped O(G + Σ O_t) cardinality and an accurate entry count.
func buildInfraPrefixes(subnets []Subnet, ports []Port) []netip.Prefix {
	seen := make(map[netip.Prefix]struct{})
	var out []netip.Prefix
	add := func(prefix netip.Prefix) {
		if _, dup := seen[prefix]; dup {
			return
		}
		seen[prefix] = struct{}{}
		out = append(out, prefix)
	}
	for _, p := range ports {
		if !IsInfraPort(p.DeviceOwner) {
			continue
		}
		for _, ip := range p.FixedIPs {
			prefix, ok := parseAddrV4AsPrefix(ip.IPAddress)
			if !ok {
				continue
			}
			add(prefix)
		}
	}
	for _, s := range subnets {
		if s.IPVersion != 4 || s.GatewayIP == "" {
			continue
		}
		prefix, ok := parseAddrV4AsPrefix(s.GatewayIP)
		if !ok {
			continue
		}
		add(prefix)
	}
	return out
}

// parsePrefixV4 parses a CIDR string and returns the prefix if it is
// IPv4. IPv6 prefixes return ok=false silently — they are filtered,
// not malformed. Malformed strings emit a warn-level log.
//
// The result is canonicalized with Masked() so host bits are zeroed
// before the prefix becomes an LPM key. Subnet CIDRs from Neutron are
// usually already canonical, but operator-authored extraroute
// destinations (Step 5) are not guaranteed to be — a key like
// 10.0.0.5/24 with dirty host bits would land at the wrong trie node
// and miss on the routed-fallback lookup (ZONE_MISS → misbilling).
func parsePrefixV4(s string) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		slog.Warn("invalid subnet CIDR; skipped",
			"component", componentNeutron, "cidr", s, "err", err)
		return netip.Prefix{}, false
	}
	if !p.Addr().Is4() {
		return netip.Prefix{}, false
	}
	return p.Masked(), true
}

// parseAddrV4AsPrefix parses a bare IPv4 address into a /32 prefix.
// Empty input is treated as not-present (no log); other parse
// failures log a warning.
func parseAddrV4AsPrefix(s string) (netip.Prefix, bool) {
	if s == "" {
		return netip.Prefix{}, false
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		slog.Warn("invalid IP; skipped",
			"component", componentNeutron, "addr", s, "err", err)
		return netip.Prefix{}, false
	}
	if !addr.Is4() {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr, 32), true
}

// sortEntries imposes a stable (TenantID, prefix, Zone) order so
// successive reconciliations against identical snapshots emit
// identical slices.
func sortEntries(es []TrieEntry) {
	sort.Slice(es, func(i, j int) bool {
		if es[i].TenantID != es[j].TenantID {
			return es[i].TenantID < es[j].TenantID
		}
		pi, pj := es[i].Prefix.String(), es[j].Prefix.String()
		if pi != pj {
			return pi < pj
		}
		return es[i].Zone < es[j].Zone
	})
}
