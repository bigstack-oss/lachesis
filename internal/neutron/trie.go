// trie.go owns the trie builder: the 5-step algorithm of
// docs/architecture/trie-construction.md#the-five-step-algorithm that turns a [Snapshot] into the [TrieEntry]
// rows destined for the kernel `subnet_zone_trie`. Each step is one
// emit* method on [trieBuilder], executed in documented order by
// [buildTrie]. The multi-hop static-route resolver Step 5 delegates
// to lives in resolve.go; the port-classification predicates Step 4
// relies on live in deviceowner.go.

package neutron

import (
	"log/slog"
	"net/netip"
	"sort"
	"time"

	"github.com/bigstack-oss/lachesis/internal/bpf"
)

// BuildTrie runs the cold-start 5-step algorithm of
// docs/architecture/trie-construction.md#the-five-step-algorithm (Step 5 delegates to the multi-hop static-
// route resolver of docs/architecture/trie-construction.md#the-static-route-resolver) and returns a flat slice of [TrieEntry]
// in two shapes:
//
//   - Global rows (Steps 1, 3, 4): catchall, shared subnets,
//     infrastructure /32s, and the Nova metadata /32 are emitted
//     exactly once with TenantID="" (the writer resolves this to
//     [metadata.TenantIDUnset], the kernel sentinel u32 = 0).
//     The kernel `lookup_zone` consults these rows on first-
//     lookup miss using `tenant_id=0` as the fallback key — see
//     `bpf/telemetry.c` and docs/architecture/data-structures.md#kernel-side-bpf-maps.
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
// incident encountered while resolving extraroutes (docs/architecture/trie-construction.md#ambiguity-after-scoping).
// Callers running in strict mode (the default) refuse to start when
// the slice is non-empty; callers running with
// --unsafe-allow-ambiguous-routes log + accept the EXTERNAL
// fallback that the resolver already emitted for each affected route.
//
// The third return aggregates every static-route cycle the resolver
// encountered (a trace attempted to revisit a router on its path).
// These do not block boot — the resolver already fell back to
// EXTERNAL for each — but [DetectAnomalies] surfaces them via the
// /debug pages and the lachesis_neutron_anomalies gauge so an
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
//     docs/architecture/trie-construction.md#the-five-step-algorithm Step 3.
//  4. Infra:      router / DHCP / metadata port IPs + subnet gateway
//     IPs + 169.254.169.254 → INFRA, emitted once with
//     TenantID="".
//  5. Extraroutes: for each router R owned by the tenant, walk
//     every (destination, nexthop) entry in R.Routes through
//     [resolveStaticRouteZone] (docs/architecture/trie-construction.md#the-static-route-resolver). The resolver
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
// resolution is deferred (docs/architecture/contracts.md#deferred-work).
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
//
// BuildTrie does not observe metrics; [Neutron.Sync] runs the
// internal metrics-observing variant.
func BuildTrie(snap Snapshot) ([]TrieEntry, []AmbiguityHit, []CycleHit) {
	return buildTrie(snap, nil)
}

// buildTrie is the implementation behind [BuildTrie], with the
// per-step durations observed on m's
// `lachesis_neutron_builder_step_duration_seconds` histogram (m may
// be nil — every [Metrics] helper no-ops on nil receivers). The body
// is a literal transcription of the docs/architecture/trie-construction.md#the-five-step-algorithm step order; each step's
// logic lives on its [trieBuilder] emit* method.
func buildTrie(snap Snapshot, m *Metrics) ([]TrieEntry, []AmbiguityHit, []CycleHit) {
	b := newTrieBuilder(snap, m)
	b.step(stepCatchall, b.emitCatchall)
	b.step(stepOwned, b.emitOwnedSubnets)
	b.step(stepShared, b.emitSharedSubnets)
	b.step(stepInfra, b.emitInfraPrefixes)
	b.step(stepExtraRoutes, b.emitExtraRoutes)
	sortEntries(b.entries)
	return b.entries, b.ambiguities, b.cycles
}

// trieBuilder carries one buildTrie pass: the indexed snapshot views
// every step reads, the metrics sink, and the accumulating outputs.
// Single-use and single-goroutine; constructed by [newTrieBuilder],
// driven step-by-step by [buildTrie].
type trieBuilder struct {
	networks []Network
	routers  []Router

	subnetsByNetwork map[string][]Subnet
	tenants          []string
	sharedPrefixes   []netip.Prefix
	infraPrefixes    []netip.Prefix
	ri               *resolveIndex

	metrics *Metrics

	entries     []TrieEntry
	ambiguities []AmbiguityHit
	cycles      []CycleHit
}

// newTrieBuilder precomputes the lookup views shared across steps.
func newTrieBuilder(snap Snapshot, m *Metrics) *trieBuilder {
	subnetsByNetwork := groupSubnetsByNetwork(snap.Subnets)
	sharedPrefixes := buildSharedPrefixes(snap.Networks, subnetsByNetwork)
	infraPrefixes := buildInfraPrefixes(snap.Subnets, snap.Ports)
	return &trieBuilder{
		networks:         snap.Networks,
		routers:          snap.Routers,
		subnetsByNetwork: subnetsByNetwork,
		tenants:          collectTenants(snap.Networks, snap.Ports, snap.Routers),
		sharedPrefixes:   sharedPrefixes,
		infraPrefixes:    infraPrefixes,
		ri:               newResolveIndex(snap),
		metrics:          m,
		// Capacity hint: globals + an over-approximation of per-tenant
		// rows (every IPv4 subnet may emit one SAME_TENANT row). Extra-
		// routes are typically few; append will grow if not enough.
		entries: make([]TrieEntry, 0,
			2+len(sharedPrefixes)+len(infraPrefixes)+len(snap.Subnets)),
	}
}

// step runs one emit method and observes its duration under label on
// the builder-step histogram. Every step is observed on every build
// — a skipped step records ~0s rather than no sample, so the
// histogram's sample count stays a steady 5 per build.
func (b *trieBuilder) step(label string, fn func()) {
	t0 := time.Now()
	fn()
	b.metrics.ObserveBuilderStep(label, time.Since(t0))
}

// hasTenants reports whether any tenant owns a resource in the
// snapshot. The global rows (Steps 1/3/4) are skipped when none do:
// the kernel `mac_tenant_map` would be empty, so `lookup_zone`
// returns ZONE_MISS at the MAC-first probe before the trie is ever
// consulted.
func (b *trieBuilder) hasTenants() bool { return len(b.tenants) > 0 }

// emitCatchall is Step 1: the global `0.0.0.0/0 → EXTERNAL` row,
// emitted once with TenantID="".
func (b *trieBuilder) emitCatchall() {
	if !b.hasTenants() {
		return
	}
	b.entries = append(b.entries, TrieEntry{"", catchall, bpf.ZoneExternal})
}

// emitOwnedSubnets is Step 2: each tenant's owned, non-shared,
// non-external subnets → SAME_TENANT, one row per (tenant, prefix).
// External networks (router:external=true) fall through to the
// Step-1 catchall — they classify as EXTERNAL even when an operator
// has marked them owned by some admin project.
func (b *trieBuilder) emitOwnedSubnets() {
	for _, tenant := range b.tenants {
		for _, n := range b.networks {
			if n.ProjectID != tenant || n.Shared || n.IsExternal {
				continue
			}
			for _, s := range b.subnetsByNetwork[n.ID] {
				p, ok := parsePrefixV4(s.CIDR)
				if !ok {
					continue
				}
				b.entries = append(b.entries, TrieEntry{tenant, p, bpf.ZoneSameTenant})
			}
		}
	}
}

// emitSharedSubnets is Step 3: every non-external shared subnet →
// SHARED, single global row each. The trie cannot resolve per-VM
// ownership inside the shared CIDR; the billing engine treats SHARED
// as its own category.
func (b *trieBuilder) emitSharedSubnets() {
	if !b.hasTenants() {
		return
	}
	for _, p := range b.sharedPrefixes {
		b.entries = append(b.entries, TrieEntry{"", p, bpf.ZoneShared})
	}
}

// emitInfraPrefixes is Step 4: the deduped infra /32s plus the Nova
// metadata /32, single global row each.
func (b *trieBuilder) emitInfraPrefixes() {
	if !b.hasTenants() {
		return
	}
	for _, p := range b.infraPrefixes {
		b.entries = append(b.entries, TrieEntry{"", p, bpf.ZoneInfra})
	}
	b.entries = append(b.entries, TrieEntry{"", metadataPrefix, bpf.ZoneInfra})
}

// emitExtraRoutes is Step 5: walk every (destination, nexthop) entry
// on each tenant's routers through [resolveStaticRouteZone]
// (docs/architecture/trie-construction.md#the-static-route-resolver) and emit one per-tenant row per route. The
// resolver traces router-interface peers until it lands on a
// directly-attached subnet or a compute:nova appliance; its
// ambiguity / cycle hits accumulate on the builder for the caller.
func (b *trieBuilder) emitExtraRoutes() {
	for _, tenant := range b.tenants {
		for _, r := range b.routers {
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
					continue // IPv6 nexthops deferred (docs/architecture/contracts.md#deferred-work).
				}
				zone, ambHit, cycHit := b.ri.resolveStaticRouteZone(r, destination, nh)
				b.entries = append(b.entries, TrieEntry{tenant, destination, zone})
				if ambHit != nil {
					b.ambiguities = append(b.ambiguities, *ambHit)
				}
				if cycHit != nil {
					b.cycles = append(b.cycles, *cycHit)
				}
			}
		}
	}
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
