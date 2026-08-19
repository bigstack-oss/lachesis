// trie.go owns the trie builder. Each step is one emit* method on
// [trieBuilder], run in documented order by [buildTrie]; the resolver
// lives in resolve.go and the port predicates in deviceowner.go.
//
// docs/architecture/trie-construction.md#the-five-step-algorithm

package neutron

import (
	"log/slog"
	"net/netip"
	"sort"
	"time"

	"github.com/bigstack-oss/lachesis/internal/bpf"
)

// BuildTrie runs the cold-start algorithm over snap and returns the rows
// destined for the kernel subnet_zone_trie, plus every ambiguity and
// cycle the static-route resolver hit. A non-empty ambiguity slice must
// refuse the boot under strict mode: those routes fall back to EXTERNAL
// and silently mis-bill the cross-tenant CIDR they cover. Output is
// sorted, so consecutive builds over identical input diff to nothing.
//
// docs/architecture/trie-construction.md#the-five-step-algorithm
func BuildTrie(snap Snapshot) ([]TrieEntry, []AmbiguityHit, []CycleHit) {
	return buildTrie(snap, nil, defaultMaxStaticRouteHops)
}

// buildTrie is [BuildTrie] with per-step timings on m (nil-safe) and
// the trace bounded by maxHops. The body is a literal transcription of
// the documented step order.
func buildTrie(snap Snapshot, m *Metrics, maxHops int) ([]TrieEntry, []AmbiguityHit, []CycleHit) {
	b := newTrieBuilder(snap, m, maxHops)
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
// maxHops bounds the static-route resolver for this build.
func newTrieBuilder(snap Snapshot, m *Metrics, maxHops int) *trieBuilder {
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
		ri:               newResolveIndex(snap, maxHops),
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

// emitExtraRoutes is Step 5: resolve every (destination, nexthop) on
// each tenant's routers and emit one per-tenant row per route. The
// resolver's ambiguity and cycle hits accumulate on the builder.
//
// docs/architecture/trie-construction.md#the-static-route-resolver
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
					continue // IPv6 nexthops are deferred work, item 1
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

// parsePrefixV4 returns the prefix if it is IPv4; IPv6 returns false
// silently (filtered, not malformed). The result is Masked() — an
// operator-authored extraroute like 10.0.0.5/24 with dirty host bits
// would otherwise land at the wrong trie node and miss.
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
