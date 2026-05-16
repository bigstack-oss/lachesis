package neutron

import (
	"log/slog"
	"net/netip"
	"sort"
	"strings"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
)

// componentNeutron is the slog `component` attribute for all
// Neutron-subsystem log calls. Matches the per-package convention
// the rest of the codebase follows.
const componentNeutron = "neutron"

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

// metadataPrefix is the cloud-init / Nova metadata service IP. Always
// INFRA from every tenant's perspective (docs/DESIGN.md §5.2 Step 4).
var metadataPrefix = netip.MustParsePrefix("169.254.169.254/32")

// catchall is the 0.0.0.0/0 → EXTERNAL Step-1 entry. Every uncovered
// destination falls through to this row.
var catchall = netip.MustParsePrefix("0.0.0.0/0")

// isInfraPort classifies a Neutron port as infrastructure when its
// `device_owner` lives in Neutron's reserved `network:` namespace,
// with one explicit exception: `network:floatingip`.
//
// NOTE: when the kernel `mac_tenant_map` writer lands (Slice 4a.6),
// its port-filter MUST stay in lockstep with this predicate. The
// hybrid lookup in bpf/telemetry.c consults `mac_tenant_map` first
// and only falls back to the LPM trie on miss — so any divergence
// between the two filters silently corrupts classification for the
// MAC-first hot path.
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
func isInfraPort(deviceOwner string) bool {
	if !strings.HasPrefix(deviceOwner, "network:") {
		return false
	}
	if deviceOwner == "network:floatingip" {
		return false
	}
	return true
}

// BuildTrie runs the cold-start 5-step algorithm of
// docs/DESIGN.md §5.2 and returns a flat slice of [TrieEntry] for
// every tenant that owns at least one network, port, or router in
// the supplied Neutron snapshot.
//
// # Step coverage
//
//  1. Catchall:   each tenant gets `0.0.0.0/0 → EXTERNAL`.
//  2. Owned:      each tenant's non-shared, non-external subnets →
//     SAME_TENANT.
//  3. Shared:     every non-external shared subnet → SHARED, applied
//     uniformly to every tenant. SHARED is a distinct
//     zone (not SAME / not OTHER) because the LPM trie
//     cannot resolve per-VM ownership inside a shared
//     /24; the MAC-first hot path classifies L2 traffic
//     correctly, and SHARED labels the L3-routed-fallback
//     case honestly rather than guessing. See
//     docs/DESIGN.md §5.2 Step 3.
//  4. Infra:      router / DHCP / metadata port IPs + subnet gateway
//     IPs + 169.254.169.254 → INFRA for every tenant.
//  5. Static routes: OMITTED in this sprint. Extra-route CIDRs
//     fall through to the Step-1 catchall (EXTERNAL).
//     docs/sprint-plan.md §4b replaces this with the
//     multi-hop resolver of docs/DESIGN.md §5.3.
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
// the kernel map writer will use.
func BuildTrie(networks []Network, subnets []Subnet, ports []Port, routers []Router) []TrieEntry {
	subnetsByNetwork := groupSubnetsByNetwork(subnets)
	tenants := collectTenants(networks, ports, routers)
	sharedPrefixes := buildSharedPrefixes(networks, subnetsByNetwork)
	infraPrefixes := buildInfraPrefixes(subnets, ports)

	entries := make([]TrieEntry, 0,
		len(tenants)*(1+len(sharedPrefixes)+len(infraPrefixes)+1))

	for _, tenant := range tenants {
		entries = append(entries, TrieEntry{tenant, catchall, bpf.ZoneExternal})

		// Step 2: owned, non-shared, non-external subnets. External
		// networks (router:external=true) fall through to the
		// Step-1 catchall — they classify as EXTERNAL even when an
		// operator has marked them owned by some admin project.
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

		// Step 3: shared subnets → SHARED, applied to every tenant.
		// SHARED (not OTHER_TENANT) because the trie cannot resolve
		// per-VM ownership inside the shared CIDR; the billing
		// engine treats SHARED as its own category.
		for _, p := range sharedPrefixes {
			entries = append(entries, TrieEntry{tenant, p, bpf.ZoneShared})
		}

		// Step 4: infra IPs, applied to every tenant.
		for _, p := range infraPrefixes {
			entries = append(entries, TrieEntry{tenant, p, bpf.ZoneInfra})
		}
		entries = append(entries, TrieEntry{tenant, metadataPrefix, bpf.ZoneInfra})
	}

	sortEntries(entries)
	return entries
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
			out = append(out, p)
		}
	}
	return out
}

func buildInfraPrefixes(subnets []Subnet, ports []Port) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range ports {
		if !isInfraPort(p.DeviceOwner) {
			continue
		}
		for _, ip := range p.FixedIPs {
			prefix, ok := parseAddrV4AsPrefix(ip.IPAddress)
			if !ok {
				continue
			}
			out = append(out, prefix)
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
		out = append(out, prefix)
	}
	return out
}

// parsePrefixV4 parses a CIDR string and returns the prefix if it is
// IPv4. IPv6 prefixes return ok=false silently — they are filtered,
// not malformed. Malformed strings emit a warn-level log.
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
	return p, true
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
