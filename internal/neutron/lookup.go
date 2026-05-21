package neutron

import "net/netip"

// LookupZone returns the trie row the kernel's `lookup_zone` would
// match for (tenant, ip): longest-prefix match against per-tenant
// rules first, then a fallback against the global sentinel rules
// (TenantID == ""). The second return reports which pass produced
// the match — "tenant" or "global" — so /debug can show whether
// the row came from the tenant's own scope or the catchall.
//
// Returns (nil, "") only when the IP doesn't match any row at all,
// which is impossible against a healthy trie (Step-1 catchall
// covers 0.0.0.0/0). Treat (nil, _) as a corrupt-trie signal.
//
// The implementation is a linear scan — the trie is O(hundreds)
// of rows at production scale and this function is only invoked
// on demand from /debug/lookup. The kernel-side LPM is a real
// trie; this userspace mirror trades structure for simplicity.
func LookupZone(entries []TrieEntry, ip netip.Addr, tenant string) (*TrieEntry, string) {
	if tenant != "" {
		if hit := longestPrefixForTenant(entries, ip, tenant); hit != nil {
			return hit, "tenant"
		}
	}
	if hit := longestPrefixForTenant(entries, ip, ""); hit != nil {
		return hit, "global"
	}
	return nil, ""
}

// longestPrefixForTenant returns the entry whose TenantID matches
// tenant and whose Prefix contains ip with the longest prefix
// length. Ties are broken by encounter order (stable since
// BuildTrie sorts deterministically).
func longestPrefixForTenant(entries []TrieEntry, ip netip.Addr, tenant string) *TrieEntry {
	var best *TrieEntry
	bestBits := -1
	for i := range entries {
		e := &entries[i]
		if e.TenantID != tenant {
			continue
		}
		if !e.Prefix.Contains(ip) {
			continue
		}
		if e.Prefix.Bits() > bestBits {
			best = e
			bestBits = e.Prefix.Bits()
		}
	}
	return best
}

// LookupResource resolves an IP against the Neutron snapshot:
// the most-specific subnet whose CIDR contains it, that subnet's
// network, and any port that carries the IP as a fixed_ip.
//
// When tenant != "", the search runs first against subnets and
// ports whose ProjectID matches that tenant — this disambiguates
// shared private CIDRs (192.168.0.0/24 is the default for almost
// every Neutron tenant). On no per-tenant match the search falls
// back to the full snapshot so an IP outside the tenant's scope
// still surfaces *something* the operator can investigate.
//
// Returned ResourceMatch fields are independently optional — a
// known subnet's unallocated address resolves Subnet+Network with
// Port == nil; an IP outside every subnet returns the zero value.
//
// Linear-scan, suitable for /debug at production scale.
func LookupResource(snap *Snapshot, ip netip.Addr, tenant string) ResourceMatch {
	if snap == nil {
		return ResourceMatch{}
	}
	if tenant != "" {
		if m := lookupResourceScoped(snap, ip, tenant); m.Subnet != nil || m.Port != nil {
			return m
		}
	}
	return lookupResourceScoped(snap, ip, "")
}

// lookupResourceScoped is one pass of the resource search.
// tenant="" disables scoping (any owner matches); a non-empty
// tenant restricts to subnets and ports whose ProjectID equals
// tenant.
func lookupResourceScoped(snap *Snapshot, ip netip.Addr, tenant string) ResourceMatch {
	var m ResourceMatch

	bestBits := -1
	var bestSubnet *Subnet
	for i := range snap.Subnets {
		s := &snap.Subnets[i]
		if tenant != "" && s.ProjectID != tenant {
			continue
		}
		p, err := netip.ParsePrefix(s.CIDR)
		if err != nil {
			continue
		}
		if !p.Contains(ip) {
			continue
		}
		if p.Bits() > bestBits {
			bestBits = p.Bits()
			bestSubnet = s
		}
	}
	if bestSubnet != nil {
		m.Subnet = bestSubnet
		for i := range snap.Networks {
			if snap.Networks[i].ID == bestSubnet.NetworkID {
				m.Network = &snap.Networks[i]
				break
			}
		}
	}
	for i := range snap.Ports {
		if tenant != "" && snap.Ports[i].ProjectID != tenant {
			continue
		}
		for _, fip := range snap.Ports[i].FixedIPs {
			if fip.IPAddress == ip.String() {
				m.Port = &snap.Ports[i]
				break
			}
		}
		if m.Port != nil {
			break
		}
	}
	return m
}

// LookupPortByMAC returns the first port whose MACAddress equals
// mac (case-insensitive compare, since Neutron sometimes emits
// uppercase and sometimes lowercase forms). Returns the matched
// port + its network, or a zero ResourceMatch if no port carries
// that MAC. Subnet is not populated — a port may have multiple
// fixed_ips across multiple subnets, and there is no single
// answer.
//
// mac must already be in canonical colon-separated form; the
// caller is responsible for parse + format.
func LookupPortByMAC(snap *Snapshot, mac string) ResourceMatch {
	if snap == nil || mac == "" {
		return ResourceMatch{}
	}
	var m ResourceMatch
	for i := range snap.Ports {
		if !equalFoldASCII(snap.Ports[i].MACAddress, mac) {
			continue
		}
		m.Port = &snap.Ports[i]
		for j := range snap.Networks {
			if snap.Networks[j].ID == snap.Ports[i].NetworkID {
				m.Network = &snap.Networks[j]
				break
			}
		}
		return m
	}
	return m
}

// ResourceMatch is the result of looking up an IP or MAC against
// the Neutron snapshot. Any field may be nil — see [LookupResource]
// and [LookupPortByMAC] for which combinations are produced.
type ResourceMatch struct {
	Subnet  *Subnet
	Network *Network
	Port    *Port
}

// equalFoldASCII is a stripped-down strings.EqualFold for pure
// ASCII inputs (MAC addresses). Avoids the unicode tables — the
// input space here is hex digits + colons.
func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
