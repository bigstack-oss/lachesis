// lookup.go holds the read-side helpers the /debug pages use to
// resolve snapshot data into human-facing answers. Pure functions
// over Snapshot values — no I/O, no locks; callers hand in the
// atomically-swapped snapshot the agent retains.

package neutron

import "net/netip"

// ProjectName returns the Keystone project's name for id, or ""
// when no matching project is present (Keystone list unavailable or
// the project was deleted between syncs). Callers render the bare
// UUID in that case. Linear scan — projects are O(tens), so the
// constant factor beats a precomputed map.
func (s Snapshot) ProjectName(id string) string {
	for _, p := range s.Projects {
		if p.ID == id {
			return p.Name
		}
	}
	return ""
}

// LookupZone mirrors the kernel's lookup_zone for (tenant, ip):
// longest-prefix over per-tenant rows, then the global sentinel rows.
// The second return names which pass matched, for /debug.
//
// (nil, "") means no row matched at all, which a healthy trie makes
// impossible — treat it as a corrupt-trie signal. Linear scan: this is
// /debug-only, and the trie is hundreds of rows.
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

// LookupResource resolves an IP to its most-specific subnet, that
// subnet's network, and any port holding it as a fixed_ip. Each field
// is independently optional.
//
// A non-empty tenant scopes the search first, which is what
// disambiguates the shared private CIDRs almost every tenant defaults
// to; it falls back to the whole snapshot so an out-of-scope IP still
// surfaces something to investigate.
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

// LookupPortByMAC returns the first port with that MAC, plus its
// network. Case-insensitive, because Neutron emits both cases. Subnet
// is never populated — a port may span several. mac must already be
// canonical colon-separated form.
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
