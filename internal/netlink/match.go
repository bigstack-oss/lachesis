package netlink

import "strings"

// ShouldAttach reports whether iface qualifies for telemetry attach:
// an exact match in explicit, or a prefix match in prefixes. Both may
// be empty, in which case nothing attaches.
//
// A prefix match on a veth is refused, and skip names why: an OVN
// metadata-proxy veth is named like a VM tap, and attaching it
// double-counts every VM's metadata traffic as tenant "unknown"
// (docs/architecture/edge-cases.md#tier-4--subtle-correctness, row 22).
// An explicit entry is the operator naming the link outright, so it
// attaches whatever its type. Nothing else is implicitly skipped.
func ShouldAttach(iface, linkType string, prefixes, explicit []string) (attach bool, skip string) {
	for _, name := range explicit {
		if iface == name {
			return true, ""
		}
	}
	if !matchesPrefix(iface, prefixes) {
		return false, ""
	}
	if linkType == linkTypeVeth {
		return false, skipReasonVeth
	}
	return true, ""
}

// matchesPrefix reports whether iface starts with any non-empty entry
// in prefixes. An empty prefix string is skipped, not treated as a
// wildcard. Shared by [ShouldAttach] and the metric-label classifier so
// the two never disagree about what counts as a prefix match.
func matchesPrefix(iface string, prefixes []string) bool {
	for _, p := range prefixes {
		if p != "" && strings.HasPrefix(iface, p) {
			return true
		}
	}
	return false
}
