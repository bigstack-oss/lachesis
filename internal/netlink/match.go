package netlink

import "strings"

// ShouldAttach reports whether iface qualifies for telemetry attach:
// an exact match in explicit, or a prefix match in prefixes. Both may
// be empty, in which case nothing attaches.
//
// It deliberately does NOT skip loopback, bridges or other "obviously
// uninteresting" links — every decision goes through the operator's
// allowlist, so there is no second place to disagree with them.
func ShouldAttach(iface string, prefixes, explicit []string) bool {
	for _, name := range explicit {
		if iface == name {
			return true
		}
	}
	return matchesPrefix(iface, prefixes)
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
