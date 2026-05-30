package netlink

import "strings"

// ShouldAttach reports whether an interface named iface qualifies
// for telemetry attach under the given allowlist. The match is:
//
//   - true if iface equals any entry in explicit (exact match), or
//   - true if iface starts with any entry in prefixes.
//
// Both inputs may be empty: explicit-only deployments leave
// prefixes nil; prefix-only deployments leave explicit nil. With
// both nil, the function returns false for any input, so the
// subscriber attaches to nothing.
//
// The function does not skip loopback, bridge, or other "obviously
// uninteresting" links — every match decision goes through the
// caller's configured allowlist. Skipping those by convention would
// be one more place to silently disagree with the operator.
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
