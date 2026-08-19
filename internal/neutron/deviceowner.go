// deviceowner.go classifies Neutron ports by their `device_owner`
// string. [IsInfraPort] and [IsVMPort] partition the owner space;
// [IsComputePort], [IsTrunkSubport] and [IsKnownVMOwner] are narrower
// predicates over the same vocabulary.
//
// docs/architecture/trie-construction.md#port-classification-device_owner

package neutron

import "strings"

// IsInfraPort reports whether deviceOwner is in Neutron's reserved
// `network:` namespace, with one carve-out: `network:floatingip` is
// neither infra nor VM-like. Prefix-matched rather than allow-listed so
// deployment-specific and future owners classify without a code change.
// Misclassifying a VM port as INFRA corrupts SAME_TENANT billing.
//
// docs/architecture/trie-construction.md#port-classification-device_owner
func IsInfraPort(deviceOwner string) bool {
	if !strings.HasPrefix(deviceOwner, deviceOwnerNetworkPrefix) {
		return false
	}
	if deviceOwner == "network:floatingip" {
		return false
	}
	return true
}

// IsVMPort reports whether a port's MAC belongs in the kernel
// mac_tenant_map — i.e. tenant-VM traffic terminates here. Deliberately
// permissive: an unrecognised non-`network:` owner admits, because
// under-billing a real VM is worse than admitting a stray MAC.
//
// docs/architecture/trie-construction.md#port-classification-device_owner
func IsVMPort(deviceOwner string) bool {
	if deviceOwner == "" {
		return false
	}
	if strings.HasPrefix(deviceOwner, deviceOwnerNetworkPrefix) {
		return false
	}
	return true
}

// IsComputePort classifies a Neutron port as a Nova VM port. Nova
// writes `compute:<az-name>` as the device_owner — `compute:nova` is
// just the default availability-zone name — so the match is on the
// `compute:` prefix, never the literal. The static-route resolver's
// Step B VM-appliance branch dispatches on this predicate, and
// [IsKnownVMOwner] reuses it for its compute case.
func IsComputePort(deviceOwner string) bool {
	return strings.HasPrefix(deviceOwner, deviceOwnerComputePrefix)
}

// IsTrunkSubport reports whether deviceOwner is a trunk subport.
// Subports admit as VM-like, but their 802.1Q-tagged traffic fails the
// data plane's ethertype gate and passes uncounted — cold start warns
// when a snapshot contains any.
//
// docs/architecture/edge-cases.md#tier-1--hard-limits
func IsTrunkSubport(deviceOwner string) bool {
	return strings.HasPrefix(deviceOwner, deviceOwnerTrunkPrefix)
}

// IsKnownVMOwner reports whether deviceOwner is in the empirically
// confirmed VM-like set for OVN-Yoga. Stricter than [IsVMPort]: an
// unknown vendor or plugin owner admits there but fails here, which is
// what cold start warn-logs as drift. Classification never changes.
//
// docs/architecture/trie-construction.md#port-classification-device_owner
func IsKnownVMOwner(deviceOwner string) bool {
	switch {
	case IsComputePort(deviceOwner):
		return true
	case deviceOwner == "Octavia" || strings.HasPrefix(deviceOwner, "Octavia:"):
		return true
	case strings.HasPrefix(deviceOwner, "manila:"):
		return true
	case strings.HasPrefix(deviceOwner, "baremetal:"):
		return true
	case IsTrunkSubport(deviceOwner):
		return true
	case deviceOwner == "cube:mgr":
		return true
	}
	return false
}
