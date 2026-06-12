// deviceowner.go classifies Neutron ports by their `device_owner`
// string. [IsInfraPort] and [IsVMPort] partition the owner space —
// infra ports contribute /32 INFRA trie rows, VM-like ports admit
// their MAC into the kernel mac_tenant_map — [IsComputePort] matches
// Nova's `compute:<az>` namespace for the static-route resolver's
// VM-appliance branch, and [IsKnownVMOwner] is the stricter
// empirical allowlist used to warn-log drift. The trie builder that
// consumes the partition lives in trie.go.

package neutron

import "strings"

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

// IsComputePort classifies a Neutron port as a Nova VM port. Nova
// writes `compute:<az-name>` as the device_owner — `compute:nova` is
// just the default availability-zone name — so the match is on the
// `compute:` prefix, never the literal. The static-route resolver's
// Step B VM-appliance branch dispatches on this predicate, and
// [IsKnownVMOwner] reuses it for its compute case.
func IsComputePort(deviceOwner string) bool {
	return strings.HasPrefix(deviceOwner, deviceOwnerComputePrefix)
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
	case IsComputePort(deviceOwner):
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
