package neutron

import "github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"

// zoneFor classifies a destination network from the source tenant's
// perspective. Per docs/DESIGN.md §5.3.
//
// The check order is significant: external first, then shared, then
// the owner comparison. External wins over shared because some
// deployments mark a public FIP pool with both flags — traffic to
// those CIDRs is leaving the cloud and must classify as EXTERNAL.
// Shared wins over the owner comparison so that a shared network
// owned by the source tenant still emits SHARED; the trie cannot
// resolve per-VM ownership inside a shared CIDR, so labelling those
// flows SAME would systematically under-bill the owner's traffic to
// non-owner VMs attached to the same shared network. The MAC-first
// hot path classifies intra-tenant L2 traffic on shared networks as
// SAME_TENANT exactly; SHARED labels the L3-routed-fallback case.
func zoneFor(ownerTenant, sourceTenant string, network Network) bpf.ZoneCode {
	switch {
	case network.IsExternal:
		return bpf.ZoneExternal
	case network.Shared:
		return bpf.ZoneShared
	case ownerTenant == sourceTenant:
		return bpf.ZoneSameTenant
	default:
		return bpf.ZoneOtherTenant
	}
}
