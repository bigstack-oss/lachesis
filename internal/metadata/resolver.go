package metadata

import "github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"

// Resolver implements `metrics.TenantResolver` against a
// [*ShardedMetadataMap]. It picks the VM-side MAC out of a
// [bpf.FlowKey] per the directional swap (CLAUDE.md "Critical
// Invariants" and bpf/telemetry.c `handle_packet`):
//
//   - INGRESS (VM sending):  vm_mac = key.SrcMac
//   - EGRESS  (VM receiving): vm_mac = key.DstMac
//
// On lookup miss it returns [UnknownTenantID]; on hit, the entry's
// `ProjectID`. Safe for concurrent use (read-only).
type Resolver struct {
	m *ShardedMetadataMap
}

// NewResolver wraps m. m must outlive the Resolver.
func NewResolver(m *ShardedMetadataMap) *Resolver {
	return &Resolver{m: m}
}

// VMMAC returns the VM-side MAC of key as a [bpf.MACKey] u64, applying
// the directional swap (CLAUDE.md "Critical Invariants" and
// bpf/telemetry.c `handle_packet`): on INGRESS the VM is the source, on
// EGRESS the destination. It is the single source of the swap rule —
// both [Resolver.ResolveTenant] and the UnresolvedBuffer classifier
// key off it, so the "which MAC is the VM" decision lives in exactly
// one place.
func VMMAC(key bpf.FlowKey) uint64 {
	if key.Direction == bpf.DirectionIngress {
		return bpf.MACKey(key.SrcMac)
	}
	return bpf.MACKey(key.DstMac)
}

// ResolveTenant satisfies the `metrics.TenantResolver` interface.
func (r *Resolver) ResolveTenant(key bpf.FlowKey) string {
	meta, ok := r.m.Lookup(VMMAC(key))
	if !ok {
		return UnknownTenantID
	}
	return meta.ProjectID
}
