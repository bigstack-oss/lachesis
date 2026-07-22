package metadata

import "github.com/bigstack-oss/lachesis/internal/bpf"

// Resolver implements `metrics.TenantResolver` against a
// [*ShardedMetadataMap]. It picks the VM-side MAC out of a
// [bpf.FlowKey] per the directional swap (CLAUDE.md "Critical
// Invariants" and bpf/telemetry.c `handle_packet`):
//
//   - INGRESS (VM sending):  vm_mac = key.SrcMac
//   - EGRESS  (VM receiving): vm_mac = key.DstMac
//
// On lookup miss it returns the [UnknownTenantID] / [NoExternalNetwork]
// sentinels; on hit, the entry's attribution fields with the
// external_network label resolved per flow ([FlowExternalLabel]: peer
// router-interface MAC first, per-VM attribution as the fallback).
// Safe for concurrent use (read-only).
type Resolver struct {
	m       *ShardedMetadataMap
	routers *RouterMACs
}

// NewResolver wraps m and routers; both must outlive the Resolver.
// routers may be nil (a resolver without per-flow router attribution —
// the per-VM fallback then always applies).
func NewResolver(m *ShardedMetadataMap, routers *RouterMACs) *Resolver {
	return &Resolver{m: m, routers: routers}
}

// VMMAC returns the VM-side MAC of key as a [bpf.MACKey] u64, applying
// the directional swap (CLAUDE.md "Critical Invariants" and
// bpf/telemetry.c `handle_packet`): on INGRESS the VM is the source, on
// EGRESS the destination. It is the single source of the swap rule —
// both [Resolver.Resolve] and the UnresolvedBuffer classifier
// key off it, so the "which MAC is the VM" decision lives in exactly
// one place.
func VMMAC(key bpf.FlowKey) uint64 {
	if key.Direction == bpf.DirectionIngress {
		return bpf.MACKey(key.SrcMac)
	}
	return bpf.MACKey(key.DstMac)
}

// Resolve satisfies the `metrics.TenantResolver` interface: one shard
// lookup yielding the tenant label, the per-server identity, and the
// zone-gated external-network label for key.
func (r *Resolver) Resolve(key bpf.FlowKey) Attribution {
	meta, ok := r.m.Lookup(VMMAC(key))
	if !ok {
		return Attribution{Tenant: UnknownTenantID, ExternalNetwork: NoExternalNetwork}
	}
	return Attribution{
		Tenant:          meta.ProjectID,
		ServerID:        meta.ServerID,
		PortID:          meta.PortID,
		ExternalNetwork: FlowExternalLabel(r.routers, meta.ExternalNetwork, key),
	}
}

// ExternalNetworkLabel applies the zone gate that keeps the
// external_network label meaningful and low-cardinality: only
// EXTERNAL-zone series carry a real network label; everything else —
// other zones, and external flows of a VM with no resolved external
// path — gets the [NoExternalNetwork] sentinel. It is the per-VM half
// of the label rule; every emitter labels through [FlowExternalLabel],
// which layers the per-flow router-MAC resolution on top of this gate.
func ExternalNetworkLabel(extNet string, zone bpf.ZoneCode) string {
	if zone != bpf.ZoneExternal || extNet == "" {
		return NoExternalNetwork
	}
	return extNet
}
