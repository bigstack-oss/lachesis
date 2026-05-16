package metadata

import "github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"

// unknownTenantID is the `tenant_id` Prometheus label emitted when a
// VM MAC is not in the map. Mirrors `metrics.UnknownTenant{}` — both
// producers must emit the same string, because Prometheus `rate()`
// queries during cold-start span the transition from "unknown" to
// resolved project UUIDs.
const unknownTenantID = "unknown"

// Resolver implements `metrics.TenantResolver` against a
// [*ShardedMetadataMap]. It picks the VM-side MAC out of a
// [bpf.FlowKey] per the directional swap (CLAUDE.md "Critical
// Invariants" and bpf/telemetry.c `handle_packet`):
//
//   - INGRESS (VM sending):  vm_mac = key.SrcMac
//   - EGRESS  (VM receiving): vm_mac = key.DstMac
//
// On lookup miss it returns [unknownTenantID]; on hit, the entry's
// `ProjectID`. Safe for concurrent use (read-only).
type Resolver struct {
	m *ShardedMetadataMap
}

// NewResolver wraps m. m must outlive the Resolver.
func NewResolver(m *ShardedMetadataMap) *Resolver {
	return &Resolver{m: m}
}

// ResolveTenant satisfies the `metrics.TenantResolver` interface.
func (r *Resolver) ResolveTenant(key bpf.FlowKey) string {
	var vmMAC [6]uint8
	if key.Direction == bpf.DirectionIngress {
		vmMAC = key.SrcMac
	} else {
		vmMAC = key.DstMac
	}
	meta, ok := r.m.Lookup(bpf.MACKey(vmMAC))
	if !ok {
		return unknownTenantID
	}
	return meta.ProjectID
}
