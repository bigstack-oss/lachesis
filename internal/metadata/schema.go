// schema.go gathers package metadata's package-level constants and the
// TenantMeta data type. The behavioural stores that hold these values —
// ShardedMetadataMap (metadata.go), TenantInterner (interner.go), and
// Resolver (resolver.go) — live alongside their methods.

package metadata

import "time"

// TenantMeta is the userspace metadata associated with a single VM
// MAC. Once stored in a [ShardedMetadataMap] it must be treated as
// immutable — see the package doc, invariant (1).
//
// docs/DESIGN.md §3.2 also enumerates a `VMName` field for log /
// dashboard enrichment. It is omitted here until a consumer arrives
// (likely a `/debug` endpoint), to keep the set of immutable fields
// minimal.
type TenantMeta struct {
	// ProjectID is the Keystone project UUID (e.g.
	// "8e1b...c4f2"). It is emitted as the `tenant_id` Prometheus
	// label and is the user-visible billing identity.
	ProjectID string
	// IsAmphora marks an Octavia load-balancer Amphora port. The
	// per-packet hot path branches on this flag to attribute LB
	// traffic to the load-balancer owner rather than the admin
	// project that owns the Amphora itself (docs/DESIGN.md §7).
	IsAmphora bool
	// DeleteAt is zero for live entries. The 60 s Lingering Ghost
	// (docs/DESIGN.md §3.3) sets it to `now+60s` on a Neutron
	// `port.deleted` / `subnet.deleted` event; the GC drops the
	// entry once `DeleteAt < now`.
	DeleteAt time.Time
}

// numShards is the fixed shard count. Must be a power of two so the
// `mac & (numShards-1)` index is a single AND.
const numShards = 64

// TenantIDUnset and unknownTenantID are the two "no tenant" sentinels
// of this package, kept together because they describe the same
// absence on two sides:
//
//   - TenantIDUnset is the kernel-facing u32 sentinel: the
//     [TenantInterner] result for an empty ProjectID. Real interned
//     IDs start at 1 so the zero value of a `uint32` field never
//     collides with a valid tenant.
//   - unknownTenantID is the userspace-facing `tenant_id` Prometheus
//     label emitted when a VM MAC is not in the map. It mirrors
//     `metrics.UnknownTenant{}` — both producers must emit the same
//     string, because Prometheus `rate()` queries during cold-start
//     span the transition from "unknown" to resolved project UUIDs.
const (
	TenantIDUnset   uint32 = 0
	unknownTenantID        = "unknown"
)
