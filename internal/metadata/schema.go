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
// docs/architecture/data-structures.md#userspace-structures also enumerates a `VMName` field for log /
// dashboard enrichment. It is omitted here until a consumer arrives
// (likely a `/debug` endpoint), to keep the set of immutable fields
// minimal.
type TenantMeta struct {
	// ProjectID is the Keystone project UUID (e.g.
	// "8e1b...c4f2"). It is emitted as the `tenant_id` Prometheus
	// label and is the user-visible billing identity.
	ProjectID string
	// ServerID is the Neutron port's device_id — the Nova instance
	// UUID for VM ports. Emitted as the `server_id` label on the
	// per-server metric family (docs/architecture/billing.md); empty when the
	// port carries no device binding.
	ServerID string
	// PortID is the Neutron port UUID. Emitted as the `port_id` label on
	// the per-server family so a server's traffic is broken out per port
	// (docs/architecture/billing.md); consumers aggregate back to
	// server_id. A MAC maps to exactly one port, so it is stable for the
	// life of the MAC — a recreated port is a new MAC, hence a new series.
	PortID string
	// ExternalNetwork is the human-facing label of the external
	// network this VM's egress leaves through — its floating IP's
	// network, or its router's external gateway network (network name,
	// falling back to ID when the name is empty). Empty when the VM has
	// no external path. Only EXTERNAL-zone series carry it; see
	// [ExternalNetworkLabel] for the zone gate every emitter applies.
	ExternalNetwork string
	// IsAmphora marks an Octavia load-balancer Amphora port. The
	// per-packet hot path branches on this flag to attribute LB
	// traffic to the load-balancer owner rather than the admin
	// project that owns the Amphora itself (docs/architecture/scenarios.md).
	IsAmphora bool
	// DeleteAt is zero for live entries. The Lingering Ghost window
	// (docs/architecture/data-structures.md#lingering-ghost) sets it on a Neutron `port.deleted` /
	// `subnet.deleted` event: MarkDelete callers use now + the live
	// `gc.ghost_grace` tunable (default 60s — internal/tunables), and
	// the GC drops the entry once `DeleteAt < now`.
	DeleteAt time.Time
}

// SameAttribution reports whether two metas carry the same attribution
// identity — every field EXCEPT the lifecycle ones (DeleteAt). It is
// the reconcile change-detection's single comparison point: a change in
// any attribution field must settle the MAC's history under the old
// binding before the new one is published (docs/architecture/data-structures.md#settled-bytes).
//
// Deliberately implemented as a whole-struct compare with lifecycle
// fields zeroed, NOT a field list: a field added to TenantMeta is
// attribution-compared BY DEFAULT, which fails safe (a spurious settle
// is sum-invariant and idempotent; a missed one silently mislabels — the
// stale-port_id bug this replaced). A new LIFECYCLE field must be zeroed
// here and classified in the schema guard test, which fails on any
// unclassified field.
func (m TenantMeta) SameAttribution(o TenantMeta) bool {
	m.DeleteAt = time.Time{}
	o.DeleteAt = time.Time{}
	return m == o
}

// numShards is the fixed shard count. Must be a power of two so the
// `mac & (numShards-1)` index is a single AND.
const numShards = 64

// TenantIDUnset and UnknownTenantID are the two "no tenant" sentinels
// of this package, kept together because they describe the same
// absence on two sides:
//
//   - TenantIDUnset is the kernel-facing u32 sentinel: the
//     [TenantInterner] result for an empty ProjectID. Real interned
//     IDs start at 1 so the zero value of a `uint32` field never
//     collides with a valid tenant.
//   - UnknownTenantID is the userspace-facing `tenant_id` Prometheus
//     label emitted when a VM MAC is not in the map. It is the single
//     source of truth for the label: `metrics.UnknownTenant{}` returns
//     it too, because Prometheus `rate()` queries during cold-start
//     span the transition from "unknown" to resolved project UUIDs,
//     so every producer must emit the same string. It is exported
//     from this package (not metrics) because metadata must not
//     import metrics (L2 → L4).
const (
	TenantIDUnset   uint32 = 0
	UnknownTenantID        = "unknown"
)

// NoExternalNetwork is the `external_network` label sentinel for series
// that have no external network: every non-EXTERNAL zone, and
// EXTERNAL-zone traffic from a VM with no resolved external path.
// Prometheus requires a consistent label set per metric, so the label is
// always present and this is its "absent" value. Single source of truth
// for the same reason as [UnknownTenantID]: it lives here (not metrics)
// because metadata must not import metrics (L2 → L4).
const NoExternalNetwork = "none"

// Attribution is everything the metrics Collector resolves per flow at
// scrape time: the tenant label, the per-server export identity, and the
// zone-gated external-network label. Returned by value — the Collector
// calls this on every live row inside Collect, so it must not allocate.
type Attribution struct {
	Tenant          string
	ServerID        string
	PortID          string
	ExternalNetwork string
}
