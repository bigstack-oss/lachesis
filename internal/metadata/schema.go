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
	// ServerID is the Neutron port's device_id — the Nova instance
	// UUID for VM ports. Emitted as the `server_id` label on the
	// per-server metric family (docs/DESIGN.md §11.5); empty when the
	// port carries no device binding.
	ServerID string
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
	// project that owns the Amphora itself (docs/DESIGN.md §7).
	IsAmphora bool
	// DeleteAt is zero for live entries. The 60 s Lingering Ghost
	// (docs/DESIGN.md §3.3) sets it to `now+60s` on a Neutron
	// `port.deleted` / `subnet.deleted` event; the GC drops the
	// entry once `DeleteAt < now`.
	DeleteAt time.Time
}

// GhostGrace is the lingering-ghost window (docs/DESIGN.md §3.3):
// [ShardedMetadataMap.MarkDelete] callers set DeleteAt = now + GhostGrace,
// and the GC sweeps the entry once it elapses. The single source of truth
// for the value every MarkDelete caller uses (the Neutron reconcile and,
// later, the Kafka consumer); the effective grace is GhostGrace plus up to
// one GC sweep interval.
const GhostGrace = 60 * time.Second

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
	ExternalNetwork string
}
