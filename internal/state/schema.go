// schema.go holds package state's pure-data value types: the per-flow
// Counter, the Snapshot Entry, the WAL Record, and the settled-
// accumulator key/record/mode types. The authoritative store
// GlobalState and the delta math that mutates these values live in
// state.go.

package state

import "github.com/bigstack-oss/lachesis/internal/bpf"

// Counter holds the per-flow cumulative state plus the last raw
// kernel reading needed for delta math. Mutated in place by
// [GlobalState.ApplyDelta] while the write lock is held.
type Counter struct {
	// Total is the agent-side cumulative — bytes and packets since
	// the flow was first observed, surviving kernel evictions and,
	// once a WAL is in place, agent restarts.
	Total bpf.FlowMetrics
	// LastEbpfRaw is the most recent raw value read from the kernel.
	// The next ApplyDelta computes Δ = current − LastEbpfRaw, then
	// updates LastEbpfRaw to current.
	LastEbpfRaw bpf.FlowMetrics
}

// Entry is the value type emitted by [GlobalState.Snapshot]: a
// (key, cumulative) pair safe to use after the RLock is released.
type Entry struct {
	Key   bpf.FlowKey
	Total bpf.FlowMetrics
}

// Record is the (Key, Counter) pair emitted by [GlobalState.SnapshotForWAL]
// and consumed by [GlobalState.Restore]. The Counter carries both
// Total and LastEbpfRaw so a WAL-restored state can compute deltas
// against the kernel's next reading without re-baselining.
//
// INVARIANT — no kernel-internal identifiers in the WAL.
//
// Record's only identifier is [bpf.FlowKey], which is intentionally
// free of the u32 `tenant_id` that the kernel maps key on (the
// userspace `internal/metadata.TenantInterner` re-allocates those
// u32s on every boot — see the FlowKey doc-comment). Adding any
// kernel-internal ID to Record would silently break WAL restore on
// restart: the same logical flow would re-key under a stale u32 and
// never merge with post-restart traffic. ProjectID strings are the
// only stable cross-boot tenant identifier and they live in
// [metadata.ShardedMetadataMap], not here.
type Record struct {
	Key     bpf.FlowKey
	Counter Counter
}

// TenantSettledKey identifies one settled-accumulator bucket. It is exactly
// the metric label tuple the Collector emits — the resolved tenant, the
// zone-gated external-network label, plus the flow key's zone and
// direction — because settling happens at the moment the finer
// flow-level identity (the MAC pair) stops being resolvable: the bytes
// are re-homed at the granularity that must stay monotonic. ExtNet is
// always the already-gated label (a network name, or the
// metadata.NoExternalNetwork sentinel) so a settled bucket lands in
// exactly the series its live flows occupied.
type TenantSettledKey struct {
	Tenant string
	ExtNet string
	Zone   bpf.ZoneCode
	Dir    bpf.Direction
}

// TenantSettledRecord is one settled bucket's cumulative totals, emitted by
// the snapshot methods and round-tripped through the WAL. TenantSettled
// buckets carry no LastEbpfRaw — they are past delta math by
// definition — and no LastSeenNs — recency belongs to live flows.
type TenantSettledRecord struct {
	Key     TenantSettledKey
	Bytes   uint64
	Packets uint64
}

// ServerSettledKey identifies one server-settled bucket — the server
// tier's fold absorber in the four-layer family hierarchy
// (docs/architecture/billing.md). Unlike [TenantSettledKey] it KEEPS the
// server dimension: it is exactly the lachesis_server_bytes_total label
// tuple, so a fold credits the same series the live flows occupied and
// the server series stays monotone for the server's whole lifetime — a
// multi-port server losing one port, a detached-then-reattached NIC, a
// port recreate. Bounded: buckets are released when their server leaves
// the Nova server list ([GlobalState.PruneServerSettled]), so a dead
// server's series simply ends.
type ServerSettledKey struct {
	ServerID string
	Tenant   string
	ExtNet   string
	Zone     bpf.ZoneCode
	Dir      bpf.Direction
}

// ServerSettledRecord is one server-settled bucket's cumulative totals,
// emitted by the snapshot methods and round-tripped through the WAL
// (additive schema v4). Like [TenantSettledRecord] it carries no delta-math
// or recency fields.
type ServerSettledRecord struct {
	Key     ServerSettledKey
	Bytes   uint64
	Packets uint64
}

// SettleMode selects what [GlobalState.Settle] does with a flow row
// after folding its Total into the settled accumulator. The right mode
// is decided by whether the row's kernel telemetry_map counters still
// exist — see the constants.
type SettleMode int

const (
	// SettleEvict deletes the folded row. Correct when the flow's
	// kernel counters are already gone (the ghost sweep deletes them
	// first), so nothing will feed the row again: a later reappearance
	// of the same key is a genuinely new flow whose kernel counter
	// restarts at zero and must re-baseline from first sight.
	SettleEvict SettleMode = iota
	// SettleRebase zeroes the folded row's Total but keeps the row and
	// its LastEbpfRaw. Correct when the kernel counters live on (a live
	// port changed tenant): the next ApplyDelta must count only bytes
	// arriving after the fold, not re-count the kernel cumulative that
	// was just settled.
	SettleRebase
)
