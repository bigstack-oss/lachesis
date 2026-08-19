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

// Record is the (Key, Counter) pair the WAL round-trips. The Counter
// carries both Total and LastEbpfRaw, so a restored state computes
// deltas against the kernel's next reading without re-baselining.
//
// INVARIANT — no kernel-internal identifiers in the WAL. FlowKey is
// deliberately free of the u32 tenant_id, which is re-interned every
// boot; adding any such ID re-keys the flow on restart and it never
// merges with post-restart traffic.
type Record struct {
	Key     bpf.FlowKey
	Counter Counter
}

// TenantSettledKey identifies one settled bucket. It is exactly the
// tenant tier's metric label tuple, so a fold lands in the same series
// the live flows occupied. ExtNet must already be the gated label.
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

// ServerSettledKey identifies one server-settled bucket. Unlike
// [TenantSettledKey] it KEEPS the server dimension — it is exactly the
// lachesis_server_bytes_total tuple, which is what makes a server's
// series monotone across a lost port or a re-created NIC. Released when
// the server leaves the Nova list.
//
// docs/architecture/billing.md
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

// TotalSettledKey identifies one total-settled bucket. The total family
// is DERIVED from the tenant tier, so a released tenant bucket folds
// here instead of vanishing — otherwise the immortal total series would
// decrease. Bounded by construction: zones × external networks × 2.
//
// docs/architecture/billing.md
type TotalSettledKey struct {
	ExtNet string
	Zone   bpf.ZoneCode
	Dir    bpf.Direction
}

// TotalSettledRecord is one total-settled bucket's cumulative totals,
// emitted by the snapshot methods and round-tripped through the WAL
// (additive schema v5). Like [TenantSettledRecord] it carries no
// delta-math or recency fields.
type TotalSettledRecord struct {
	Key     TotalSettledKey
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
