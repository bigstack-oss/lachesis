// schema.go holds package state's pure-data value types: the per-flow
// Counter, the Snapshot Entry, and the WAL Record. The authoritative
// store GlobalState and the delta math that mutates these values live in
// state.go.

package state

import "github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"

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
