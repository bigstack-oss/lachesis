// Package state owns the agent's authoritative cumulative counters,
// keyed by [bpf.FlowKey]. It is the staging area between the
// [internal/scraper] (which feeds raw kernel readings) and the
// [internal/metrics] custom Collector (which emits cumulatives to
// Prometheus).
//
// # Lifecycle of an entry
//
// On first sight the scraper calls [GlobalState.ApplyDelta] with the
// raw kernel counter. The entry is created with that value as both
// Total and LastEbpfRaw; no delta is applied. This is the
// restart-without-WAL guard: re-seeing a flow on agent startup must
// not double-count the prior cumulative.
//
// On subsequent sightings delta = current − lastRaw, with a u64
// wraparound guard treating current<lastRaw as a kernel-side reset
// (kernel reboot or post-eviction re-creation). Total += delta;
// LastEbpfRaw = current. See [GlobalState.ApplyDelta] and
// docs/DESIGN.md §13.1.
//
// # Concurrency
//
// The map is guarded by a sync.RWMutex. The single scraper goroutine
// is the writer; the metrics Collector is the reader. Snapshot is a
// copy-out so the Collector can release the RLock before doing the
// (allocating) prometheus emission — holding the RLock across
// encoding would block the scraper for the duration of a Prometheus
// scrape.
package state

import (
	"sync"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
)

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

// GlobalState is the agent's authoritative flow-keyed counter store.
// See the package doc for invariants.
type GlobalState struct {
	mu     sync.RWMutex
	counts map[bpf.FlowKey]*Counter
}

// New returns an empty GlobalState.
func New() *GlobalState {
	return &GlobalState{counts: make(map[bpf.FlowKey]*Counter)}
}

// ApplyDelta integrates a raw kernel reading for one flow key. First
// sight of a key sets Total=LastEbpfRaw=raw (no delta). Subsequent
// readings increment Total by current−lastRaw, treating current<lastRaw
// as a kernel-side reset where current itself is the delta
// (Implementation Contract #5).
//
// Hot path: zero allocations after the first sighting of each key.
func (g *GlobalState) ApplyDelta(key bpf.FlowKey, raw bpf.FlowMetrics) {
	g.mu.Lock()
	c, ok := g.counts[key]
	if !ok {
		g.counts[key] = &Counter{Total: raw, LastEbpfRaw: raw}
		g.mu.Unlock()
		return
	}
	addDelta(&c.Total.Bytes, &c.LastEbpfRaw.Bytes, raw.Bytes)
	addDelta(&c.Total.Packets, &c.LastEbpfRaw.Packets, raw.Packets)
	if raw.LastSeenNs > c.Total.LastSeenNs {
		c.Total.LastSeenNs = raw.LastSeenNs
	}
	c.LastEbpfRaw.LastSeenNs = raw.LastSeenNs
	g.mu.Unlock()
}

// addDelta integrates a raw counter into a cumulative total.
// current < lastRaw is treated as a kernel-side reset: the new
// current is itself the delta, not (max_u64 − lastRaw + current).
func addDelta(total, lastRaw *uint64, current uint64) {
	if current >= *lastRaw {
		*total += current - *lastRaw
	} else {
		*total += current
	}
	*lastRaw = current
}

// Snapshot appends every (key, Total) pair to dst and returns the
// resulting slice. Reusing the prior return value keeps steady-state
// allocations at zero; capacity grows only when the flow count
// exceeds the prior peak.
//
// Holds the RLock for the full iteration (Implementation Contract #2).
func (g *GlobalState) Snapshot(dst []Entry) []Entry {
	g.mu.RLock()
	defer g.mu.RUnlock()
	for k, c := range g.counts {
		dst = append(dst, Entry{Key: k, Total: c.Total})
	}
	return dst
}

// Len returns the number of distinct flows currently tracked.
func (g *GlobalState) Len() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.counts)
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

// SnapshotForWAL appends every (key, Counter) pair to dst and returns
// the resulting slice. Same reuse contract as [GlobalState.Snapshot]:
// pass the prior return value to keep steady-state allocations at zero.
//
// Holds the RLock for the full iteration. The Counter is copied by
// value so the returned records are safe to use after the RLock is
// released, including across the (no-lock) marshal and flush phases
// of the WAL writer.
func (g *GlobalState) SnapshotForWAL(dst []Record) []Record {
	g.mu.RLock()
	defer g.mu.RUnlock()
	for k, c := range g.counts {
		dst = append(dst, Record{Key: k, Counter: *c})
	}
	return dst
}

// Restore seeds the map from records previously written to the WAL.
// Intended to run once at boot before any scraper or collector
// goroutine starts; takes the write lock defensively. Existing keys
// are overwritten, matching the "WAL is the source of truth on
// boot" contract.
func (g *GlobalState) Restore(records []Record) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for i := range records {
		r := records[i]
		c := r.Counter
		g.counts[r.Key] = &c
	}
}
