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
// # Settled bytes
//
// A flow row's tenant is late-bound: the Collector resolves the MAC at
// scrape time. When that binding is about to disappear (a dead VM's
// metadata swept, a live port re-pointed at a new tenant), the flow's
// cumulative would silently re-bucket — so the owner of that moment
// calls [GlobalState.Settle], which folds the row's Total into a
// per-(tenant, zone, direction) settled accumulator that the Collector
// adds to its emission forever after. Settled buckets only grow; they
// are what keeps a tenant's exposed series monotonic across VM churn
// (docs/DESIGN.md §3.5, §13.1 Contract 7).
//
// # Concurrency
//
// The maps are guarded by one sync.RWMutex. The single scraper
// goroutine is the writer; the metrics Collector is the reader.
// Snapshot is a copy-out so the Collector can release the RLock before
// doing the (allocating) prometheus emission — holding the RLock
// across encoding would block the scraper for the duration of a
// Prometheus scrape.
package state

import (
	"sync"

	"github.com/bigstack-oss/lachesis/internal/bpf"
)

// GlobalState is the agent's authoritative flow-keyed counter store,
// plus the settled-bytes accumulator that keeps a tenant's exposed
// series monotonic after its flows stop resolving (docs/DESIGN.md
// §3.5). See the package doc for invariants.
//
// Both maps live under the one mutex deliberately: [GlobalState.Settle]
// moves value between them, and every reader (the Collector's combined
// snapshot, the WAL's combined snapshot) must observe the two sides
// consistently — a snapshot taken between "row deleted" and "settled
// credited" would lose the folded bytes for that scrape or flush, and
// the reverse order would double-count them.
type GlobalState struct {
	mu      sync.RWMutex
	counts  map[bpf.FlowKey]*Counter
	settled map[SettledKey]*settledTotal
}

// settledTotal is the mutable per-bucket accumulator behind the
// settled map. SettledRecord is its copy-out form.
type settledTotal struct {
	bytes   uint64
	packets uint64
}

// New returns an empty GlobalState.
func New() *GlobalState {
	return &GlobalState{
		counts:  make(map[bpf.FlowKey]*Counter),
		settled: make(map[SettledKey]*settledTotal),
	}
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
	AddDelta(&c.Total.Bytes, &c.LastEbpfRaw.Bytes, raw.Bytes)
	AddDelta(&c.Total.Packets, &c.LastEbpfRaw.Packets, raw.Packets)
	if raw.LastSeenNs > c.Total.LastSeenNs {
		c.Total.LastSeenNs = raw.LastSeenNs
	}
	c.LastEbpfRaw.LastSeenNs = raw.LastSeenNs
	g.mu.Unlock()
}

// Add folds m into the cumulative total for key without delta math:
// Total grows by m's bytes/packets and tracks the max LastSeenNs. It is
// the entry point for already-computed deltas — the UnresolvedBuffer
// folds an expired flow's accumulated total into a synthetic
// "unknown"-tenant key this way (docs/DESIGN.md §3.2). Unlike
// [GlobalState.ApplyDelta] it never reads or writes LastEbpfRaw, so a
// key only ever touched by Add stays monotonic: its series can only
// rise, so rate() never goes negative. Callers must not mix Add and
// ApplyDelta on the same key.
func (g *GlobalState) Add(key bpf.FlowKey, m bpf.FlowMetrics) {
	g.mu.Lock()
	c, ok := g.counts[key]
	if !ok {
		g.counts[key] = &Counter{Total: m}
		g.mu.Unlock()
		return
	}
	c.Total.Bytes += m.Bytes
	c.Total.Packets += m.Packets
	if m.LastSeenNs > c.Total.LastSeenNs {
		c.Total.LastSeenNs = m.LastSeenNs
	}
	g.mu.Unlock()
}

// Resolve credits a late-bound flow whose VM MAC just became known: it
// folds total (the bytes the UnresolvedBuffer accumulated while the MAC
// was unknown) into the flow's GlobalState total, and sets LastEbpfRaw
// to lastRaw — the kernel cumulative the buffer last observed. The next
// [GlobalState.ApplyDelta] for this key then counts only bytes that
// arrive after the hand-off (current − lastRaw), never re-counting what
// total already captured. Omitting the LastEbpfRaw write-back is the
// classic double-count documented in docs/DESIGN.md §3.2.
//
// First sight of the key is the expected case — a buffered flow is, by
// the Classifier's known/unknown split, never simultaneously in
// GlobalState. The merge branch is defensive only.
func (g *GlobalState) Resolve(key bpf.FlowKey, total, lastRaw bpf.FlowMetrics) {
	g.mu.Lock()
	defer g.mu.Unlock()
	c, ok := g.counts[key]
	if !ok {
		g.counts[key] = &Counter{Total: total, LastEbpfRaw: lastRaw}
		return
	}
	c.Total.Bytes += total.Bytes
	c.Total.Packets += total.Packets
	if total.LastSeenNs > c.Total.LastSeenNs {
		c.Total.LastSeenNs = total.LastSeenNs
	}
	c.LastEbpfRaw = lastRaw
}

// AddDelta integrates a raw counter into a cumulative total.
// current < lastRaw is treated as a kernel-side reset: the new
// current is itself the delta, not (max_u64 − lastRaw + current)
// (Implementation Contract #5, the u64 wraparound guard). Exported so
// the UnresolvedBuffer (internal/unresolved) computes per-scrape deltas
// for buffered flows with the identical guard rather than a second copy
// that could drift.
func AddDelta(total, lastRaw *uint64, current uint64) {
	if current >= *lastRaw {
		*total += current - *lastRaw
	} else {
		*total += current
	}
	*lastRaw = current
}

// Settle folds every flow row that resolve maps to an attribution into
// the settled accumulator, under one write-lock critical section: for
// each row where resolve(key) returns (tenant, extNet, true), Total's
// bytes and packets are added to the (tenant, extNet, key.DstZone,
// key.Direction) settled bucket, and the row is then evicted or rebased
// per mode (see [SettleMode]). Rows where resolve returns false are
// untouched. Returns the number of rows folded.
//
// extNet must be the already-gated external_network label for that row
// (metadata.ExternalNetworkLabel over the dying attribution and the
// row's zone) so the fold lands in exactly the series the live flow
// occupied.
//
// Settle is how a flow's bytes survive the death of their attribution:
// callers invoke it at the last moment the attribution is still
// knowable — the ghost sweep just before it deletes a dead MAC's
// metadata, the reconciler just before it re-points a live MAC at a new
// tenant or external network. The exposed per-tenant aggregate is
// unchanged by the fold (value moves between the two maps inside one
// critical section), which is exactly the §13.1 Contract 7 monotonicity
// guarantee.
func (g *GlobalState) Settle(mode SettleMode, resolve func(bpf.FlowKey) (tenant, extNet string, ok bool)) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	folded := 0
	for k, c := range g.counts {
		tenant, extNet, ok := resolve(k)
		if !ok {
			continue
		}
		sk := SettledKey{Tenant: tenant, ExtNet: extNet, Zone: k.DstZone, Dir: k.Direction}
		t := g.settled[sk]
		if t == nil {
			t = &settledTotal{}
			g.settled[sk] = t
		}
		t.bytes += c.Total.Bytes
		t.packets += c.Total.Packets
		if mode == SettleEvict {
			delete(g.counts, k)
		} else {
			c.Total.Bytes = 0
			c.Total.Packets = 0
		}
		folded++
	}
	return folded
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

// SnapshotWithSettled appends every live flow to flows and every
// settled bucket to settled, under ONE RLock — the Collector's read
// path. Atomicity with respect to [GlobalState.Settle] is the point:
// two separate snapshots would let a concurrent fold move value
// between them, and the scrape would double-count (live then settled)
// or drop (settled then live) the folded bytes for one exposure —
// either way the next scrape breaks series monotonicity. Both slices
// follow the [GlobalState.Snapshot] reuse contract.
func (g *GlobalState) SnapshotWithSettled(flows []Entry, settled []SettledRecord) ([]Entry, []SettledRecord) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	for k, c := range g.counts {
		flows = append(flows, Entry{Key: k, Total: c.Total})
	}
	for k, t := range g.settled {
		settled = append(settled, SettledRecord{Key: k, Bytes: t.bytes, Packets: t.packets})
	}
	return flows, settled
}

// Len returns the number of distinct flows currently tracked.
func (g *GlobalState) Len() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.counts)
}

// SnapshotForWAL appends every (key, Counter) pair to flows and every
// settled bucket to settled, under ONE RLock, and returns both slices.
// Same reuse contract as [GlobalState.Snapshot]: pass the prior return
// values to keep steady-state allocations at zero.
//
// The combined walk exists for the same atomicity-against-Settle
// reason as [GlobalState.SnapshotWithSettled]: a WAL snapshot torn
// across a fold would persist the folded bytes twice or not at all,
// and a crash would make that permanent. Values are copied out so the
// records are safe to use after the RLock is released, including
// across the (no-lock) marshal and flush phases of the WAL writer.
func (g *GlobalState) SnapshotForWAL(flows []Record, settled []SettledRecord) ([]Record, []SettledRecord) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	for k, c := range g.counts {
		flows = append(flows, Record{Key: k, Counter: *c})
	}
	for k, t := range g.settled {
		settled = append(settled, SettledRecord{Key: k, Bytes: t.bytes, Packets: t.packets})
	}
	return flows, settled
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

// RestoreSettled seeds the settled accumulator from records previously
// written to the WAL. Same contract as [GlobalState.Restore]: boot-time
// only, existing buckets overwritten.
func (g *GlobalState) RestoreSettled(records []SettledRecord) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, r := range records {
		g.settled[r.Key] = &settledTotal{bytes: r.Bytes, packets: r.Packets}
	}
}

// SettledLen returns the number of settled buckets currently held.
func (g *GlobalState) SettledLen() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.settled)
}
