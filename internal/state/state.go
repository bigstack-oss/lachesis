// Package state owns the agent's authoritative cumulative counters,
// keyed by [bpf.FlowKey] — the staging area between the scraper, which
// feeds raw kernel readings, and the metrics Collector, which emits
// cumulatives to Prometheus.
//
// Three invariants a caller must not break:
//
//   - Delta math compares the entry-identity stamp, never counter
//     magnitudes. See [GlobalState.ApplyDelta].
//   - A row whose attribution is about to change or die is folded via
//     [GlobalState.Settle] first, or its whole history re-buckets at
//     the next scrape.
//   - Every reader takes one lock across live rows AND settled buckets.
//     A snapshot torn across a fold double-counts or drops the bytes.
//
// docs/architecture/contracts.md#required-contracts
package state

import (
	"sync"

	"github.com/bigstack-oss/lachesis/internal/bpf"
)

// GlobalState is the agent's authoritative flow-keyed counter store
// plus the settled-bytes accumulators that keep an exposed series
// monotone after its flows stop resolving. All maps live under one
// mutex: Settle moves value between them, and a reader that saw only
// one side would lose or double-count the folded bytes.
//
// docs/architecture/data-structures.md#settled-bytes
type GlobalState struct {
	mu            sync.RWMutex
	counts        map[bpf.FlowKey]*Counter
	tenantSettled map[TenantSettledKey]*settledTotal
	// serverSettled is the server tier's fold absorber, credited in the
	// same critical section as settled and released only when its
	// server leaves the Nova list.
	serverSettled map[ServerSettledKey]*settledTotal
	// totalSettled is the total tier's fold absorber: the total family
	// is derived (Σ tenant tier at Collect), so a tenant-settled bucket
	// released by [GlobalState.PruneTenantSettled] folds its value here
	// — in the same critical section — or the immortal total series
	// would dip by the dead project's lifetime bytes. Never pruned: the
	// total tier has no owner to die with.
	totalSettled map[TotalSettledKey]*settledTotal
}

// settledTotal is the mutable per-bucket accumulator behind the
// settled and serverSettled maps. TenantSettledRecord / ServerSettledRecord
// are the copy-out forms.
type settledTotal struct {
	bytes   uint64
	packets uint64
}

// New returns an empty GlobalState.
func New() *GlobalState {
	return &GlobalState{
		counts:        make(map[bpf.FlowKey]*Counter),
		tenantSettled: make(map[TenantSettledKey]*settledTotal),
		serverSettled: make(map[ServerSettledKey]*settledTotal),
		totalSettled:  make(map[TotalSettledKey]*settledTotal),
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
	switch {
	case c.LastEbpfRaw.CreatedNs == 0:
		// Identity unknown: a v6 WAL restore (the field predates schema
		// v7) or a first sighting seeded before the stamp existed. Fall
		// back to the value guard for this one observation rather than
		// assume a reset — assuming would re-count the whole cumulative
		// of a pinned map that survived the restart. Adopt the kernel's
		// stamp below so every later scrape compares identity.
		AddDelta(&c.Total.Bytes, &c.LastEbpfRaw.Bytes, raw.Bytes)
		AddDelta(&c.Total.Packets, &c.LastEbpfRaw.Packets, raw.Packets)
	case raw.CreatedNs != c.LastEbpfRaw.CreatedNs:
		// A DIFFERENT entry now occupies this key: the one our baseline
		// described was destroyed (evicted, or lost with an unpinned
		// map) and the kernel counted `raw` from zero. Take it whole —
		// diffing against the dead baseline is what silently discarded
		// traffic before (lachesis#287).
		c.Total.Bytes += raw.Bytes
		c.Total.Packets += raw.Packets
		c.LastEbpfRaw.Bytes = raw.Bytes
		c.LastEbpfRaw.Packets = raw.Packets
	default:
		AddDelta(&c.Total.Bytes, &c.LastEbpfRaw.Bytes, raw.Bytes)
		AddDelta(&c.Total.Packets, &c.LastEbpfRaw.Packets, raw.Packets)
	}
	if raw.LastSeenNs > c.Total.LastSeenNs {
		c.Total.LastSeenNs = raw.LastSeenNs
	}
	c.LastEbpfRaw.LastSeenNs = raw.LastSeenNs
	c.LastEbpfRaw.CreatedNs = raw.CreatedNs
	g.mu.Unlock()
}

// Add folds m into key's cumulative without delta math, for
// already-computed totals (the UnresolvedBuffer's fold to "unknown").
// It never touches LastEbpfRaw, so a key only ever passed to Add stays
// monotone. Never mix Add and ApplyDelta on one key.
//
// docs/architecture/data-structures.md#userspace-structures
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

// Resolve credits a late-bound flow whose MAC just became known: it
// folds the buffer's accumulated total in and sets LastEbpfRaw to
// lastRaw. Omitting that write-back is the classic double-count — the
// next ApplyDelta re-counts everything total already captured.
//
// docs/architecture/data-structures.md#userspace-structures
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

// Settle folds every resolvable row into the settled accumulators and
// evicts or rebases it per mode, in ONE critical section so the exposed
// aggregate never changes across the fold. Call it at the last moment
// the attribution is knowable. extNet must already be the gated label.
//
// docs/architecture/contracts.md#required-contracts
func (g *GlobalState) Settle(mode SettleMode, resolve func(bpf.FlowKey) (tenant, extNet, server string, ok bool)) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	folded := 0
	for k, c := range g.counts {
		tenant, extNet, server, ok := resolve(k)
		if !ok {
			continue
		}
		sk := TenantSettledKey{Tenant: tenant, ExtNet: extNet, Zone: k.DstZone, Dir: k.Direction}
		t := g.tenantSettled[sk]
		if t == nil {
			t = &settledTotal{}
			g.tenantSettled[sk] = t
		}
		t.bytes += c.Total.Bytes
		t.packets += c.Total.Packets
		// Credit the same bytes to the server tier in this critical
		// section; a torn fold over/under-exposes one scrape. Rows with
		// no server_id have no server series.
		if server != "" {
			ck := ServerSettledKey{ServerID: server, Tenant: tenant, ExtNet: extNet, Zone: k.DstZone, Dir: k.Direction}
			sc := g.serverSettled[ck]
			if sc == nil {
				sc = &settledTotal{}
				g.serverSettled[ck] = sc
			}
			sc.bytes += c.Total.Bytes
			sc.packets += c.Total.Packets
		}
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

// SnapshotWithSettled appends live flows and settled buckets under ONE
// RLock — the Collector's read path. Two snapshots would let a
// concurrent fold move value between them, double-counting or dropping
// the bytes for that exposure. Both slices follow the
// [GlobalState.Snapshot] reuse contract.
func (g *GlobalState) SnapshotWithSettled(flows []Entry, settled []TenantSettledRecord, serverSettled []ServerSettledRecord, totalSettled []TotalSettledRecord) ([]Entry, []TenantSettledRecord, []ServerSettledRecord, []TotalSettledRecord) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	for k, c := range g.counts {
		flows = append(flows, Entry{Key: k, Total: c.Total})
	}
	for k, t := range g.tenantSettled {
		settled = append(settled, TenantSettledRecord{Key: k, Bytes: t.bytes, Packets: t.packets})
	}
	// Server-settled rides the SAME RLock as live+settled: the server
	// family's emitted value is live+serverSettled per tuple, and a fold
	// moving bytes rows→bucket must never be observable half-done across
	// a scrape (Contract 7).
	//
	// Full rationale: docs/architecture/contracts.md#required-contracts
	for k, t := range g.serverSettled {
		serverSettled = append(serverSettled, ServerSettledRecord{Key: k, Bytes: t.bytes, Packets: t.packets})
	}
	// Total-settled likewise: a tenant prune moving value bucket→bucket
	// must never be observable half-done across a scrape.
	for k, t := range g.totalSettled {
		totalSettled = append(totalSettled, TotalSettledRecord{Key: k, Bytes: t.bytes, Packets: t.packets})
	}
	return flows, settled, serverSettled, totalSettled
}

// Len returns the number of distinct flows currently tracked.
func (g *GlobalState) Len() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.counts)
}

// SnapshotForWAL appends flows and settled buckets under ONE RLock;
// same reuse contract as [GlobalState.Snapshot]. The combined walk is
// for atomicity against Settle, as in [GlobalState.SnapshotWithSettled]
// — a torn WAL snapshot persists the folded bytes twice or not at all,
// and a crash makes that permanent. Values are copied out, so records
// outlive the RLock.
func (g *GlobalState) SnapshotForWAL(flows []Record, settled []TenantSettledRecord, serverSettled []ServerSettledRecord, totalSettled []TotalSettledRecord) ([]Record, []TenantSettledRecord, []ServerSettledRecord, []TotalSettledRecord) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	for k, c := range g.counts {
		flows = append(flows, Record{Key: k, Counter: *c})
	}
	for k, t := range g.tenantSettled {
		settled = append(settled, TenantSettledRecord{Key: k, Bytes: t.bytes, Packets: t.packets})
	}
	for k, t := range g.serverSettled {
		serverSettled = append(serverSettled, ServerSettledRecord{Key: k, Bytes: t.bytes, Packets: t.packets})
	}
	for k, t := range g.totalSettled {
		totalSettled = append(totalSettled, TotalSettledRecord{Key: k, Bytes: t.bytes, Packets: t.packets})
	}
	return flows, settled, serverSettled, totalSettled
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

// RestoreTenantSettled seeds the settled accumulator from records previously
// written to the WAL. Same contract as [GlobalState.Restore]: boot-time
// only, existing buckets overwritten.
func (g *GlobalState) RestoreTenantSettled(records []TenantSettledRecord) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, r := range records {
		g.tenantSettled[r.Key] = &settledTotal{bytes: r.Bytes, packets: r.Packets}
	}
}

// TenantSettledLen returns the number of settled buckets currently held.
func (g *GlobalState) TenantSettledLen() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.tenantSettled)
}

// RestoreServerSettled seeds the server-settled accumulator from records
// previously written to the WAL. Same contract as [GlobalState.Restore]:
// boot-time only, existing buckets overwritten.
func (g *GlobalState) RestoreServerSettled(records []ServerSettledRecord) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, r := range records {
		g.serverSettled[r.Key] = &settledTotal{bytes: r.Bytes, packets: r.Packets}
	}
}

// ServerSettledLen returns the number of server-settled buckets held.
func (g *GlobalState) ServerSettledLen() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.serverSettled)
}

// PruneServerSettled drops buckets whose ServerID is not in alive — a
// server's series ends when it leaves the Nova list, never on a TTL.
// alive MUST come from a successful, non-empty Nova fetch; pruning on
// missing data ends live servers' series. Returns buckets dropped.
//
// docs/architecture/data-structures.md#settled-bytes
func (g *GlobalState) PruneServerSettled(alive map[string]struct{}) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	dropped := 0
	for k := range g.serverSettled {
		if _, ok := alive[k.ServerID]; !ok {
			delete(g.serverSettled, k)
			dropped++
		}
	}
	return dropped
}

// PruneTenantSettled releases buckets absent from alive — a
// settle-to-parent, not a delete: each dying bucket folds into the
// total absorber or lachesis_bytes_total dips. alive MUST come from a
// successful, non-empty Keystone fetch and MUST include
// metadata.UnknownTenantID.
//
// docs/architecture/data-structures.md#settled-bytes
func (g *GlobalState) PruneTenantSettled(alive map[string]struct{}) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	dropped := 0
	for k, t := range g.tenantSettled {
		if _, ok := alive[k.Tenant]; ok {
			continue
		}
		tk := TotalSettledKey{ExtNet: k.ExtNet, Zone: k.Zone, Dir: k.Dir}
		tt := g.totalSettled[tk]
		if tt == nil {
			tt = &settledTotal{}
			g.totalSettled[tk] = tt
		}
		tt.bytes += t.bytes
		tt.packets += t.packets
		delete(g.tenantSettled, k)
		dropped++
	}
	return dropped
}

// RestoreTotalSettled seeds the total-settled accumulator from records
// previously written to the WAL. Same contract as [GlobalState.Restore]:
// boot-time only, existing buckets overwritten.
func (g *GlobalState) RestoreTotalSettled(records []TotalSettledRecord) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, r := range records {
		g.totalSettled[r.Key] = &settledTotal{bytes: r.Bytes, packets: r.Packets}
	}
}

// TotalSettledLen returns the number of total-settled buckets held.
func (g *GlobalState) TotalSettledLen() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.totalSettled)
}
