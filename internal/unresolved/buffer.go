// Package unresolved implements the UnresolvedBuffer: the late-binding
// holding area for flows whose VM-side MAC is not yet in the metadata
// map. Without it, every unknown-MAC flow would take its own GlobalState
// key and grow that map without bound under a Neutron outage or a flood
// of uncatalogued MACs.
//
// The accounting rule that makes it safe: on eviction the accumulated
// total is folded to a synthetic "unknown" key AND the flow's kernel
// telemetry_map entry is deleted. Deleting is what makes counting the
// whole cumulative safe — a flow that reappears starts from a fresh
// kernel value, so folded bytes are never folded twice.
//
// The scrape goroutine is the single owner, so there is no internal
// locking.
//
// docs/architecture/data-structures.md#userspace-structures
package unresolved

import (
	"container/list"
	"log/slog"
	"time"

	"github.com/bigstack-oss/lachesis/internal/bpf"
	"github.com/bigstack-oss/lachesis/internal/state"
	"github.com/bigstack-oss/lachesis/internal/tunables"
)

// FlowEvictor deletes a flow entry from the kernel telemetry_map — the
// consumer-defined seam the buffer resets a flow's kernel counter
// through on eviction. The agent wires a *ebpf.Map adapter (the same
// one the pressure-relief GC uses); tests wire a recording mock. Delete
// must be idempotent on a key already gone.
type FlowEvictor interface {
	Delete(key bpf.FlowKey) error
}

// Buffer holds unknown-MAC flows until their MAC resolves (a later
// sprint), their TTL elapses, or the cap evicts them. It is driven
// solely by the scraper goroutine — Capture and Sweep are not safe for
// concurrent use, and need none, since the depth gauge is Set from the
// same goroutine.
type Buffer struct {
	entries map[bpf.FlowKey]*entry
	// order is an LRU list of bpf.FlowKey, most-recently-captured at the
	// front; the back is the eviction victim when the cap is exceeded.
	order   *list.List
	tun     *tunables.Store
	state   *state.GlobalState
	evictor FlowEvictor
	mx      *Metrics
	now     func() time.Time
}

// entry is one buffered flow. total is the cumulative since first sight;
// lastRaw is the delta baseline (the kernel cumulative at the last
// Capture); firstSeen drives TTL expiry.
type entry struct {
	total     bpf.FlowMetrics
	lastRaw   bpf.FlowMetrics
	firstSeen time.Time
	elem      *list.Element
}

// Options bundles the inputs to [NewBuffer]. State, Evictor, and Metrics
// are required. Cap (≤0 → [defaultCap]) and TTL (≤0 → [defaultTTL])
// override the production bounds for tests. Now (nil → time.Now) injects
// a clock.
type Options struct {
	State   *state.GlobalState
	Evictor FlowEvictor
	Metrics *Metrics
	Now     func() time.Time
	// Tunables supplies the live buffer bounds (cap, TTL), read at
	// each admission / expiry check — a cap shrink applies through the
	// normal LRU eviction on the next admission. REQUIRED; unit tests
	// construct a store with the bounds they exercise.
	Tunables *tunables.Store
}

// NewBuffer constructs a buffer over the live tunable bounds.
func NewBuffer(opts Options) *Buffer {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Buffer{
		entries: make(map[bpf.FlowKey]*entry),
		order:   list.New(),
		tun:     opts.Tunables,
		state:   opts.State,
		evictor: opts.Evictor,
		mx:      opts.Metrics,
		now:     now,
	}
}

// Capture integrates one drained reading for an unknown-MAC flow into
// its buffer entry. First sight seeds the cumulative from the current
// kernel value; later sightings add the delta. Capturing touches the
// entry's LRU position. A first sight that pushes the buffer over its
// cap triggers an LRU eviction of the oldest entry.
func (b *Buffer) Capture(key bpf.FlowKey, raw bpf.FlowMetrics) {
	e, ok := b.entries[key]
	if !ok {
		b.entries[key] = &entry{
			total:     raw,
			lastRaw:   raw,
			firstSeen: b.now(),
			elem:      b.order.PushFront(key),
		}
		b.evictOverCap()
		return
	}
	state.AddDelta(&e.total.Bytes, &e.lastRaw.Bytes, raw.Bytes)
	state.AddDelta(&e.total.Packets, &e.lastRaw.Packets, raw.Packets)
	if raw.LastSeenNs > e.total.LastSeenNs {
		e.total.LastSeenNs = raw.LastSeenNs
	}
	e.lastRaw.LastSeenNs = raw.LastSeenNs
	b.order.MoveToFront(e.elem)
}

// Sweep folds out entries whose TTL has elapsed, then publishes the
// buffer depth. With force set it folds every entry regardless of TTL —
// the graceful-shutdown drain, so no unknown bytes are lost to the final
// WAL flush. Force does NOT delete kernel entries: the maps are about to
// be replaced on the next boot, so resetting them is pointless, and
// skipping ~10k deletes keeps shutdown inside its budget. Run once per
// scrape tick by the [Classifier].
func (b *Buffer) Sweep(force bool) {
	now := b.now()
	expired := 0
	for key, e := range b.entries {
		if !force && now.Sub(e.firstSeen) < b.tun.Get().UnresolvedTTL {
			continue
		}
		b.foldToUnknown(key, e.total)
		b.drop(key, e, !force) // delete the kernel entry except on shutdown
		expired++
	}
	b.mx.RecordExpiredEvictions(expired)
	b.mx.SetDepth(len(b.entries))
}

// Resolve hands a buffered flow to its real tenant once the MAC becomes
// known, seeding both the accumulated total and the kernel baseline so
// the next delta continues without re-counting. Unlike an eviction it
// does not fold to "unknown" and does not reset the kernel entry — the
// flow lives on and the scraper keeps integrating it.
func (b *Buffer) Resolve(key bpf.FlowKey) bool {
	e, ok := b.entries[key]
	if !ok {
		return false
	}
	b.state.Resolve(key, e.total, e.lastRaw)
	b.drop(key, e, false)
	b.mx.RecordResolved()
	return true
}

// Len reports the current entry count. Exposed for tests.
func (b *Buffer) Len() int { return len(b.entries) }

// evictOverCap evicts least-recently-captured entries until the buffer
// is back within its cap, folding each victim's accumulated bytes into
// the "unknown" tenant (never dropping them) and resetting its kernel
// entry.
func (b *Buffer) evictOverCap() {
	for len(b.entries) > b.tun.Get().UnresolvedCap {
		back := b.order.Back()
		if back == nil {
			return
		}
		key := back.Value.(bpf.FlowKey)
		e := b.entries[key]
		b.foldToUnknown(key, e.total)
		b.drop(key, e, true)
		b.mx.RecordLRUEviction()
	}
}

// foldToUnknown adds total to a synthetic key that keeps the flow's
// eth_proto, direction and zone but zeroes both MACs. An all-zero source
// MAC never occurs in real traffic, so the key cannot collide, and all
// unknown traffic collapses into a handful of monotone series.
func (b *Buffer) foldToUnknown(key bpf.FlowKey, total bpf.FlowMetrics) {
	b.state.Add(bpf.FlowKey{
		EthProto:  key.EthProto,
		Direction: key.Direction,
		DstZone:   key.DstZone,
	}, total)
}

// drop removes an entry from the map and LRU list. When delKernel is
// set it also resets the flow's kernel telemetry_map entry, so a
// reappearing flow re-baselines from a fresh counter and its
// already-folded bytes are never double-counted. A delete failure is
// logged, not fatal — the worst case is one flow's bytes being folded
// twice into "unknown", which over-reports the unbilled pseudo-tenant
// (never a real tenant) and never loses bytes.
func (b *Buffer) drop(key bpf.FlowKey, e *entry, delKernel bool) {
	b.order.Remove(e.elem)
	delete(b.entries, key)
	if delKernel {
		if err := b.evictor.Delete(key); err != nil {
			slog.Warn("unresolved kernel reset failed; flow may re-fold to unknown once",
				"component", component, "err", err)
		}
	}
}
