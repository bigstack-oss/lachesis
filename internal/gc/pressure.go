package gc

import (
	"container/heap"
	"log/slog"

	"github.com/bigstack-oss/lachesis/internal/bpf"
	"github.com/bigstack-oss/lachesis/internal/tunables"
)

// FlowEvictor deletes a flow entry from the kernel telemetry_map. Like
// [MacEvictor] it is the consumer-defined seam over a kernel map: the
// agent wires a *ebpf.Map adapter, tests wire a mock. Delete must be
// idempotent on a key that is already gone.
type FlowEvictor interface {
	Delete(key bpf.FlowKey) error
}

// BaselineInvalidator drops the delta baseline for a flow whose kernel
// entry has just been removed, so the next reading of that key is
// counted from zero rather than diffed against a baseline that no longer
// exists. Like [FlowEvictor] it is a consumer-defined seam: the agent
// wires *state.GlobalState, tests wire a recorder.
//
// This must be driven by the eviction and not left to the value-based
// reset guard in state.AddDelta: the guard only fires on
// current<lastRaw, so a re-created entry that climbs back to the old
// baseline within one scrape interval is read as a small normal advance
// and the flushed bytes are lost (lachesis#287).
type BaselineInvalidator interface {
	InvalidateBaseline(key bpf.FlowKey)
}

// PressureReliever evicts the oldest telemetry_map entries when the map
// approaches its capacity, so the kernel never drops a counter on its
// own (a silent byte loss). It runs inside the scraper's drain
// goroutine, once per tick, after the drained readings have been
// applied to GlobalState — every evicted entry's bytes are therefore
// already accounted before the kernel entry is removed
// (docs/architecture/data-structures.md#kernel-side-bpf-maps, "flush before evict").
//
// Eviction uses a high/low watermark hysteresis: a relief cycle begins
// when fill crosses the high watermark and continues every tick,
// evicting up to the per-pass cap of the oldest flows, until fill falls
// below the low watermark. Bounding each pass means the map drains to
// the low watermark over a few scrapes rather than in one long stall.
//
// The three bounds (high watermark, low watermark, per-pass cap) are
// operator-tunable and hot-reloadable: the scrape goroutine reads the
// shared [tunables.Store] snapshot each pass, and the SIGHUP reload
// swaps it (runtime.Manager.Reload). The relieving flag, by contrast,
// is touched only from the scrape goroutine, so it needs no
// synchronisation.
type PressureReliever struct {
	evictor    FlowEvictor
	baselines  BaselineInvalidator
	maxEntries int
	mx         *Metrics
	tun        *tunables.Store
	relieving  bool
}

// PressureOptions bundles the inputs to [NewPressureReliever]. All
// fields are required; MaxEntries must be positive (it is the
// fill-ratio denominator). The tuning values come from the shared
// tunables snapshot, validated at load/reload by config.GCConfig.
type PressureOptions struct {
	Evictor FlowEvictor
	// Baselines is told about every entry actually evicted, so the flow's
	// delta baseline is dropped alongside its kernel entry. Required:
	// without it a re-created entry is diffed against a dead baseline and
	// its bytes go unbilled (lachesis#287).
	Baselines  BaselineInvalidator
	MaxEntries int
	Metrics    *Metrics
	Tunables   *tunables.Store
}

// NewPressureReliever constructs a reliever. MaxEntries is the kernel
// telemetry_map's compiled-in capacity (bpf.MapTelemetryMaxEntries).
func NewPressureReliever(opts PressureOptions) *PressureReliever {
	return &PressureReliever{
		evictor:    opts.Evictor,
		baselines:  opts.Baselines,
		maxEntries: opts.MaxEntries,
		mx:         opts.Metrics,
		tun:        opts.Tunables,
	}
}

// Relieve runs one pressure-relief pass over the just-drained readings
// (already applied to GlobalState). drained is the scraper's reused
// buffer — its key count is the current kernel population (read-don't-
// clear; only this GC evicts), and each value's LastSeenNs is the
// eviction key. Relieve only reads drained; it deletes from the kernel
// map via the evictor. It is a no-op while fill stays below the high
// watermark (outside a relief cycle) or once it drops below the low
// watermark.
func (p *PressureReliever) Relieve(drained map[bpf.FlowKey]bpf.FlowMetrics) {
	if p == nil || p.maxEntries <= 0 {
		return
	}
	pp := p.tun.Get()
	n := len(drained)
	high := int(pp.PressureHighWatermark * float64(p.maxEntries))
	low := int(pp.PressureLowWatermark * float64(p.maxEntries))

	switch {
	case n <= low:
		p.relieving = false // back under the floor — cycle complete
		return
	case !p.relieving && n <= high:
		return // between watermarks but not in a cycle — leave it
	}
	p.relieving = true

	want := n - low
	if want > pp.PressureMaxPerPass {
		want = pp.PressureMaxPerPass
	}
	victims := selectOldest(drained, want)

	evicted := 0
	for _, k := range victims {
		if err := p.evictor.Delete(k); err != nil {
			// The entry is STILL LIVE and its kernel counter keeps climbing
			// from the value we last read, so its baseline must stand. This
			// `continue` is load-bearing: invalidating here would make the
			// next reading count the flow's whole history a second time,
			// turning an under-count into an over-count.
			slog.Warn("pressure-relief kernel delete failed; entry stays until next pass",
				"component", component, "err", err)
			continue
		}
		// Confirmed gone: the next value read for this key starts at zero,
		// so the delta baseline must go with it (lachesis#287).
		if p.baselines != nil {
			p.baselines.InvalidateBaseline(k)
		}
		evicted++
	}
	p.mx.IncPressureReliefRuns()
	p.mx.RecordPressureReliefEvictions(evicted)
	slog.Info("pressure-relief pass",
		"component", component, "fill", n, "max", p.maxEntries, "evicted", evicted)
}

// selectOldest returns the k flow keys with the smallest LastSeenNs,
// found in a single O(N log k) pass using a size-k heap — never a full
// O(N log N) sort of the whole map (docs/architecture/data-structures.md#kernel-side-bpf-maps). The heap is
// ordered max-by-LastSeenNs at its root so the newest of the k
// candidates kept so far can be replaced when an older flow is seen.
func selectOldest(drained map[bpf.FlowKey]bpf.FlowMetrics, k int) []bpf.FlowKey {
	if k <= 0 {
		return nil
	}
	h := make(ageHeap, 0, k)
	for key, v := range drained {
		if h.Len() < k {
			heap.Push(&h, flowAge{key: key, seen: v.LastSeenNs})
			continue
		}
		if v.LastSeenNs < h[0].seen {
			h[0] = flowAge{key: key, seen: v.LastSeenNs}
			heap.Fix(&h, 0)
		}
	}
	out := make([]bpf.FlowKey, h.Len())
	for i := range h {
		out[i] = h[i].key
	}
	return out
}

// flowAge pairs a flow key with its LastSeenNs for heap ordering.
type flowAge struct {
	key  bpf.FlowKey
	seen uint64
}

// ageHeap is a max-heap on LastSeenNs: the root is the newest entry
// among those retained, so [selectOldest] can evict it in favour of an
// older flow. It satisfies container/heap.Interface.
type ageHeap []flowAge

func (h ageHeap) Len() int           { return len(h) }
func (h ageHeap) Less(i, j int) bool { return h[i].seen > h[j].seen }
func (h ageHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *ageHeap) Push(x any)        { *h = append(*h, x.(flowAge)) }
func (h *ageHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}
