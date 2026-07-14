package gc

import (
	"container/heap"
	"log/slog"
	"sync/atomic"

	"github.com/bigstack-oss/lachesis/internal/bpf"
)

// FlowEvictor deletes a flow entry from the kernel telemetry_map. Like
// [MacEvictor] it is the consumer-defined seam over a kernel map: the
// agent wires a *ebpf.Map adapter, tests wire a mock. Delete must be
// idempotent on a key that is already gone.
type FlowEvictor interface {
	Delete(key bpf.FlowKey) error
}

// PressureReliever evicts the oldest telemetry_map entries when the map
// approaches its capacity, so the kernel never drops a counter on its
// own (a silent byte loss). It runs inside the scraper's drain
// goroutine, once per tick, after the drained readings have been
// applied to GlobalState — every evicted entry's bytes are therefore
// already accounted before the kernel entry is removed (docs/DESIGN.md
// §3.1, "flush before evict").
//
// Eviction uses a high/low watermark hysteresis: a relief cycle begins
// when fill crosses the high watermark and continues every tick,
// evicting up to the per-pass cap of the oldest flows, until fill falls
// below the low watermark. Bounding each pass means the map drains to
// the low watermark over a few scrapes rather than in one long stall.
//
// The three bounds (high watermark, low watermark, per-pass cap) are
// operator-tunable and hot-reloadable: they live in an [atomic.Pointer]
// snapshot that the scrape goroutine Loads each pass and the SIGHUP
// reload goroutine Stores via [PressureReliever.SetPressureParams]. The
// relieving flag, by contrast, is touched only from the scrape
// goroutine, so it needs no synchronisation.
type PressureReliever struct {
	evictor    FlowEvictor
	maxEntries int
	mx         *Metrics
	params     atomic.Pointer[pressureParams]
	relieving  bool
}

// pressureParams is the hot-swappable tuning snapshot. high and low are
// fill ratios; maxPerPass caps evictions per scrape.
type pressureParams struct {
	high, low  float64
	maxPerPass int
}

// PressureOptions bundles the inputs to [NewPressureReliever]. Evictor,
// MaxEntries, and Metrics are required; MaxEntries must be positive (it
// is the fill-ratio denominator). The three tuning values come from
// config.GCConfig and are validated there.
type PressureOptions struct {
	Evictor       FlowEvictor
	MaxEntries    int
	Metrics       *Metrics
	HighWatermark float64
	LowWatermark  float64
	MaxPerPass    int
}

// NewPressureReliever constructs a reliever. MaxEntries is the kernel
// telemetry_map's compiled-in capacity (bpf.MapTelemetryMaxEntries);
// the watermarks and per-pass cap seed the initial tuning snapshot.
func NewPressureReliever(opts PressureOptions) *PressureReliever {
	p := &PressureReliever{
		evictor:    opts.Evictor,
		maxEntries: opts.MaxEntries,
		mx:         opts.Metrics,
	}
	p.params.Store(&pressureParams{
		high:       opts.HighWatermark,
		low:        opts.LowWatermark,
		maxPerPass: opts.MaxPerPass,
	})
	return p
}

// SetPressureParams atomically swaps the tuning snapshot. The SIGHUP
// reload goroutine calls it; the scrape goroutine picks up the new
// values on its next Relieve. Values are assumed pre-validated —
// config.GCConfig.Validate runs in runtime.Manager.Reload, which
// rejects an invalid config before reaching here.
func (p *PressureReliever) SetPressureParams(high, low float64, maxPerPass int) {
	if p == nil {
		return
	}
	p.params.Store(&pressureParams{high: high, low: low, maxPerPass: maxPerPass})
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
	pp := p.params.Load()
	n := len(drained)
	high := int(pp.high * float64(p.maxEntries))
	low := int(pp.low * float64(p.maxEntries))

	switch {
	case n <= low:
		p.relieving = false // back under the floor — cycle complete
		return
	case !p.relieving && n <= high:
		return // between watermarks but not in a cycle — leave it
	}
	p.relieving = true

	want := n - low
	if want > pp.maxPerPass {
		want = pp.maxPerPass
	}
	victims := selectOldest(drained, want)

	evicted := 0
	for _, k := range victims {
		if err := p.evictor.Delete(k); err != nil {
			slog.Warn("pressure-relief kernel delete failed; entry stays until next pass",
				"component", component, "err", err)
			continue
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
// O(N log N) sort of the whole map (docs/DESIGN.md §3.1). The heap is
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
