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

// PressureReliever evicts the oldest telemetry_map entries before the
// map fills, so the kernel never drops a counter on its own. It runs in
// the scraper's drain goroutine AFTER the readings are applied, so
// every evicted entry's bytes are already accounted ("flush before
// evict").
//
// High/low watermark hysteresis with a per-pass cap: the map drains
// over a few scrapes rather than one long stall. All three bounds are
// hot-reloadable.
//
// docs/architecture/data-structures.md#kernel-side-bpf-maps
type PressureReliever struct {
	evictor    FlowEvictor
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
	Evictor    FlowEvictor
	MaxEntries int
	Metrics    *Metrics
	Tunables   *tunables.Store
}

// NewPressureReliever constructs a reliever. MaxEntries is the kernel
// telemetry_map's compiled-in capacity (bpf.MapTelemetryMaxEntries).
func NewPressureReliever(opts PressureOptions) *PressureReliever {
	return &PressureReliever{
		evictor:    opts.Evictor,
		maxEntries: opts.MaxEntries,
		mx:         opts.Metrics,
		tun:        opts.Tunables,
	}
}

// Relieve runs one pass over the just-drained readings, which are
// already in GlobalState. drained is read-only here: its key count IS
// the kernel population (read-don't-clear) and LastSeenNs is the
// eviction key. No-op outside a relief cycle.
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
// O(N log N) sort of the whole map. The heap is ordered
// max-by-LastSeenNs at its root so the newest of the k candidates kept
// so far can be replaced when an older flow is seen.
//
// Kernel maps: docs/architecture/data-structures.md#kernel-side-bpf-maps
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
