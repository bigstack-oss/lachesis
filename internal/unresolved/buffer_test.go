package unresolved

import (
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/bigstack-oss/lachesis/internal/bpf"
	"github.com/bigstack-oss/lachesis/internal/state"
	"github.com/bigstack-oss/lachesis/internal/tunables"
)

// recordingEvictor records the kernel telemetry_map deletes the buffer
// issues on eviction. failOn keys return an error.
type recordingEvictor struct {
	failOn  map[bpf.FlowKey]bool
	deleted []bpf.FlowKey
}

func (e *recordingEvictor) Delete(key bpf.FlowKey) error {
	if e.failOn[key] {
		return errors.New("kernel delete failed")
	}
	e.deleted = append(e.deleted, key)
	return nil
}

// fakeClock is a movable clock for TTL tests.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func flowKey(id uint32, zone bpf.ZoneCode, dir bpf.Direction) bpf.FlowKey {
	// Encode id into both MACs so the VM-side MAC (Dst on egress, Src on
	// ingress) is distinct per id regardless of direction.
	return bpf.FlowKey{
		SrcMac:    [6]uint8{0xaa, byte(id >> 24), byte(id >> 16), byte(id >> 8), byte(id), 0x01},
		DstMac:    [6]uint8{0xbb, byte(id >> 24), byte(id >> 16), byte(id >> 8), byte(id), 0x02},
		EthProto:  0x0800,
		Direction: dir,
		DstZone:   zone,
	}
}

// unknownTotal returns the cumulative the collector would emit for the
// (unknown, zone, direction) bucket: the synthetic key with both MACs
// zeroed. The directional swap means the VM MAC is the zeroed Src
// (ingress) or Dst (egress) — either way it resolves to "unknown".
func unknownTotal(t *testing.T, st *state.GlobalState, zone bpf.ZoneCode, dir bpf.Direction) bpf.FlowMetrics {
	t.Helper()
	want := bpf.FlowKey{EthProto: 0x0800, Direction: dir, DstZone: zone}
	for _, e := range st.Snapshot(nil) {
		if e.Key == want {
			return e.Total
		}
	}
	return bpf.FlowMetrics{}
}

func newBuf(st *state.GlobalState, ev FlowEvictor, clk *fakeClock) *Buffer {
	return NewBuffer(Options{State: st, Evictor: ev, Metrics: NewMetrics(), Tunables: tunables.New(tunables.Values{UnresolvedCap: 10_000, UnresolvedTTL: time.Minute}), Now: clk.now})
}

func TestBuffer_FoldsFullCumulativeOnExpiryAndResetsKernel(t *testing.T) {
	st := state.New()
	ev := &recordingEvictor{}
	clk := &fakeClock{t: time.Unix(1000, 0)}
	b := newBuf(st, ev, clk)

	k := flowKey(1, bpf.ZoneExternal, bpf.DirectionEgress)
	b.Capture(k, bpf.FlowMetrics{Bytes: 100, Packets: 1, LastSeenNs: 10}) // first sight counts the cumulative
	b.Capture(k, bpf.FlowMetrics{Bytes: 300, Packets: 4, LastSeenNs: 20}) // +200/+3

	clk.advance(2 * time.Minute) // past TTL
	b.Sweep(false)

	got := unknownTotal(t, st, bpf.ZoneExternal, bpf.DirectionEgress)
	if got.Bytes != 300 || got.Packets != 4 {
		t.Errorf("folded unknown total = %+v, want full cumulative {Bytes:300 Packets:4}", got)
	}
	if len(ev.deleted) != 1 || ev.deleted[0] != k {
		t.Errorf("kernel deletes = %v, want exactly [%v] (reset on eviction)", ev.deleted, k)
	}
	if b.Len() != 0 {
		t.Errorf("buffer not cleared after expiry: len=%d", b.Len())
	}
}

func TestBuffer_ReappearanceAfterEvictionDoesNotDoubleCount(t *testing.T) {
	st := state.New()
	ev := &recordingEvictor{}
	clk := &fakeClock{t: time.Unix(1000, 0)}
	b := newBuf(st, ev, clk)

	k := flowKey(1, bpf.ZoneExternal, bpf.DirectionEgress)
	b.Capture(k, bpf.FlowMetrics{Bytes: 500, Packets: 5, LastSeenNs: 10})
	clk.advance(2 * time.Minute)
	b.Sweep(false) // folds 500, deletes kernel entry k

	// Kernel honoured the delete: the flow reappears from a fresh, low
	// counter (50), not the old cumulative.
	b.Capture(k, bpf.FlowMetrics{Bytes: 50, Packets: 1, LastSeenNs: 30})
	clk.advance(2 * time.Minute)
	b.Sweep(false)

	got := unknownTotal(t, st, bpf.ZoneExternal, bpf.DirectionEgress)
	if got.Bytes != 550 {
		t.Errorf("unknown total = %d, want 550 (500 + 50, no double-count of the 500)", got.Bytes)
	}
}

func TestBuffer_LRUEvictsOldestAndFolds(t *testing.T) {
	st := state.New()
	ev := &recordingEvictor{}
	clk := &fakeClock{t: time.Unix(1000, 0)}
	b := NewBuffer(Options{State: st, Evictor: ev, Metrics: NewMetrics(), Tunables: tunables.New(tunables.Values{UnresolvedCap: 2, UnresolvedTTL: time.Hour}), Now: clk.now})

	k1 := flowKey(1, bpf.ZoneExternal, bpf.DirectionEgress)
	k2 := flowKey(2, bpf.ZoneExternal, bpf.DirectionEgress)
	k3 := flowKey(3, bpf.ZoneExternal, bpf.DirectionEgress)
	b.Capture(k1, bpf.FlowMetrics{Bytes: 10, Packets: 1})
	b.Capture(k2, bpf.FlowMetrics{Bytes: 20, Packets: 1})
	b.Capture(k1, bpf.FlowMetrics{Bytes: 10, Packets: 1}) // touch k1 → k2 is now oldest
	b.Capture(k3, bpf.FlowMetrics{Bytes: 30, Packets: 1}) // over cap → evict k2

	if b.Len() != 2 {
		t.Fatalf("buffer len = %d, want 2 (cap)", b.Len())
	}
	if len(ev.deleted) != 1 || ev.deleted[0] != k2 {
		t.Errorf("LRU evicted %v, want the oldest [%v]", ev.deleted, k2)
	}
	if got := unknownTotal(t, st, bpf.ZoneExternal, bpf.DirectionEgress).Bytes; got != 20 {
		t.Errorf("folded %d on LRU eviction, want k2's 20", got)
	}
}

func TestBuffer_ForceSweepFoldsAllWithoutKernelDelete(t *testing.T) {
	st := state.New()
	ev := &recordingEvictor{}
	clk := &fakeClock{t: time.Unix(1000, 0)}
	b := newBuf(st, ev, clk) // TTL 1m; nothing has expired

	b.Capture(flowKey(1, bpf.ZoneExternal, bpf.DirectionEgress), bpf.FlowMetrics{Bytes: 100, Packets: 1})
	b.Capture(flowKey(2, bpf.ZoneInfra, bpf.DirectionIngress), bpf.FlowMetrics{Bytes: 200, Packets: 2})

	b.Sweep(true) // shutdown drain

	if b.Len() != 0 {
		t.Errorf("force sweep left %d entries, want 0", b.Len())
	}
	if len(ev.deleted) != 0 {
		t.Errorf("force sweep issued %d kernel deletes, want 0 (maps replaced on next boot)", len(ev.deleted))
	}
	if got := unknownTotal(t, st, bpf.ZoneExternal, bpf.DirectionEgress).Bytes; got != 100 {
		t.Errorf("egress/external unknown = %d, want 100", got)
	}
	if got := unknownTotal(t, st, bpf.ZoneInfra, bpf.DirectionIngress).Bytes; got != 200 {
		t.Errorf("ingress/infra unknown = %d, want 200", got)
	}
}

func TestBuffer_HoldsAtCapUnder100kUnknownFlows(t *testing.T) {
	st := state.New()
	ev := &recordingEvictor{}
	clk := &fakeClock{t: time.Unix(1000, 0)}
	b := NewBuffer(Options{State: st, Evictor: ev, Metrics: NewMetrics(), Tunables: tunables.New(tunables.Values{UnresolvedCap: 10_000, UnresolvedTTL: time.Hour}), Now: clk.now})

	for i := uint32(0); i < 100_000; i++ {
		b.Capture(flowKey(i, bpf.ZoneExternal, bpf.DirectionEgress), bpf.FlowMetrics{Bytes: 1, Packets: 1})
	}
	if b.Len() != 10_000 {
		t.Errorf("buffer len = %d, want it held at the cap %d (no OOM)", b.Len(), 10_000)
	}
	// The 90k LRU-evicted flows were folded to "unknown", not dropped.
	if got := unknownTotal(t, st, bpf.ZoneExternal, bpf.DirectionEgress).Bytes; got != 100_000-10_000 {
		t.Errorf("folded unknown bytes = %d, want %d (every evicted flow's byte)", got, 100_000-10_000)
	}
}

func TestBuffer_KernelDeleteFailureStillFolds(t *testing.T) {
	st := state.New()
	k := flowKey(1, bpf.ZoneExternal, bpf.DirectionEgress)
	ev := &recordingEvictor{failOn: map[bpf.FlowKey]bool{k: true}}
	clk := &fakeClock{t: time.Unix(1000, 0)}
	b := newBuf(st, ev, clk)

	b.Capture(k, bpf.FlowMetrics{Bytes: 100, Packets: 1})
	clk.advance(2 * time.Minute)
	b.Sweep(false) // kernel delete fails, but the fold still happens

	if got := unknownTotal(t, st, bpf.ZoneExternal, bpf.DirectionEgress).Bytes; got != 100 {
		t.Errorf("unknown total = %d, want 100 (fold happens even when kernel reset fails)", got)
	}
	if b.Len() != 0 {
		t.Errorf("entry not dropped after failed kernel delete: len=%d", b.Len())
	}
}

func TestBuffer_DepthGaugeTracksOccupancy(t *testing.T) {
	st := state.New()
	ev := &recordingEvictor{}
	clk := &fakeClock{t: time.Unix(1000, 0)}
	mx := NewMetrics()
	b := NewBuffer(Options{State: st, Evictor: ev, Metrics: mx, Tunables: tunables.New(tunables.Values{UnresolvedCap: 10_000, UnresolvedTTL: time.Minute}), Now: clk.now})

	b.Capture(flowKey(1, bpf.ZoneExternal, bpf.DirectionEgress), bpf.FlowMetrics{Bytes: 1})
	b.Capture(flowKey(2, bpf.ZoneExternal, bpf.DirectionEgress), bpf.FlowMetrics{Bytes: 1})
	b.Sweep(false) // nothing expired; publishes depth
	if got := testutil.ToFloat64(mx.depth); got != 2 {
		t.Errorf("depth gauge = %v, want 2", got)
	}
	if got := testutil.ToFloat64(mx.evictions.WithLabelValues(reasonExpired)); got != 0 {
		t.Errorf("expired evictions = %v, want 0", got)
	}
}

// TestBuffer_CapShrinkAppliesLive: a hot-reloaded smaller cap takes
// effect through the normal LRU eviction on the next admission
// (lachesis#156) — no restart, no special-case flush.
func TestBuffer_CapShrinkAppliesLive(t *testing.T) {
	tun := tunables.New(tunables.Values{UnresolvedCap: 4, UnresolvedTTL: time.Hour})
	b := NewBuffer(Options{State: state.New(), Evictor: &recordingEvictor{}, Metrics: NewMetrics(), Tunables: tun})

	for i := uint32(1); i <= 4; i++ {
		b.Capture(flowKey(i, bpf.ZoneExternal, bpf.DirectionEgress), bpf.FlowMetrics{Bytes: 10, Packets: 1})
	}
	if got := b.Len(); got != 4 {
		t.Fatalf("len = %d, want 4 at cap", got)
	}

	tun.Replace(tunables.Values{UnresolvedCap: 2, UnresolvedTTL: time.Hour})
	b.Capture(flowKey(9, bpf.ZoneExternal, bpf.DirectionEgress), bpf.FlowMetrics{Bytes: 10, Packets: 1})
	if got := b.Len(); got != 2 {
		t.Fatalf("len = %d after shrink-to-2 admission, want 2 (LRU evicted down to the live cap)", got)
	}
}
