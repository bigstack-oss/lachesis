package gc

import (
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/bigstack-oss/lachesis/internal/bpf"
	"github.com/bigstack-oss/lachesis/internal/tunables"
)

// Test tuning values mirror the config defaults (docs/architecture/data-structures.md#kernel-side-bpf-maps).
const (
	testHigh = 0.80
	testLow  = 0.75
	testCap  = 1000
)

// newReliever builds a reliever with the default-mirroring tuning.
func newReliever(ev FlowEvictor, maxN int, mx *Metrics) *PressureReliever {
	return newRelieverWith(ev, maxN, mx, testHigh, testLow, testCap)
}

// newRelieverWith wires a reliever to its own store seeded with the
// given tuning — tests mutate the store to model a SIGHUP reload.
func newRelieverWith(ev FlowEvictor, maxN int, mx *Metrics, high, low float64, perPass int) *PressureReliever {
	tun := tunables.New(tunables.Values{
		PressureHighWatermark: high,
		PressureLowWatermark:  low,
		PressureMaxPerPass:    perPass,
	})
	return NewPressureReliever(PressureOptions{
		Evictor:    ev,
		MaxEntries: maxN,
		Metrics:    mx,
		Tunables:   tun,
	})
}

// flowKey builds a distinct FlowKey from a 32-bit id (spread across the
// src MAC) so tests can mint many unique keys cheaply.
func flowKey(id uint32) bpf.FlowKey {
	return bpf.FlowKey{
		SrcMac:    [6]uint8{0xaa, byte(id >> 24), byte(id >> 16), byte(id >> 8), byte(id), 0x01},
		DstMac:    [6]uint8{0xbb, 0, 0, 0, 0, 0x02},
		EthProto:  0x0800,
		Direction: bpf.DirectionEgress,
		DstZone:   bpf.ZoneExternal,
	}
}

// mapFlowEvictor mocks the kernel telemetry_map: Delete removes the key
// from the backing map so successive Relieve passes see a shrinking
// population, exactly as a real drain would. failOn keys return errors.
type mapFlowEvictor struct {
	m       map[bpf.FlowKey]bpf.FlowMetrics
	failOn  map[bpf.FlowKey]bool
	deleted []bpf.FlowKey
}

func (e *mapFlowEvictor) Delete(key bpf.FlowKey) error {
	if e.failOn[key] {
		return errors.New("kernel delete failed")
	}
	delete(e.m, key)
	e.deleted = append(e.deleted, key)
	return nil
}

func TestSelectOldest_PicksSmallestLastSeen(t *testing.T) {
	drained := map[bpf.FlowKey]bpf.FlowMetrics{}
	for i := uint32(0); i < 20; i++ {
		drained[flowKey(i)] = bpf.FlowMetrics{LastSeenNs: uint64(i)} // older = smaller i
	}
	got := selectOldest(drained, 5)
	if len(got) != 5 {
		t.Fatalf("selectOldest returned %d keys, want 5", len(got))
	}
	// The 5 oldest are ids 0..4 (LastSeenNs 0..4). Order within the set
	// is unspecified; check membership.
	want := map[bpf.FlowKey]bool{}
	for i := uint32(0); i < 5; i++ {
		want[flowKey(i)] = true
	}
	for _, k := range got {
		if !want[k] {
			t.Errorf("selectOldest returned %v, which is not among the 5 oldest", k)
		}
	}
}

func TestRelieve_BelowHighWatermarkIsNoop(t *testing.T) {
	maxN := 1000
	drained := map[bpf.FlowKey]bpf.FlowMetrics{}
	for i := uint32(0); i < 700; i++ { // 70% < 80% high watermark
		drained[flowKey(i)] = bpf.FlowMetrics{LastSeenNs: uint64(i)}
	}
	ev := &mapFlowEvictor{m: drained}
	mx := NewMetrics()
	p := newReliever(ev, maxN, mx)
	p.Relieve(drained)

	if len(ev.deleted) != 0 {
		t.Errorf("evicted %d below the high watermark, want 0", len(ev.deleted))
	}
	if got := testutil.ToFloat64(mx.pressureReliefRun); got != 0 {
		t.Errorf("pressure_relief_runs = %v, want 0", got)
	}
}

func TestRelieve_EvictsOldestCappedPerPass(t *testing.T) {
	maxN := bpf.MapTelemetryMaxEntries // 65536
	high := int(testHigh * float64(maxN))
	n := high + 1 // just over the high watermark
	drained := make(map[bpf.FlowKey]bpf.FlowMetrics, n)
	for i := uint32(0); i < uint32(n); i++ {
		drained[flowKey(i)] = bpf.FlowMetrics{LastSeenNs: uint64(i)}
	}
	ev := &mapFlowEvictor{m: drained}
	mx := NewMetrics()
	p := newReliever(ev, maxN, mx)
	p.Relieve(drained)

	// want = n - low(75%) is far above the per-pass cap, so exactly the
	// cap is evicted this pass.
	if len(ev.deleted) != testCap {
		t.Fatalf("evicted %d in one pass, want the cap %d", len(ev.deleted), testCap)
	}
	// Every evicted key must be among the oldest (smallest ids): the cap
	// oldest are ids 0..cap-1, whose two high id-bytes are zero.
	for _, k := range ev.deleted {
		if k.SrcMac[1] != 0 || k.SrcMac[2] != 0 {
			t.Fatalf("evicted a non-oldest key %v", k)
		}
	}
	if got := testutil.ToFloat64(mx.evictions.WithLabelValues(reasonPressureRelief)); got != testCap {
		t.Errorf("pressure_relief evictions = %v, want %d", got, testCap)
	}
	if got := testutil.ToFloat64(mx.pressureReliefRun); got != 1 {
		t.Errorf("pressure_relief_runs = %v, want 1", got)
	}
}

// TestRelieve_DrainsToFloorWithinFourScrapes is the done-criterion
// stress test: a telemetry_map filled past the 80% watermark must drop
// below 75% within four successive scrape passes, with each pass capped.
func TestRelieve_DrainsToFloorWithinFourScrapes(t *testing.T) {
	maxN := bpf.MapTelemetryMaxEntries
	low := int(testLow * float64(maxN))
	n := int(testHigh*float64(maxN)) + 1 // just over 80%

	drained := make(map[bpf.FlowKey]bpf.FlowMetrics, n)
	for i := uint32(0); i < uint32(n); i++ {
		drained[flowKey(i)] = bpf.FlowMetrics{LastSeenNs: uint64(i)}
	}
	ev := &mapFlowEvictor{m: drained}
	mx := NewMetrics()
	p := newReliever(ev, maxN, mx)

	passes := 0
	for len(drained) > low {
		passes++
		if passes > 4 {
			t.Fatalf("still above the 75%% floor (%d entries) after 4 passes", len(drained))
		}
		p.Relieve(drained) // deletes from `drained` via the mock
	}
	// Hysteresis: one more pass at/below the floor must do nothing.
	before := len(ev.deleted)
	p.Relieve(drained)
	if len(ev.deleted) != before {
		t.Errorf("evicted below the low watermark — hysteresis not honoured")
	}
}

func TestRelieve_DeleteFailureNotCounted(t *testing.T) {
	maxN := bpf.MapTelemetryMaxEntries
	n := int(testHigh*float64(maxN)) + 1
	drained := make(map[bpf.FlowKey]bpf.FlowMetrics, n)
	for i := uint32(0); i < uint32(n); i++ {
		drained[flowKey(i)] = bpf.FlowMetrics{LastSeenNs: uint64(i)}
	}
	// Fail the very oldest key; it is certain to be picked this pass.
	ev := &mapFlowEvictor{m: drained, failOn: map[bpf.FlowKey]bool{flowKey(0): true}}
	mx := NewMetrics()
	p := newReliever(ev, maxN, mx)
	p.Relieve(drained)

	if got := testutil.ToFloat64(mx.evictions.WithLabelValues(reasonPressureRelief)); got != float64(testCap-1) {
		t.Errorf("pressure_relief evictions = %v, want %d (one delete failed)", got, testCap-1)
	}
	if _, stillThere := drained[flowKey(0)]; !stillThere {
		t.Error("the failed-delete key was removed from the map anyway")
	}
}

// TestPressureTunables_HotSwapTakesEffect proves a reloaded tuning
// snapshot is honoured on the next pass: a fill between the default
// watermarks (no relief) starts evicting once the high watermark is
// lowered beneath it via the shared tunables store — the SIGHUP path.
func TestPressureTunables_HotSwapTakesEffect(t *testing.T) {
	maxN := bpf.MapTelemetryMaxEntries
	n := int(0.78 * float64(maxN)) // between default low (75%) and high (80%)
	drained := make(map[bpf.FlowKey]bpf.FlowMetrics, n)
	for i := uint32(0); i < uint32(n); i++ {
		drained[flowKey(i)] = bpf.FlowMetrics{LastSeenNs: uint64(i)}
	}
	ev := &mapFlowEvictor{m: drained}
	p := newReliever(ev, maxN, NewMetrics())

	p.Relieve(drained)
	if len(ev.deleted) != 0 {
		t.Fatalf("evicted %d at 78%% fill with an 80%% high watermark, want 0", len(ev.deleted))
	}

	// Lower the high watermark beneath the current fill (as a SIGHUP
	// reload would); next pass evicts.
	p.tun.Replace(tunables.Values{
		PressureHighWatermark: 0.70,
		PressureLowWatermark:  0.65,
		PressureMaxPerPass:    testCap,
	})
	p.Relieve(drained)
	if len(ev.deleted) == 0 {
		t.Error("no eviction after lowering the high watermark below the fill — hot swap not applied")
	}
}

// recordingInvalidator records which keys the reliever declared dead.
type recordingInvalidator struct{ keys []bpf.FlowKey }

func (r *recordingInvalidator) InvalidateBaseline(k bpf.FlowKey) {
	r.keys = append(r.keys, k)
}

func (r *recordingInvalidator) has(k bpf.FlowKey) bool {
	for _, got := range r.keys {
		if got == k {
			return true
		}
	}
	return false
}

// TestRelieve_InvalidatesBaselineOnlyForDeletedKeys is the other half of
// the lachesis#287 regression, and it guards the direction that would be
// WORSE than the original bug.
//
// A successful eviction must drop the flow's delta baseline, or the
// re-created entry is diffed against a baseline that no longer exists and
// its bytes go unbilled. But a FAILED delete leaves the entry live with
// its counter still climbing from the value we last read — invalidating
// there would make the next reading count the flow's entire history a
// second time, converting silent under-billing into over-billing.
func TestRelieve_InvalidatesBaselineOnlyForDeletedKeys(t *testing.T) {
	maxN := bpf.MapTelemetryMaxEntries
	n := int(testHigh*float64(maxN)) + 1
	drained := make(map[bpf.FlowKey]bpf.FlowMetrics, n)
	for i := uint32(0); i < uint32(n); i++ {
		drained[flowKey(i)] = bpf.FlowMetrics{LastSeenNs: uint64(i)}
	}
	// flowKey(0) is the very oldest, so it is certain to be a victim —
	// and its delete fails.
	failing := flowKey(0)
	ev := &mapFlowEvictor{m: drained, failOn: map[bpf.FlowKey]bool{failing: true}}
	inv := &recordingInvalidator{}
	p := newRelieverWith(ev, maxN, NewMetrics(), testHigh, testLow, testCap)
	p.baselines = inv
	p.Relieve(drained)

	if inv.has(failing) {
		t.Error("a FAILED delete invalidated the baseline: the entry is still live and " +
			"still climbing, so the next reading would re-count its whole history (over-billing)")
	}
	if len(ev.deleted) == 0 {
		t.Fatal("no key was evicted; the fixture does not exercise the success path")
	}
	for _, k := range ev.deleted {
		if !inv.has(k) {
			t.Errorf("evicted key %v kept its baseline: the re-created entry will be diffed "+
				"against a dead baseline and its bytes go unbilled (lachesis#287)", k)
		}
	}
	if len(inv.keys) != len(ev.deleted) {
		t.Errorf("invalidated %d baselines for %d confirmed deletes — the two must match exactly",
			len(inv.keys), len(ev.deleted))
	}
}

// TestRelieve_NilInvalidatorIsSafe: the seam is optional at the type
// level so existing constructions (and the no-op paths) cannot panic.
func TestRelieve_NilInvalidatorIsSafe(t *testing.T) {
	maxN := bpf.MapTelemetryMaxEntries
	n := int(testHigh*float64(maxN)) + 1
	drained := make(map[bpf.FlowKey]bpf.FlowMetrics, n)
	for i := uint32(0); i < uint32(n); i++ {
		drained[flowKey(i)] = bpf.FlowMetrics{LastSeenNs: uint64(i)}
	}
	p := newReliever(&mapFlowEvictor{m: drained}, maxN, NewMetrics())
	p.Relieve(drained) // must not panic with baselines unset
}
