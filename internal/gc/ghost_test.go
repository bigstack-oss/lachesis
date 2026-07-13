package gc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/boot"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/metadata"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/state"
)

// fakeGauge records the last value set for each kernel map.
type fakeGauge struct{ vals map[string]float64 }

func (f *fakeGauge) SetCurrent(name string, v float64) {
	if f.vals == nil {
		f.vals = map[string]float64{}
	}
	f.vals[name] = v
}

// TestSweep_RefreshesMacGauge locks the gauge-gap fix on the ghost path:
// after a sweep deletes ghosts, cubecos_bpf_map_current_entries for
// mac_tenant_map reflects the post-sweep metadata count.
func TestSweep_RefreshesMacGauge(t *testing.T) {
	meta := metadata.New()
	now := time.Now()
	meta.Insert(0x01, &metadata.TenantMeta{ProjectID: "live"})
	meta.Insert(0x02, &metadata.TenantMeta{ProjectID: "gone"})
	meta.MarkDelete(0x02, now.Add(-time.Second)) // expired → swept

	ev := &recordingEvictor{meta: meta}
	fg := &fakeGauge{}
	g := New(Options{Meta: meta, Evictor: ev, MapGauge: fg, Metrics: NewMetrics(), Interval: time.Hour})
	g.sweep(now)

	if got := fg.vals[bpf.MapMacTenant]; got != 1 {
		t.Errorf("mac_tenant_map gauge = %v, want 1 (2 entries, 1 swept)", got)
	}
}

// recordingEvictor mocks the kernel mac_tenant_map. It records each
// deleted MAC and — crucially — checks at delete time that the
// userspace entry still exists, so an inverted (userspace-first)
// deletion order is caught (docs/DESIGN.md §3.4). MACs in failOn return
// an error to model a kernel delete that fails.
type recordingEvictor struct {
	meta              *metadata.ShardedMetadataMap
	failOn            map[uint64]bool
	deleted           []uint64
	sawUserspaceFirst bool
}

func (e *recordingEvictor) Delete(mac uint64) error {
	if e.failOn[mac] {
		return errors.New("kernel delete failed")
	}
	if _, ok := e.meta.Lookup(mac); !ok {
		e.sawUserspaceFirst = true
	}
	e.deleted = append(e.deleted, mac)
	return nil
}

func newSweeper(t *testing.T, meta *metadata.ShardedMetadataMap, ev MacEvictor) (*GhostSweeper, *Metrics) {
	t.Helper()
	mx := NewMetrics()
	g := New(Options{Meta: meta, Evictor: ev, Metrics: mx, Interval: time.Hour})
	return g, mx
}

// recordingFlowEvictor mocks the kernel telemetry_map residual-flow
// cleanup. It reports flowsPerMAC deleted per MAC, and — like
// recordingEvictor — checks at call time that the swept MACs still exist
// in userspace, so an inverted order (userspace dropped before residual
// flows are evicted) is caught.
type recordingFlowEvictor struct {
	meta             *metadata.ShardedMetadataMap
	flowsPerMAC      int
	calls            int
	got              map[uint64]struct{}
	sawUserspaceGone bool
}

func (e *recordingFlowEvictor) DeleteFlowsForMACs(macs map[uint64]struct{}) (int, error) {
	e.calls++
	e.got = make(map[uint64]struct{}, len(macs))
	for mac := range macs {
		if _, ok := e.meta.Lookup(mac); !ok {
			e.sawUserspaceGone = true
		}
		e.got[mac] = struct{}{}
	}
	return len(macs) * e.flowsPerMAC, nil
}

// TestSweep_EvictsResidualFlowsBeforeUserspaceDelete locks the
// known→unknown residual-flow fix: a swept MAC's telemetry_map flows are
// evicted (for exactly the expired MACs) before the userspace entry is
// dropped, so they can never be re-billed as "unknown" (docs/DESIGN.md
// §3.3).
func TestSweep_EvictsResidualFlowsBeforeUserspaceDelete(t *testing.T) {
	meta := metadata.New()
	now := time.Now()
	const expired1, expired2, live = uint64(0x11), uint64(0x12), uint64(0x13)
	meta.Insert(expired1, &metadata.TenantMeta{ProjectID: "a"})
	meta.Insert(expired2, &metadata.TenantMeta{ProjectID: "b"})
	meta.Insert(live, &metadata.TenantMeta{ProjectID: "c"})
	meta.MarkDelete(expired1, now.Add(-time.Second))
	meta.MarkDelete(expired2, now.Add(-time.Second))

	ev := &recordingEvictor{meta: meta}
	fe := &recordingFlowEvictor{meta: meta, flowsPerMAC: 2}
	mx := NewMetrics()
	g := New(Options{Meta: meta, Evictor: ev, FlowEvictor: fe, Metrics: mx, Interval: time.Hour})
	g.sweep(now)

	if fe.sawUserspaceGone {
		t.Error("residual flows evicted after the userspace entry was dropped — a concurrent scrape could re-bill them as unknown")
	}
	if fe.calls != 1 {
		t.Fatalf("DeleteFlowsForMACs called %d times, want 1 (one batch per sweep)", fe.calls)
	}
	if _, ok := fe.got[expired1]; !ok {
		t.Error("expired1 missing from the residual-flow eviction set")
	}
	if _, ok := fe.got[expired2]; !ok {
		t.Error("expired2 missing from the residual-flow eviction set")
	}
	if _, ok := fe.got[live]; ok {
		t.Error("live MAC included in the residual-flow eviction set")
	}
	if got := testutil.ToFloat64(mx.evictions.WithLabelValues(reasonGhostResidualFlow)); got != 4 {
		t.Errorf("residual-flow evictions = %v, want 4 (2 MACs × 2 flows)", got)
	}
	if _, ok := meta.Lookup(expired1); ok {
		t.Error("expired1 still in userspace after sweep")
	}
}

// TestSweep_SettlesFlowsToTenantBeforeUserspaceDelete locks the
// settled-bytes fold (docs/DESIGN.md §3.5): the swept MAC's GlobalState
// rows fold into the settled accumulator under the tenant its metadata
// still resolves to — proving the fold runs before the userspace
// delete, since afterwards the tenant would be unknowable — with the
// rows' zone/direction preserved and the rows themselves evicted. A
// live VM's rows are untouched.
func TestSweep_SettlesFlowsToTenantBeforeUserspaceDelete(t *testing.T) {
	meta := metadata.New()
	now := time.Now()
	macDead := [6]uint8{0xaa, 0, 0, 0, 0, 1}
	macLive := [6]uint8{0xaa, 0, 0, 0, 0, 2}
	peer := [6]uint8{0xee, 0, 0, 0, 0, 9}
	meta.Insert(bpf.MACKey(macDead), &metadata.TenantMeta{ProjectID: "tenant-a"})
	meta.Insert(bpf.MACKey(macLive), &metadata.TenantMeta{ProjectID: "tenant-b"})
	meta.MarkDelete(bpf.MACKey(macDead), now.Add(-time.Second))

	st := state.New()
	// Dead VM sending (INGRESS → VM is SrcMac) and receiving (EGRESS →
	// VM is DstMac): two rows, distinct zones, both must fold.
	st.ApplyDelta(bpf.FlowKey{SrcMac: macDead, DstMac: peer, EthProto: 0x0800,
		Direction: bpf.DirectionIngress, DstZone: bpf.ZoneSameTenant},
		bpf.FlowMetrics{Bytes: 100, Packets: 2, LastSeenNs: 1})
	st.ApplyDelta(bpf.FlowKey{SrcMac: peer, DstMac: macDead, EthProto: 0x0800,
		Direction: bpf.DirectionEgress, DstZone: bpf.ZoneInfra},
		bpf.FlowMetrics{Bytes: 50, Packets: 1, LastSeenNs: 2})
	liveKey := bpf.FlowKey{SrcMac: macLive, DstMac: peer, EthProto: 0x0800,
		Direction: bpf.DirectionIngress, DstZone: bpf.ZoneSameTenant}
	st.ApplyDelta(liveKey, bpf.FlowMetrics{Bytes: 70, Packets: 1, LastSeenNs: 3})

	ev := &recordingEvictor{meta: meta}
	mx := NewMetrics()
	g := New(Options{Meta: meta, Evictor: ev, Settler: st, Metrics: mx, Interval: time.Hour})
	g.sweep(now)

	flows, settled := st.SnapshotWithSettled(nil, nil)
	if len(flows) != 1 || flows[0].Key != liveKey {
		t.Fatalf("flows after sweep = %+v, want only the live VM's row", flows)
	}
	want := map[state.SettledKey]uint64{
		{Tenant: "tenant-a", Zone: bpf.ZoneSameTenant, Dir: bpf.DirectionIngress}: 100,
		{Tenant: "tenant-a", Zone: bpf.ZoneInfra, Dir: bpf.DirectionEgress}:       50,
	}
	if len(settled) != len(want) {
		t.Fatalf("settled buckets = %+v, want %d buckets", settled, len(want))
	}
	for _, s := range settled {
		if want[s.Key] != s.Bytes {
			t.Errorf("settled[%+v] = %d bytes, want %d", s.Key, s.Bytes, want[s.Key])
		}
	}
	if got := testutil.ToFloat64(mx.settledFlows); got != 2 {
		t.Errorf("cubecos_gc_settled_flows_total = %v, want 2", got)
	}
}

// TestSweep_NilFlowEvictorStillSweeps confirms residual-flow cleanup is
// optional: with no FlowEvictor wired (tests, darwin) the ghost sweep
// still deletes expired MACs.
func TestSweep_NilFlowEvictorStillSweeps(t *testing.T) {
	meta := metadata.New()
	now := time.Now()
	const mac = uint64(0x21)
	meta.Insert(mac, &metadata.TenantMeta{ProjectID: "a"})
	meta.MarkDelete(mac, now.Add(-time.Second))

	ev := &recordingEvictor{meta: meta}
	g, mx := newSweeper(t, meta, ev) // no FlowEvictor
	g.sweep(now)

	if _, ok := meta.Lookup(mac); ok {
		t.Error("expired entry not swept when FlowEvictor is nil")
	}
	if got := testutil.ToFloat64(mx.evictions.WithLabelValues(reasonTTL)); got != 1 {
		t.Errorf("ttl evictions = %v, want 1", got)
	}
}

func TestSweep_DeletesExpiredKernelFirst(t *testing.T) {
	meta := metadata.New()
	now := time.Now()

	const live, expired, pending = uint64(0x01), uint64(0x02), uint64(0x03)
	meta.Insert(live, &metadata.TenantMeta{ProjectID: "live"})
	meta.Insert(expired, &metadata.TenantMeta{ProjectID: "expired"})
	meta.Insert(pending, &metadata.TenantMeta{ProjectID: "pending"})
	meta.MarkDelete(expired, now.Add(-time.Second)) // grace already elapsed
	meta.MarkDelete(pending, now.Add(time.Minute))  // still within grace

	ev := &recordingEvictor{meta: meta}
	g, mx := newSweeper(t, meta, ev)
	g.sweep(now)

	if ev.sawUserspaceFirst {
		t.Error("sweep deleted the userspace entry before the kernel entry (inverts DESIGN §3.4)")
	}
	if len(ev.deleted) != 1 || ev.deleted[0] != expired {
		t.Errorf("kernel deletes = %#x, want exactly [%#x]", ev.deleted, expired)
	}
	if _, ok := meta.Lookup(expired); ok {
		t.Error("expired entry still present in userspace after sweep")
	}
	if _, ok := meta.Lookup(pending); !ok {
		t.Error("pending ghost (grace not elapsed) was swept early")
	}
	if _, ok := meta.Lookup(live); !ok {
		t.Error("live entry (no DeleteAt) was swept")
	}

	if got := testutil.ToFloat64(mx.evictions.WithLabelValues(reasonTTL)); got != 1 {
		t.Errorf("ttl evictions = %v, want 1", got)
	}
	if got := testutil.ToFloat64(mx.ghostsActive); got != 1 {
		t.Errorf("lingering_ghosts_active = %v, want 1 (the pending ghost)", got)
	}
}

func TestSweep_KernelDeleteFailureRetainsUserspace(t *testing.T) {
	meta := metadata.New()
	now := time.Now()
	const mac = uint64(0x42)
	meta.Insert(mac, &metadata.TenantMeta{ProjectID: "t"})
	meta.MarkDelete(mac, now.Add(-time.Second))

	ev := &recordingEvictor{meta: meta, failOn: map[uint64]bool{mac: true}}
	g, mx := newSweeper(t, meta, ev)
	g.sweep(now)

	if _, ok := meta.Lookup(mac); !ok {
		t.Error("userspace entry deleted despite a failed kernel delete — breaks kernel⊆userspace")
	}
	if got := testutil.ToFloat64(mx.evictions.WithLabelValues(reasonTTL)); got != 0 {
		t.Errorf("ttl evictions = %v, want 0 (nothing successfully evicted)", got)
	}
}

func TestSweep_NoGhostsIsNoop(t *testing.T) {
	meta := metadata.New()
	meta.Insert(0x01, &metadata.TenantMeta{ProjectID: "a"})
	meta.Insert(0x02, &metadata.TenantMeta{ProjectID: "b"})

	ev := &recordingEvictor{meta: meta}
	g, mx := newSweeper(t, meta, ev)
	g.sweep(time.Now())

	if len(ev.deleted) != 0 {
		t.Errorf("deleted %d entries, want 0", len(ev.deleted))
	}
	if got := testutil.ToFloat64(mx.ghostsActive); got != 0 {
		t.Errorf("lingering_ghosts_active = %v, want 0", got)
	}
}

func TestRun_AwaitsStateRestoredBeforeSweeping(t *testing.T) {
	meta := metadata.New()
	const mac = uint64(0x7)
	meta.Insert(mac, &metadata.TenantMeta{ProjectID: "t"})
	meta.MarkDelete(mac, time.Now().Add(-time.Second)) // already expired

	seq := boot.New()
	ev := &recordingEvictor{meta: meta}
	g := New(Options{Meta: meta, Evictor: ev, Seq: seq, Metrics: NewMetrics(), Interval: 5 * time.Millisecond})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { g.Run(ctx); close(done) }()

	// While the boot has not reached PhaseStateRestored the sweeper must
	// stay parked, so the expired entry is still present.
	time.Sleep(30 * time.Millisecond)
	if _, ok := meta.Lookup(mac); !ok {
		t.Fatal("sweeper evicted before PhaseStateRestored — Await barrier not honoured")
	}

	for _, p := range []boot.Phase{boot.PhaseBPFLoaded, boot.PhaseMetadataReady, boot.PhaseAttached, boot.PhaseStateRestored} {
		if err := seq.Advance(p); err != nil {
			t.Fatalf("Advance(%s): %v", p, err)
		}
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, ok := meta.Lookup(mac); !ok {
			cancel()
			<-done
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("sweeper did not evict the expired entry after PhaseStateRestored")
}

func TestRun_ReturnsWhenBootAbortsBeforePhase(t *testing.T) {
	seq := boot.New()
	g := New(Options{
		Meta: metadata.New(), Evictor: &recordingEvictor{meta: metadata.New()},
		Seq: seq, Metrics: NewMetrics(), Interval: time.Hour,
	})

	done := make(chan struct{})
	go func() { g.Run(context.Background()); close(done) }()

	seq.Fail(boot.PhaseMetadataReady, errors.New("neutron unreachable"))
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not return after the boot aborted")
	}
}
