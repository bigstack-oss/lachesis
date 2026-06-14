package gc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/boot"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/metadata"
)

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
