package state_test

import (
	"sync"
	"testing"

	"github.com/bigstack-oss/lachesis/internal/bpf"
	"github.com/bigstack-oss/lachesis/internal/state"
)

func keyA() bpf.FlowKey {
	return bpf.FlowKey{
		SrcMac:    [6]uint8{0xaa, 0, 0, 0, 0, 1},
		DstMac:    [6]uint8{0xaa, 0, 0, 0, 0, 2},
		EthProto:  0x0800,
		Direction: bpf.DirectionEgress,
		DstZone:   bpf.ZoneExternal,
	}
}

func keyB() bpf.FlowKey {
	k := keyA()
	k.Direction = bpf.DirectionIngress
	return k
}

// TestResolve_WriteBackNoDoubleCount locks the late-binding write-back
// (docs/DESIGN.md §3.2): Resolve credits the buffered cumulative AND
// sets LastEbpfRaw, so the next ApplyDelta adds only the post-hand-off
// delta. A buggy Resolve that left LastEbpfRaw zero would re-count the
// full kernel cumulative (1500 + 1800 = 3300 here).
func TestResolve_WriteBackNoDoubleCount(t *testing.T) {
	g := state.New()
	// The UnresolvedBuffer accumulated 1500 bytes while the MAC was
	// unknown; the kernel cumulative it last observed was also 1500.
	g.Resolve(keyA(),
		bpf.FlowMetrics{Bytes: 1500, Packets: 8, LastSeenNs: 2},
		bpf.FlowMetrics{Bytes: 1500, Packets: 8, LastSeenNs: 2})
	// The next scrape sees the kernel at 1800 — only the 300-byte delta
	// since the hand-off should be added.
	g.ApplyDelta(keyA(), bpf.FlowMetrics{Bytes: 1800, Packets: 9, LastSeenNs: 3})

	dst := g.Snapshot(nil)
	if len(dst) != 1 {
		t.Fatalf("Snapshot returned %d entries, want 1", len(dst))
	}
	if got := dst[0].Total; got.Bytes != 1800 || got.Packets != 9 {
		t.Errorf("resolved Total = %+v, want {Bytes:1800 Packets:9} (1500 buffered + 300/1 delta, no double-count)", got)
	}
}

func TestApplyDelta_FirstSightDoesNotDoubleCount(t *testing.T) {
	g := state.New()
	g.ApplyDelta(keyA(), bpf.FlowMetrics{Bytes: 1000, Packets: 7, LastSeenNs: 42})

	dst := g.Snapshot(nil)
	if len(dst) != 1 {
		t.Fatalf("Snapshot returned %d entries, want 1", len(dst))
	}
	got := dst[0].Total
	want := bpf.FlowMetrics{Bytes: 1000, Packets: 7, LastSeenNs: 42}
	if got != want {
		t.Errorf("first-sight Total = %+v, want %+v", got, want)
	}
}

func TestApplyDelta_AccumulatesAcrossTicks(t *testing.T) {
	g := state.New()
	g.ApplyDelta(keyA(), bpf.FlowMetrics{Bytes: 100, Packets: 1, LastSeenNs: 1})
	g.ApplyDelta(keyA(), bpf.FlowMetrics{Bytes: 250, Packets: 3, LastSeenNs: 2})
	g.ApplyDelta(keyA(), bpf.FlowMetrics{Bytes: 1000, Packets: 9, LastSeenNs: 3})

	dst := g.Snapshot(nil)
	got := dst[0].Total
	// First sight set baseline 100/1. Two deltas: +150/+2 then +750/+6.
	want := bpf.FlowMetrics{Bytes: 1000, Packets: 9, LastSeenNs: 3}
	if got != want {
		t.Errorf("Total after deltas = %+v, want %+v", got, want)
	}
}

func TestApplyDelta_KernelResetTreatsCurrentAsDelta(t *testing.T) {
	g := state.New()
	g.ApplyDelta(keyA(), bpf.FlowMetrics{Bytes: 1000, Packets: 5, LastSeenNs: 1})
	g.ApplyDelta(keyA(), bpf.FlowMetrics{Bytes: 2500, Packets: 8, LastSeenNs: 2})
	// Kernel-side reset: bytes drops from 2500 to 50; packets 8 to 2.
	g.ApplyDelta(keyA(), bpf.FlowMetrics{Bytes: 50, Packets: 2, LastSeenNs: 3})

	dst := g.Snapshot(nil)
	got := dst[0].Total
	// Up to reset: baseline 1000 + delta 1500 = 2500 bytes, 5 + 3 = 8 packets.
	// Reset adds the new current as the delta itself: +50 / +2.
	want := bpf.FlowMetrics{Bytes: 2550, Packets: 10, LastSeenNs: 3}
	if got != want {
		t.Errorf("Total after reset = %+v, want %+v", got, want)
	}
}

func TestApplyDelta_KeysAreIndependent(t *testing.T) {
	g := state.New()
	g.ApplyDelta(keyA(), bpf.FlowMetrics{Bytes: 100, Packets: 1, LastSeenNs: 1})
	g.ApplyDelta(keyB(), bpf.FlowMetrics{Bytes: 200, Packets: 2, LastSeenNs: 1})
	g.ApplyDelta(keyA(), bpf.FlowMetrics{Bytes: 300, Packets: 4, LastSeenNs: 2})

	dst := g.Snapshot(nil)
	if len(dst) != 2 {
		t.Fatalf("Snapshot returned %d entries, want 2", len(dst))
	}
	byKey := map[bpf.FlowKey]bpf.FlowMetrics{
		dst[0].Key: dst[0].Total,
		dst[1].Key: dst[1].Total,
	}
	if got, want := byKey[keyA()], (bpf.FlowMetrics{Bytes: 300, Packets: 4, LastSeenNs: 2}); got != want {
		t.Errorf("keyA Total = %+v, want %+v", got, want)
	}
	if got, want := byKey[keyB()], (bpf.FlowMetrics{Bytes: 200, Packets: 2, LastSeenNs: 1}); got != want {
		t.Errorf("keyB Total = %+v, want %+v", got, want)
	}
}

func TestApplyDelta_LastSeenNsMonotonicOnTotal(t *testing.T) {
	g := state.New()
	g.ApplyDelta(keyA(), bpf.FlowMetrics{Bytes: 10, Packets: 1, LastSeenNs: 100})
	// An out-of-order kernel reading (e.g. timestamp jitter across CPUs)
	// must not pull Total.LastSeenNs backward.
	g.ApplyDelta(keyA(), bpf.FlowMetrics{Bytes: 20, Packets: 2, LastSeenNs: 50})

	dst := g.Snapshot(nil)
	if got := dst[0].Total.LastSeenNs; got != 100 {
		t.Errorf("Total.LastSeenNs = %d, want 100 (monotonic)", got)
	}
}

func TestSnapshot_ReusesCapacity(t *testing.T) {
	g := state.New()
	for i := 0; i < 8; i++ {
		k := keyA()
		k.SrcMac[5] = byte(i)
		g.ApplyDelta(k, bpf.FlowMetrics{Bytes: 1, Packets: 1, LastSeenNs: 1})
	}

	dst := g.Snapshot(nil)
	if len(dst) != 8 {
		t.Fatalf("first Snapshot len = %d, want 8", len(dst))
	}
	cap1 := cap(dst)

	// Reset length, reuse capacity, populate again — capacity should not grow.
	dst = g.Snapshot(dst[:0])
	if len(dst) != 8 {
		t.Fatalf("second Snapshot len = %d, want 8", len(dst))
	}
	if cap(dst) != cap1 {
		t.Errorf("Snapshot grew capacity: %d → %d (should reuse)", cap1, cap(dst))
	}
}

func TestLen(t *testing.T) {
	g := state.New()
	if got := g.Len(); got != 0 {
		t.Errorf("Len on empty = %d, want 0", got)
	}
	g.ApplyDelta(keyA(), bpf.FlowMetrics{Bytes: 1})
	g.ApplyDelta(keyB(), bpf.FlowMetrics{Bytes: 1})
	g.ApplyDelta(keyA(), bpf.FlowMetrics{Bytes: 2}) // existing key — no new entry
	if got := g.Len(); got != 2 {
		t.Errorf("Len after inserts = %d, want 2", got)
	}
}

func TestSnapshotForWAL_ReturnsTotalAndLastRaw(t *testing.T) {
	g := state.New()
	g.ApplyDelta(keyA(), bpf.FlowMetrics{Bytes: 100, Packets: 1, LastSeenNs: 10})
	g.ApplyDelta(keyA(), bpf.FlowMetrics{Bytes: 250, Packets: 3, LastSeenNs: 20})

	records, _ := g.SnapshotForWAL(nil, nil)
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	r := records[0]
	// Total = baseline 100 + delta 150 = 250.
	if got, want := r.Counter.Total.Bytes, uint64(250); got != want {
		t.Errorf("Total.Bytes = %d, want %d", got, want)
	}
	// LastEbpfRaw = the most recent raw reading.
	if got, want := r.Counter.LastEbpfRaw.Bytes, uint64(250); got != want {
		t.Errorf("LastEbpfRaw.Bytes = %d, want %d", got, want)
	}
}

func TestRestore_SeedsBothTotalAndLastRaw(t *testing.T) {
	g := state.New()
	g.Restore([]state.Record{{
		Key: keyA(),
		Counter: state.Counter{
			Total:       bpf.FlowMetrics{Bytes: 1000, Packets: 10, LastSeenNs: 100},
			LastEbpfRaw: bpf.FlowMetrics{Bytes: 900, Packets: 9, LastSeenNs: 90},
		},
	}})

	// The next ApplyDelta must compute delta against the restored
	// LastEbpfRaw, not re-baseline. Raw 1000 → delta = 100 → Total = 1100.
	g.ApplyDelta(keyA(), bpf.FlowMetrics{Bytes: 1000, Packets: 11, LastSeenNs: 200})

	records, _ := g.SnapshotForWAL(nil, nil)
	r := records[0]
	if got, want := r.Counter.Total.Bytes, uint64(1100); got != want {
		t.Errorf("Total.Bytes after restore + delta = %d, want %d (= 1000 + (1000-900))", got, want)
	}
	if got, want := r.Counter.Total.Packets, uint64(12); got != want {
		t.Errorf("Total.Packets after restore + delta = %d, want %d (= 10 + (11-9))", got, want)
	}
}

func TestRestore_OverwritesExistingKey(t *testing.T) {
	g := state.New()
	g.ApplyDelta(keyA(), bpf.FlowMetrics{Bytes: 50})
	g.Restore([]state.Record{{
		Key: keyA(),
		Counter: state.Counter{
			Total:       bpf.FlowMetrics{Bytes: 9999},
			LastEbpfRaw: bpf.FlowMetrics{Bytes: 9999},
		},
	}})

	records, _ := g.SnapshotForWAL(nil, nil)
	if got, want := records[0].Counter.Total.Bytes, uint64(9999); got != want {
		t.Errorf("Restore did not overwrite: got %d, want %d", got, want)
	}
}

func TestSnapshotForWAL_ReusesCapacity(t *testing.T) {
	g := state.New()
	for i := 0; i < 8; i++ {
		k := keyA()
		k.SrcMac[5] = byte(i)
		g.ApplyDelta(k, bpf.FlowMetrics{Bytes: 1})
	}
	dst, _ := g.SnapshotForWAL(nil, nil)
	cap1 := cap(dst)
	dst, _ = g.SnapshotForWAL(dst[:0], nil)
	if cap(dst) != cap1 {
		t.Errorf("SnapshotForWAL grew capacity: %d → %d", cap1, cap(dst))
	}
}

// TestConcurrent_ApplyAndSnapshot exercises the RWMutex contract under
// the race detector. With -race, any unsynchronised access will fail.
func TestConcurrent_ApplyAndSnapshot(t *testing.T) {
	g := state.New()
	var wg sync.WaitGroup

	writer := func(seed byte) {
		defer wg.Done()
		k := keyA()
		k.SrcMac[5] = seed
		for i := 0; i < 1000; i++ {
			g.ApplyDelta(k, bpf.FlowMetrics{Bytes: uint64(i), Packets: uint64(i), LastSeenNs: uint64(i)})
		}
	}
	reader := func() {
		defer wg.Done()
		var buf []state.Entry
		for i := 0; i < 1000; i++ {
			buf = g.Snapshot(buf[:0])
			_ = buf
		}
	}

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go writer(byte(i))
	}
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go reader()
	}
	wg.Wait()
}

func TestAdd_AccumulatesMonotonicallyWithoutDeltaMath(t *testing.T) {
	g := state.New()
	// Add is additive: two Adds sum, with no delta math against a raw
	// reading (the UnresolvedBuffer fold path).
	g.Add(keyA(), bpf.FlowMetrics{Bytes: 100, Packets: 2, LastSeenNs: 10})
	g.Add(keyA(), bpf.FlowMetrics{Bytes: 250, Packets: 3, LastSeenNs: 5}) // older LastSeenNs ignored

	dst := g.Snapshot(nil)
	if len(dst) != 1 {
		t.Fatalf("Snapshot returned %d entries, want 1", len(dst))
	}
	got := dst[0].Total
	want := bpf.FlowMetrics{Bytes: 350, Packets: 5, LastSeenNs: 10}
	if got != want {
		t.Errorf("Add Total = %+v, want %+v", got, want)
	}
}

func TestAdd_DoesNotPrimeDeltaBaseline(t *testing.T) {
	// A key only ever touched by Add must keep its LastEbpfRaw at zero so
	// it stays a pure additive ("unknown") series; Add never reads it.
	// We can't see LastEbpfRaw directly, but a WAL round-trip exposes the
	// Counter — assert the cumulative is exactly what was Added.
	g := state.New()
	g.Add(keyA(), bpf.FlowMetrics{Bytes: 4242, Packets: 7, LastSeenNs: 1})
	recs, _ := g.SnapshotForWAL(nil, nil)
	if len(recs) != 1 {
		t.Fatalf("SnapshotForWAL returned %d records, want 1", len(recs))
	}
	if recs[0].Counter.Total.Bytes != 4242 {
		t.Errorf("Total.Bytes = %d, want 4242", recs[0].Counter.Total.Bytes)
	}
	if recs[0].Counter.LastEbpfRaw.Bytes != 0 {
		t.Errorf("LastEbpfRaw.Bytes = %d, want 0 (Add must not prime the delta baseline)", recs[0].Counter.LastEbpfRaw.Bytes)
	}
}

// settleAll resolves every key to one tenant — the common test fold.
func settleAll(tenant string) func(bpf.FlowKey) (string, bool) {
	return func(bpf.FlowKey) (string, bool) { return tenant, true }
}

// TestSettle_EvictMovesTotalsAndDeletesRows: the ghost-sweep fold.
// Value moves from the flow rows into per-(tenant, zone, direction)
// settled buckets — the per-tuple sum is unchanged — and the folded
// rows are gone. Unresolved rows are untouched.
func TestSettle_EvictMovesTotalsAndDeletesRows(t *testing.T) {
	g := state.New()
	g.ApplyDelta(keyA(), bpf.FlowMetrics{Bytes: 100, Packets: 2, LastSeenNs: 1})
	g.ApplyDelta(keyB(), bpf.FlowMetrics{Bytes: 50, Packets: 1, LastSeenNs: 2})

	folded := g.Settle(state.SettleEvict, func(k bpf.FlowKey) (string, bool) {
		if k == keyA() {
			return "tenant-a", true
		}
		return "", false
	})
	if folded != 1 {
		t.Fatalf("Settle folded %d rows, want 1", folded)
	}
	flows, settled := g.SnapshotWithSettled(nil, nil)
	if len(flows) != 1 || flows[0].Key != keyB() || flows[0].Total.Bytes != 50 {
		t.Errorf("flows = %+v, want only keyB with 50 bytes", flows)
	}
	want := state.SettledKey{Tenant: "tenant-a", Zone: keyA().DstZone, Dir: keyA().Direction}
	if len(settled) != 1 || settled[0].Key != want || settled[0].Bytes != 100 || settled[0].Packets != 2 {
		t.Errorf("settled = %+v, want 100 bytes / 2 packets under %+v", settled, want)
	}
}

// TestSettle_EvictAccumulatesIntoExistingBucket: two folds to the same
// tuple add up — settled buckets only grow.
func TestSettle_EvictAccumulatesIntoExistingBucket(t *testing.T) {
	g := state.New()
	g.ApplyDelta(keyA(), bpf.FlowMetrics{Bytes: 100, Packets: 1, LastSeenNs: 1})
	g.Settle(state.SettleEvict, settleAll("t1"))
	g.ApplyDelta(keyA(), bpf.FlowMetrics{Bytes: 30, Packets: 1, LastSeenNs: 2})
	g.Settle(state.SettleEvict, settleAll("t1"))

	_, settled := g.SnapshotWithSettled(nil, nil)
	if len(settled) != 1 || settled[0].Bytes != 130 {
		t.Errorf("settled = %+v, want one bucket with 130 bytes", settled)
	}
}

// TestSettle_RebaseZerosTotalKeepsWatermark: the tenant-change fold.
// The row survives with Total zeroed and LastEbpfRaw intact, so the
// next ApplyDelta counts only bytes that arrived after the fold.
func TestSettle_RebaseZerosTotalKeepsWatermark(t *testing.T) {
	g := state.New()
	g.ApplyDelta(keyA(), bpf.FlowMetrics{Bytes: 100, Packets: 4, LastSeenNs: 1})

	g.Settle(state.SettleRebase, settleAll("t-old"))

	flows, settled := g.SnapshotWithSettled(nil, nil)
	if len(flows) != 1 || flows[0].Total.Bytes != 0 {
		t.Fatalf("flows = %+v, want the row kept with Total zeroed", flows)
	}
	if len(settled) != 1 || settled[0].Bytes != 100 {
		t.Fatalf("settled = %+v, want 100 bytes", settled)
	}

	// Kernel cumulative advances 100→130: only the 30 delta accrues.
	g.ApplyDelta(keyA(), bpf.FlowMetrics{Bytes: 130, Packets: 5, LastSeenNs: 2})
	flows, _ = g.SnapshotWithSettled(nil, nil)
	if flows[0].Total.Bytes != 30 {
		t.Errorf("post-rebase Total = %d, want 30 (settled cumulative must not replay)", flows[0].Total.Bytes)
	}
}

// TestSettledWALRoundTrip: SnapshotForWAL emits the settled buckets and
// RestoreSettled seeds them back — restart-safe.
func TestSettledWALRoundTrip(t *testing.T) {
	g := state.New()
	g.ApplyDelta(keyA(), bpf.FlowMetrics{Bytes: 100, Packets: 2, LastSeenNs: 1})
	g.Settle(state.SettleEvict, settleAll("t1"))

	_, settled := g.SnapshotForWAL(nil, nil)
	if len(settled) != 1 {
		t.Fatalf("SnapshotForWAL settled = %+v, want 1 bucket", settled)
	}

	fresh := state.New()
	fresh.RestoreSettled(settled)
	if fresh.SettledLen() != 1 {
		t.Fatalf("SettledLen after restore = %d, want 1", fresh.SettledLen())
	}
	_, got := fresh.SnapshotWithSettled(nil, nil)
	if got[0] != settled[0] {
		t.Errorf("restored settled = %+v, want %+v", got[0], settled[0])
	}
}
