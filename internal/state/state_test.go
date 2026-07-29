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
// (docs/architecture/data-structures.md#userspace-structures): Resolve credits the buffered cumulative AND
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

	records, _, _, _ := g.SnapshotForWAL(nil, nil, nil, nil)
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

	records, _, _, _ := g.SnapshotForWAL(nil, nil, nil, nil)
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

	records, _, _, _ := g.SnapshotForWAL(nil, nil, nil, nil)
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
	dst, _, _, _ := g.SnapshotForWAL(nil, nil, nil, nil)
	cap1 := cap(dst)
	dst, _, _, _ = g.SnapshotForWAL(dst[:0], nil, nil, nil)
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
	recs, _, _, _ := g.SnapshotForWAL(nil, nil, nil, nil)
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

// settleAll resolves every key to one tenant with the "none"
// external-network sentinel — the common test fold.
func settleAll(tenant string) func(bpf.FlowKey) (string, string, string, bool) {
	return func(bpf.FlowKey) (string, string, string, bool) { return tenant, "none", "", true }
}

// TestSettle_EvictMovesTotalsAndDeletesRows: the ghost-sweep fold.
// Value moves from the flow rows into per-(tenant, zone, direction)
// settled buckets — the per-tuple sum is unchanged — and the folded
// rows are gone. Unresolved rows are untouched.
func TestSettle_EvictMovesTotalsAndDeletesRows(t *testing.T) {
	g := state.New()
	g.ApplyDelta(keyA(), bpf.FlowMetrics{Bytes: 100, Packets: 2, LastSeenNs: 1})
	g.ApplyDelta(keyB(), bpf.FlowMetrics{Bytes: 50, Packets: 1, LastSeenNs: 2})

	folded := g.Settle(state.SettleEvict, func(k bpf.FlowKey) (string, string, string, bool) {
		if k == keyA() {
			return "tenant-a", "none", "", true
		}
		return "", "", "", false
	})
	if folded != 1 {
		t.Fatalf("Settle folded %d rows, want 1", folded)
	}
	flows, settled, _, _ := g.SnapshotWithSettled(nil, nil, nil, nil)
	if len(flows) != 1 || flows[0].Key != keyB() || flows[0].Total.Bytes != 50 {
		t.Errorf("flows = %+v, want only keyB with 50 bytes", flows)
	}
	want := state.TenantSettledKey{Tenant: "tenant-a", ExtNet: "none", Zone: keyA().DstZone, Dir: keyA().Direction}
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

	_, settled, _, _ := g.SnapshotWithSettled(nil, nil, nil, nil)
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

	flows, settled, _, _ := g.SnapshotWithSettled(nil, nil, nil, nil)
	if len(flows) != 1 || flows[0].Total.Bytes != 0 {
		t.Fatalf("flows = %+v, want the row kept with Total zeroed", flows)
	}
	if len(settled) != 1 || settled[0].Bytes != 100 {
		t.Fatalf("settled = %+v, want 100 bytes", settled)
	}

	// Kernel cumulative advances 100→130: only the 30 delta accrues.
	g.ApplyDelta(keyA(), bpf.FlowMetrics{Bytes: 130, Packets: 5, LastSeenNs: 2})
	flows, _, _, _ = g.SnapshotWithSettled(nil, nil, nil, nil)
	if flows[0].Total.Bytes != 30 {
		t.Errorf("post-rebase Total = %d, want 30 (settled cumulative must not replay)", flows[0].Total.Bytes)
	}
}

// TestSettledWALRoundTrip: SnapshotForWAL emits the settled buckets and
// RestoreTenantSettled seeds them back — restart-safe.
func TestSettledWALRoundTrip(t *testing.T) {
	g := state.New()
	g.ApplyDelta(keyA(), bpf.FlowMetrics{Bytes: 100, Packets: 2, LastSeenNs: 1})
	g.Settle(state.SettleEvict, settleAll("t1"))

	_, settled, _, _ := g.SnapshotForWAL(nil, nil, nil, nil)
	if len(settled) != 1 {
		t.Fatalf("SnapshotForWAL settled = %+v, want 1 bucket", settled)
	}

	fresh := state.New()
	fresh.RestoreTenantSettled(settled)
	if fresh.TenantSettledLen() != 1 {
		t.Fatalf("TenantSettledLen after restore = %d, want 1", fresh.TenantSettledLen())
	}
	_, got, _, _ := fresh.SnapshotWithSettled(nil, nil, nil, nil)
	if got[0] != settled[0] {
		t.Errorf("restored settled = %+v, want %+v", got[0], settled[0])
	}
}

// TestSettle_DistinctExternalNetworksSeparateBuckets: the same tenant's
// folds land in per-external_network buckets, mirroring the label tuple
// the Collector emits — folding an EXTERNAL flow must not contaminate
// the "none" bucket (and vice versa).
func TestSettle_DistinctExternalNetworksSeparateBuckets(t *testing.T) {
	g := state.New()
	g.ApplyDelta(keyA(), bpf.FlowMetrics{Bytes: 100, Packets: 1, LastSeenNs: 1})
	g.Settle(state.SettleEvict, func(bpf.FlowKey) (string, string, string, bool) { return "t1", "public-1", "", true })
	g.ApplyDelta(keyA(), bpf.FlowMetrics{Bytes: 40, Packets: 1, LastSeenNs: 2})
	g.Settle(state.SettleEvict, func(bpf.FlowKey) (string, string, string, bool) { return "t1", "none", "", true })

	_, settled, _, _ := g.SnapshotWithSettled(nil, nil, nil, nil)
	if len(settled) != 2 {
		t.Fatalf("settled = %+v, want 2 buckets (public-1, none)", settled)
	}
	got := map[string]uint64{}
	for _, s := range settled {
		got[s.Key.ExtNet] = s.Bytes
	}
	if got["public-1"] != 100 || got["none"] != 40 {
		t.Errorf("bucket split = %v, want public-1:100 none:40", got)
	}
}

// serverKey builds a flow key on one server's series tuple — same zone +
// direction, a distinct src MAC per port — so two ports feed one
// per-server series (the lachesis#226 shape).
func serverKey(port uint8) bpf.FlowKey {
	return bpf.FlowKey{
		SrcMac:    [6]uint8{0xaa, 0, 0, 0, 0, port},
		DstMac:    [6]uint8{0xee, 0, 0, 0, 0, 9},
		EthProto:  0x0800,
		Direction: bpf.DirectionEgress,
		DstZone:   bpf.ZoneExternal,
	}
}

// TestServerSettled_FoldCreditsBothAccumulators: a SettleEvict fold that
// resolves a server_id credits BOTH the tenant-settled and the
// server-settled accumulators with the folded bytes, in one call.
func TestServerSettled_FoldCreditsBothAccumulators(t *testing.T) {
	g := state.New()
	g.ApplyDelta(serverKey(1), bpf.FlowMetrics{Bytes: 600, Packets: 6, LastSeenNs: 1})
	folded := g.Settle(state.SettleEvict, func(bpf.FlowKey) (string, string, string, bool) {
		return "t1", "none", "srv-1", true
	})
	if folded != 1 {
		t.Fatalf("folded %d, want 1", folded)
	}
	_, settled, serverSettled, _ := g.SnapshotWithSettled(nil, nil, nil, nil)
	if len(settled) != 1 || settled[0].Bytes != 600 {
		t.Fatalf("tenant settled = %+v, want one 600-byte bucket", settled)
	}
	if len(serverSettled) != 1 || serverSettled[0].Key.ServerID != "srv-1" || serverSettled[0].Bytes != 600 {
		t.Fatalf("server settled = %+v, want srv-1 with 600 bytes", serverSettled)
	}
}

// TestServerSettled_NoServerNoBucket: rows with no server_id credit the
// tenant accumulator only — unattributable traffic has no server series.
func TestServerSettled_NoServerNoBucket(t *testing.T) {
	g := state.New()
	g.ApplyDelta(serverKey(1), bpf.FlowMetrics{Bytes: 100, Packets: 1, LastSeenNs: 1})
	g.Settle(state.SettleEvict, settleAll("t1"))
	if g.ServerSettledLen() != 0 {
		t.Fatalf("ServerSettledLen = %d, want 0 for a server-less fold", g.ServerSettledLen())
	}
	if g.TenantSettledLen() != 1 {
		t.Fatalf("TenantSettledLen = %d, want 1", g.TenantSettledLen())
	}
}

// TestPruneServerSettled_DropsDeadHoldsAlive: the reconciler's Nova-list
// prune drops only buckets whose server left the list; everything else —
// including buckets for servers momentarily without live rows — is held.
func TestPruneServerSettled_DropsDeadHoldsAlive(t *testing.T) {
	g := state.New()
	g.ApplyDelta(serverKey(1), bpf.FlowMetrics{Bytes: 600, Packets: 6, LastSeenNs: 1})
	g.ApplyDelta(serverKey(2), bpf.FlowMetrics{Bytes: 400, Packets: 4, LastSeenNs: 1})
	g.Settle(state.SettleEvict, func(k bpf.FlowKey) (string, string, string, bool) {
		if k == serverKey(1) {
			return "t1", "none", "srv-1", true
		}
		return "t1", "none", "srv-2", true
	})
	if g.ServerSettledLen() != 2 {
		t.Fatalf("ServerSettledLen = %d, want 2", g.ServerSettledLen())
	}

	// Both servers still in the Nova list → nothing dropped, even though
	// srv-1 has no live rows at all (portless-but-alive flat line).
	alive := map[string]struct{}{"srv-1": {}, "srv-2": {}}
	if dropped := g.PruneServerSettled(alive); dropped != 0 {
		t.Fatalf("dropped %d with both servers alive, want 0", dropped)
	}

	// srv-1 deleted from Nova → its bucket (and only its) is released.
	if dropped := g.PruneServerSettled(map[string]struct{}{"srv-2": {}}); dropped != 1 {
		t.Fatalf("dropped %d, want 1", dropped)
	}
	_, _, serverSettled, _ := g.SnapshotWithSettled(nil, nil, nil, nil)
	if len(serverSettled) != 1 || serverSettled[0].Key.ServerID != "srv-2" {
		t.Fatalf("server settled after prune = %+v, want only srv-2", serverSettled)
	}
}

// TestServerSettled_SameServerResume: the detach→reattach-same-server
// shape (lachesis#233). The fold parks the bytes in the server's bucket;
// the reattached port's fresh kernel counter starts a new row from zero;
// live + server-settled for the tuple never dips and resumes growth.
func TestServerSettled_SameServerResume(t *testing.T) {
	g := state.New()
	g.ApplyDelta(serverKey(1), bpf.FlowMetrics{Bytes: 600, Packets: 6, LastSeenNs: 1})
	// Detach: ghost-fold the port's row.
	g.Settle(state.SettleEvict, func(bpf.FlowKey) (string, string, string, bool) {
		return "t1", "none", "srv-1", true
	})
	// Reattach: the same tuple's traffic returns on a fresh kernel
	// counter. The tap's counter began at zero at attach, so the first
	// reading (50) is all genuinely post-reattach bytes — first sight
	// seeds Total=raw, and the next delta adds 40 more.
	g.ApplyDelta(serverKey(1), bpf.FlowMetrics{Bytes: 50, Packets: 1, LastSeenNs: 2})
	g.ApplyDelta(serverKey(1), bpf.FlowMetrics{Bytes: 90, Packets: 2, LastSeenNs: 3})

	flows, _, serverSettled, _ := g.SnapshotWithSettled(nil, nil, nil, nil)
	var live uint64
	for _, f := range flows {
		live += f.Total.Bytes
	}
	var parked uint64
	for _, s := range serverSettled {
		parked += s.Bytes
	}
	// 600 parked + 90 live = 690: pre-detach bytes appear exactly once
	// (the bucket), post-reattach bytes exactly once (the live row) —
	// the emitted sum resumed from the detach point, never below 600,
	// no double-count.
	if parked != 600 || live != 90 {
		t.Fatalf("parked=%d live=%d, want 600/90 — sum must resume from the detach point", parked, live)
	}
}

// tenantKey builds flow keys that resolve to distinct tenants: one
// tuple per tenant index under the same zone/direction, a distinct
// src MAC per tenant — the lachesis#251 prune shape.
func tenantKey(tenant uint8) bpf.FlowKey {
	return bpf.FlowKey{
		SrcMac:    [6]uint8{0xbb, 0, 0, 0, 0, tenant},
		DstMac:    [6]uint8{0xee, 0, 0, 0, 0, 9},
		EthProto:  0x0800,
		Direction: bpf.DirectionEgress,
		DstZone:   bpf.ZoneExternal,
	}
}

// TestPruneTenantSettled_FoldsIntoTotalAndDrops: the reconciler's
// Keystone-list prune is a settle-to-parent — a dead project's bucket
// folds into the total-settled absorber (the total tier is derived, so
// a plain delete would dip it) and only then disappears; per-key value
// is conserved across the fold.
func TestPruneTenantSettled_FoldsIntoTotalAndDrops(t *testing.T) {
	g := state.New()
	g.ApplyDelta(tenantKey(1), bpf.FlowMetrics{Bytes: 600, Packets: 6, LastSeenNs: 1})
	g.ApplyDelta(tenantKey(2), bpf.FlowMetrics{Bytes: 400, Packets: 4, LastSeenNs: 1})
	g.Settle(state.SettleEvict, func(k bpf.FlowKey) (string, string, string, bool) {
		if k == tenantKey(1) {
			return "t-dead", "none", "", true
		}
		return "t-alive", "none", "", true
	})

	// Both projects still in the Keystone list → nothing released.
	alive := map[string]struct{}{"t-dead": {}, "t-alive": {}}
	if dropped := g.PruneTenantSettled(alive); dropped != 0 {
		t.Fatalf("dropped %d with both projects alive, want 0", dropped)
	}
	if g.TotalSettledLen() != 0 {
		t.Fatalf("TotalSettledLen = %d before any release, want 0", g.TotalSettledLen())
	}

	// t-dead deleted from Keystone → its bucket folds into the total
	// absorber and is released; t-alive is untouched.
	if dropped := g.PruneTenantSettled(map[string]struct{}{"t-alive": {}}); dropped != 1 {
		t.Fatalf("dropped %d, want 1", dropped)
	}
	_, settled, _, totalSettled := g.SnapshotWithSettled(nil, nil, nil, nil)
	if len(settled) != 1 || settled[0].Key.Tenant != "t-alive" || settled[0].Bytes != 400 {
		t.Fatalf("tenant settled after prune = %+v, want only t-alive with 400 bytes", settled)
	}
	if len(totalSettled) != 1 || totalSettled[0].Bytes != 600 || totalSettled[0].Packets != 6 {
		t.Fatalf("total settled = %+v, want one 600-byte/6-packet bucket", totalSettled)
	}
	want := state.TotalSettledKey{ExtNet: "none", Zone: bpf.ZoneExternal, Dir: bpf.DirectionEgress}
	if totalSettled[0].Key != want {
		t.Fatalf("total settled key = %+v, want %+v", totalSettled[0].Key, want)
	}
}

// TestPruneTenantSettled_AccumulatesSharedTuple: two dead projects on
// the same (zone, ext, dir) tuple accumulate into ONE total bucket —
// and a second prune round adds on top of the first, never overwrites.
func TestPruneTenantSettled_AccumulatesSharedTuple(t *testing.T) {
	g := state.New()
	g.ApplyDelta(tenantKey(1), bpf.FlowMetrics{Bytes: 600, Packets: 6, LastSeenNs: 1})
	g.ApplyDelta(tenantKey(2), bpf.FlowMetrics{Bytes: 400, Packets: 4, LastSeenNs: 1})
	g.Settle(state.SettleEvict, func(k bpf.FlowKey) (string, string, string, bool) {
		if k == tenantKey(1) {
			return "t-dead-1", "none", "", true
		}
		return "t-dead-2", "none", "", true
	})

	if dropped := g.PruneTenantSettled(map[string]struct{}{"t-dead-2": {}}); dropped != 1 {
		t.Fatalf("first round dropped %d, want 1", dropped)
	}
	if dropped := g.PruneTenantSettled(map[string]struct{}{}); dropped != 1 {
		t.Fatalf("second round dropped %d, want 1", dropped)
	}
	_, _, _, totalSettled := g.SnapshotWithSettled(nil, nil, nil, nil)
	if len(totalSettled) != 1 || totalSettled[0].Bytes != 1000 || totalSettled[0].Packets != 10 {
		t.Fatalf("total settled = %+v, want one accumulated 1000-byte/10-packet bucket", totalSettled)
	}
}

// TestRestoreTotalSettled_RoundTrip: the WAL seed path — records
// restored at boot come back bit-exact through the combined snapshot.
func TestRestoreTotalSettled_RoundTrip(t *testing.T) {
	g := state.New()
	want := []state.TotalSettledRecord{{
		Key:   state.TotalSettledKey{ExtNet: "net-ext", Zone: bpf.ZoneExternal, Dir: bpf.DirectionIngress},
		Bytes: 1 << 40, Packets: 1 << 20,
	}}
	g.RestoreTotalSettled(want)
	if g.TotalSettledLen() != 1 {
		t.Fatalf("TotalSettledLen = %d, want 1", g.TotalSettledLen())
	}
	_, _, _, got := g.SnapshotWithSettled(nil, nil, nil, nil)
	if len(got) != 1 || got[0] != want[0] {
		t.Fatalf("snapshot = %+v, want %+v", got, want)
	}
	flows, settled, serverSettled, totals := g.SnapshotForWAL(nil, nil, nil, nil)
	if len(flows) != 0 || len(settled) != 0 || len(serverSettled) != 0 || len(totals) != 1 || totals[0] != want[0] {
		t.Fatalf("SnapshotForWAL totals = %+v, want %+v", totals, want)
	}
}

// The entry-identity stamp (ADR 0014) lets ApplyDelta tell "this counter
// advanced" from "a different entry now occupies this key" without
// inferring it from magnitudes. These pin the three-way rule.

// TestApplyDelta_NewEntryCountedWhole is the lachesis#287 case, now
// caught in-band. The evicted entry's replacement climbs PAST the old
// baseline before the next scrape, so the value guard (current<lastRaw)
// cannot see the reset — only the changed stamp can.
func TestApplyDelta_NewEntryCountedWhole(t *testing.T) {
	g := state.New()
	k := keyA()
	g.ApplyDelta(k, bpf.FlowMetrics{Bytes: 1_200_000, Packets: 20, CreatedNs: 111})

	// Evicted and re-created (new stamp); climbs to 1_300_000 — above the
	// old baseline, so magnitudes alone read this as a 100_000 advance.
	g.ApplyDelta(k, bpf.FlowMetrics{Bytes: 1_300_000, Packets: 21, CreatedNs: 222})

	if got, want := totalBytes(t, g, k), uint64(2_500_000); got != want {
		t.Errorf("total = %d, want %d — a changed created_ns means a different entry, "+
			"so its counter must be taken whole (got the %d a stale-baseline diff produces)",
			got, want, 1_200_000+100_000)
	}
}

// TestApplyDelta_SameEntryDiffs: an unchanged stamp is the ordinary
// case and must still difference, not re-add.
func TestApplyDelta_SameEntryDiffs(t *testing.T) {
	g := state.New()
	k := keyA()
	g.ApplyDelta(k, bpf.FlowMetrics{Bytes: 600_000, CreatedNs: 111})
	g.ApplyDelta(k, bpf.FlowMetrics{Bytes: 900_000, CreatedNs: 111})

	if got, want := totalBytes(t, g, k), uint64(900_000); got != want {
		t.Errorf("total = %d, want %d (600_000 first sight + 300_000 delta)", got, want)
	}
}

// TestApplyDelta_UnknownIdentityFallsBackToValueGuard is the migration
// guard, and the one that would hurt most if it were wrong.
//
// A v6 WAL has no created_ns, so a restored baseline decodes as 0. If 0
// were treated as "different entry", the first scrape of a PINNED map
// that survived the restart would re-count its entire cumulative. Zero
// must mean "identity unknown" and defer to the value guard.
func TestApplyDelta_UnknownIdentityFallsBackToValueGuard(t *testing.T) {
	g := state.New()
	k := keyA()
	// A v6 restore: 5 GB already counted, baseline carries no stamp.
	g.Restore([]state.Record{{Key: k, Counter: state.Counter{
		Total:       bpf.FlowMetrics{Bytes: 5_000_000_000},
		LastEbpfRaw: bpf.FlowMetrics{Bytes: 5_000_000_000}, // CreatedNs zero
	}}})

	// The pinned kernel entry survived and has advanced by 1_000. It now
	// reports a real stamp for the first time.
	g.ApplyDelta(k, bpf.FlowMetrics{Bytes: 5_000_001_000, CreatedNs: 333})

	if got, want := totalBytes(t, g, k), uint64(5_000_001_000); got != want {
		t.Errorf("total = %d, want %d — unknown identity must diff, not re-count; "+
			"treating 0 as a reset would double to %d", got, want, 10_000_001_000)
	}

	// ...and the stamp is adopted, so the NEXT eviction is detected.
	g.ApplyDelta(k, bpf.FlowMetrics{Bytes: 2_000, CreatedNs: 444})
	if got, want := totalBytes(t, g, k), uint64(5_000_003_000); got != want {
		t.Errorf("total = %d, want %d — the stamp must be adopted after the "+
			"unknown-identity scrape", got, want)
	}
}

func totalBytes(t *testing.T, g *state.GlobalState, k bpf.FlowKey) uint64 {
	t.Helper()
	for _, e := range g.Snapshot(nil) {
		if e.Key == k {
			return e.Total.Bytes
		}
	}
	t.Fatalf("key absent from snapshot")
	return 0
}

// TestApplyDelta_SurvivingEntryDoesNotDoubleCount pins the property the
// removed BaselineInvalidator seam used to guard explicitly (its
// "failed Delete must not invalidate" case, lachesis#287), now handled
// structurally by the entry stamp.
//
// When pressure-relief's kernel delete FAILS the entry stays live and
// keeps climbing from the value we last read. Its created_ns is
// unchanged — it is the same entry — so the next scrape must difference,
// not re-add the flow's whole history. Nothing has to remember this:
// an unchanged stamp says it.
func TestApplyDelta_SurvivingEntryDoesNotDoubleCount(t *testing.T) {
	g := state.New()
	k := keyA()
	g.ApplyDelta(k, bpf.FlowMetrics{Bytes: 800_000, CreatedNs: 555})

	// Eviction was attempted and failed; the entry lives on and advances.
	g.ApplyDelta(k, bpf.FlowMetrics{Bytes: 900_000, CreatedNs: 555})

	if got, want := totalBytes(t, g, k), uint64(900_000); got != want {
		t.Errorf("total = %d, want %d — a surviving entry keeps its identity, so this "+
			"is a 100_000 advance; re-counting it whole would over-bill by %d",
			got, want, 800_000)
	}
}
