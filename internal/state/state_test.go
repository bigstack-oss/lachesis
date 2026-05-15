package state_test

import (
	"sync"
	"testing"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/state"
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

	records := g.SnapshotForWAL(nil)
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

	records := g.SnapshotForWAL(nil)
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

	records := g.SnapshotForWAL(nil)
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
	dst := g.SnapshotForWAL(nil)
	cap1 := cap(dst)
	dst = g.SnapshotForWAL(dst[:0])
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
