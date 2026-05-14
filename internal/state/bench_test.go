package state_test

import (
	"testing"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/state"
)

// BenchmarkHotpath_ApplyDelta measures the steady-state delta-math
// path: an existing key, no allocation. Gated to zero allocs/op by
// scripts/bench-gate.sh.
func BenchmarkHotpath_ApplyDelta(b *testing.B) {
	g := state.New()
	k := keyA()
	// First sight: creates the entry (one-time allocation, outside the
	// timed region) so the benchmark loop only exercises the existing-key
	// path.
	g.ApplyDelta(k, bpf.FlowMetrics{Bytes: 1, Packets: 1, LastSeenNs: 1})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g.ApplyDelta(k, bpf.FlowMetrics{
			Bytes:      uint64(i + 2),
			Packets:    uint64(i + 2),
			LastSeenNs: uint64(i + 2),
		})
	}
}

// BenchmarkHotpath_Snapshot measures the RLocked copy-out the metrics
// Collector uses. Reuse of the dst slice across calls keeps allocation
// at zero in steady state — that's the property the bench-gate enforces.
func BenchmarkHotpath_Snapshot(b *testing.B) {
	const flows = 1024
	g := state.New()
	for i := 0; i < flows; i++ {
		k := keyA()
		k.SrcMac[5] = byte(i)
		k.DstMac[5] = byte(i >> 8)
		g.ApplyDelta(k, bpf.FlowMetrics{Bytes: 1, Packets: 1, LastSeenNs: 1})
	}
	dst := make([]state.Entry, 0, flows)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst = g.Snapshot(dst[:0])
	}
	_ = dst
}
