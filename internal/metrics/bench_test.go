package metrics_test

import (
	"testing"

	"github.com/bigstack-oss/lachesis/internal/bpf"
	"github.com/bigstack-oss/lachesis/internal/metrics"
	"github.com/bigstack-oss/lachesis/internal/state"
	"github.com/prometheus/client_golang/prometheus"
)

// benchCollectKeys builds n distinct flow keys spread across MACs,
// zones, and directions so the benchmark exercises realistic
// aggregation fan-in (many flow keys collapsing onto the bounded
// (tenant, zone, direction) tuple set) rather than a single hot key.
func benchCollectKeys(n int) []bpf.FlowKey {
	keys := make([]bpf.FlowKey, n)
	for i := range keys {
		keys[i] = bpf.FlowKey{
			SrcMac:    [6]uint8{0, 0, 0, 0, byte(i >> 8), byte(i)},
			EthProto:  0x0800,
			Direction: bpf.Direction(i % 2),
			DstZone:   bpf.ZoneCode(i % 6),
		}
	}
	return keys
}

// BenchmarkCollect measures the full Collect() path — Snapshot walk,
// per-tuple aggregation, and metric emission — and reports allocs.
//
// Collect() is NOT fully zero-alloc by design: the Snapshot walk
// reuses buffers (zero-alloc), but the per-(tenant,zone,direction)
// emission via prometheus.MustNewConstMetric allocates per emitted
// series each scrape — accepted at the 10s scrape cadence (see the
// collector.go package doc and docs/architecture/performance.md). This benchmark is
// therefore deliberately NOT named BenchmarkHotpath_* (which the
// zero-alloc bench-gate would fail); its job is to surface the
// per-scrape alloc count so a regression that made Collect allocate
// per *flow* (e.g. dropping the reused emitBuf) shows up here.
func BenchmarkCollect(b *testing.B) {
	b.ReportAllocs()

	st := state.New()
	for _, k := range benchCollectKeys(1000) {
		st.ApplyDelta(k, bpf.FlowMetrics{Bytes: 1, Packets: 1, LastSeenNs: 1})
	}
	col := metrics.New(st, benchScraper{}, metrics.UnknownTenant{})

	// Buffered beyond the emitted-series count (2 per tuple + 3 health
	// metrics; the keys above span at most 2 dirs × 6 zones = 12
	// tuples for the single UnknownTenant label) so Collect never
	// blocks and the drain below does not allocate.
	ch := make(chan prometheus.Metric, 4096)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		col.Collect(ch)
		for {
			select {
			case <-ch:
			default:
				goto drained
			}
		}
	drained:
	}
}

// benchScraper is a no-op ScraperStats for the Collect benchmark.
type benchScraper struct{}

func (benchScraper) ErrorCount() uint64     { return 0 }
func (benchScraper) LastSuccessUnix() int64 { return 0 }
