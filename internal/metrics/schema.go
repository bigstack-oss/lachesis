// schema.go holds package metrics' exported metric-name constant and its
// pure-data aggregation types. The Collector, the TenantResolver /
// ScraperStats seam interfaces, the UnknownTenant stub, and the
// label-formatting funcs live with their logic in collector.go.

package metrics

import "github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"

// MetricBytesTotal is the fully-qualified name of the cumulative bytes
// counter emitted by [Collector]. It is the one metric name consumed by a
// second package — the loadtest harness scrapes it as a liveness check
// (internal/loadtest) — so both the Desc here and that scraper reference
// this const instead of re-typing the string. Other metric names stay
// inline in their NewMetrics, each pinned by a GatherAndCompare test.
const MetricBytesTotal = "cubecos_bytes_total"

// aggKey is the granularity at which Collect aggregates per-flow
// state for Prometheus emission. tenant is the resolver output.
type aggKey struct {
	tenant string
	zone   bpf.ZoneCode
	dir    bpf.Direction
}

// aggValue holds the summed per-tuple counters.
type aggValue struct {
	bytes   uint64
	packets uint64
}
