// schema.go holds package metrics' pure-data aggregation types. The
// Collector, the TenantResolver / ScraperStats seam interfaces, the
// UnknownTenant stub, and the label-formatting funcs live with their
// logic in collector.go.

package metrics

import "github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"

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
