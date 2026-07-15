// schema.go holds package metrics' exported metric-name constant and its
// pure-data aggregation types. The Collector, the TenantResolver /
// ScraperStats seam interfaces, the UnknownTenant stub, and the
// label-formatting funcs live with their logic in collector.go.

package metrics

import "github.com/bigstack-oss/lachesis/internal/bpf"

// MetricBytesTotal is the fully-qualified name of the cumulative bytes
// counter emitted by [Collector]. It is the one metric name consumed by a
// second package — the loadtest harness scrapes it as a liveness check
// (internal/loadtest) — so both the Desc here and that scraper reference
// this const instead of re-typing the string. Other metric names stay
// inline in their NewMetrics, each pinned by a GatherAndCompare test.
const MetricBytesTotal = "lachesis_bytes_total"

// MetricServerBytesTotal is the per-server billing-export family
// (docs/DESIGN.md §11.5). Unlike the tenant family it is MORTAL: a
// series ends when its VM's attribution dies (ghost sweep) — there is no
// per-server settled accumulator, deliberately. Consumers do period
// subtraction over range queries, never increase()/rate() for money.
const MetricServerBytesTotal = "lachesis_server_bytes_total"

// aggKey is the granularity at which Collect aggregates per-flow
// state for tenant-family emission. tenant and ext are resolver
// outputs; ext is the zone-gated external_network label.
type aggKey struct {
	tenant string
	ext    string
	zone   bpf.ZoneCode
	dir    bpf.Direction
}

// serverAggKey is the per-server family's aggregation granularity —
// aggKey plus the server identity. Live rows only; rows without a
// resolved server never enter this aggregation.
type serverAggKey struct {
	server string
	tenant string
	ext    string
	zone   bpf.ZoneCode
	dir    bpf.Direction
}

// aggValue holds the summed per-tuple counters.
type aggValue struct {
	bytes   uint64
	packets uint64
}
