// schema.go holds package metrics' exported metric-name constants and its
// pure-data aggregation types. The Collector, the TenantResolver /
// ScraperStats seam interfaces, the UnknownTenant stub, and the
// label-formatting funcs live with their logic in collector.go.

package metrics

import "github.com/bigstack-oss/lachesis/internal/bpf"

// The four-layer billing family names: total → tenant → server → port,
// each immortal within its owner's lifetime, each absorbing the deaths
// of the tier below.
//
// Full rationale: docs/architecture/billing.md

// MetricBytesTotal is the TOTAL tier — everything the node observed,
// summed over tenants (including "unknown"): live rows + all settled.
// No tenant dimension; immortal. It is also the metric name consumed by
// a second package — the loadtest harness scrapes it as a liveness
// check (internal/loadtest) — so both the Desc here and that scraper
// reference this const instead of re-typing the string.
const (
	MetricBytesTotal   = "lachesis_bytes_total"
	MetricPacketsTotal = "lachesis_packets_total"
)

// MetricTenantBytesTotal / MetricTenantPacketsTotal are the TENANT tier
// — live rows + tenant-settled per (tenant, zone, external_network,
// direction). Immortal: the settled accumulator absorbs server and port
// deaths, so a tenant's series never decreases across VM churn.
const (
	MetricTenantBytesTotal   = "lachesis_tenant_bytes_total"
	MetricTenantPacketsTotal = "lachesis_tenant_packets_total"
)

// MetricServerBytesTotal is the SERVER tier — Σ live rows +
// server-settled per (server, tenant, zone, external_network,
// direction). Monotone for exactly the server's lifetime: the
// server-settled absorber holds folded port bytes (a portless-but-alive
// server flat-lines, like a stopped VM), and the series ends when the
// server leaves the Nova list. Plain period subtraction is safe within
// the lifetime; never increase()/rate() for money.
const (
	MetricServerBytesTotal   = "lachesis_server_bytes_total"
	MetricServerPacketsTotal = "lachesis_server_packets_total"
)

// MetricPortBytesTotal is the PORT tier — the mortal leaf, one series
// per Neutron port. A port's series stops when the port is deleted, and
// a detached-then-reattached port's series restarts from a fresh kernel
// counter — billing exactness lives one tier up; this family is the
// per-port drill-down view.
const (
	MetricPortBytesTotal   = "lachesis_port_bytes_total"
	MetricPortPacketsTotal = "lachesis_port_packets_total"
)

// totalAggKey is the total tier's aggregation granularity: the tenant
// dimension summed away.
type totalAggKey struct {
	ext  string
	zone bpf.ZoneCode
	dir  bpf.Direction
}

// aggKey is the granularity at which Collect aggregates per-flow
// state for tenant-family emission. tenant and ext are resolver
// outputs; ext is the zone-gated external_network label.
type aggKey struct {
	tenant string
	ext    string
	zone   bpf.ZoneCode
	dir    bpf.Direction
}

// serverAggKey is the server tier's aggregation granularity — aggKey
// plus the server identity. Fed by live rows AND the server-settled
// absorber; rows without a resolved server never enter it.
type serverAggKey struct {
	server string
	tenant string
	ext    string
	zone   bpf.ZoneCode
	dir    bpf.Direction
}

// portAggKey is the port tier's granularity — serverAggKey plus the
// port identity. Live rows only (the leaf has no absorber).
type portAggKey struct {
	server string
	port   string
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
