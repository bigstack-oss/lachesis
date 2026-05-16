// Package metrics implements the Prometheus custom Collector for the
// agent. Collect() holds the [state.GlobalState] RLock for the full
// iteration — without it the Prometheus scrape would race the
// scraper writer and the Go runtime would fatal on concurrent map
// iteration. See docs/DESIGN.md §13.1.
//
// # Why a custom Collector, not CounterVec
//
// CounterVec resets to zero on process restart. The agent restores
// [state.GlobalState] from its WAL on boot; emitting from
// GlobalState directly preserves cumulative continuity across
// restarts so `rate()` does not go negative. See docs/DESIGN.md §C.7.
//
// # Per-flow vs per-label aggregation
//
// [state.GlobalState] is keyed by [bpf.FlowKey] (MAC, EthProto,
// Direction, DstZone) — finer than the metric label set. Multiple
// flow keys can map to the same (tenant_id, zone, direction) tuple.
// The Collector aggregates per tuple before emission; Prometheus
// rejects duplicate label sets in a single scrape, so this is not
// optional. Per-flow granularity remains available to the GC + WAL,
// which need it.
//
// # Allocation behaviour
//
// The Snapshot walk is zero-alloc thanks to the reused buffer. The
// per-tuple aggregation map and [prometheus.MustNewConstMetric] do
// allocate; those costs are per-scrape (10s cadence), not per-flow
// per-packet, so they are left as-is. A custom [prometheus.Metric]
// implementation backed by a sync.Pool would close that gap if
// profiling later shows the emission to be a hotspot.
package metrics

import (
	"strconv"
	"sync"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/state"
	"github.com/prometheus/client_golang/prometheus"
)

// TenantResolver maps a [bpf.FlowKey] to its tenant_id label.
// Implementations must be safe for concurrent use. The agent wires
// [UnknownTenant] until a Neutron-backed resolver consulting the
// kernel `mac_tenant_map` is available.
type TenantResolver interface {
	ResolveTenant(key bpf.FlowKey) string
}

// ScraperStats is the read-only subset of [scraper.Scraper] that
// the Collector exposes as internal-health metrics. Keeping it as
// an interface (rather than a concrete pointer) lets the metrics
// package stay independent of the scraper's internals.
type ScraperStats interface {
	ErrorCount() uint64
	LastSuccessUnix() int64
}

// Collector emits per-(tenant, zone, direction) cumulative byte and
// packet counters from a [state.GlobalState], plus a handful of
// internal-health gauges.
type Collector struct {
	state    *state.GlobalState
	scraper  ScraperStats
	resolver TenantResolver

	bytesDesc        *prometheus.Desc
	packetsDesc      *prometheus.Desc
	flowsDesc        *prometheus.Desc
	scrapeErrorsDesc *prometheus.Desc
	scrapeLastOKDesc *prometheus.Desc

	// collectMu serialises concurrent Collect callers. The default
	// Prometheus registry is single-threaded but third-party
	// registries are not.
	collectMu sync.Mutex
	// emitBuf is reused across Collect calls so the snapshot walk is
	// zero-alloc in steady state.
	emitBuf []state.Entry
	// aggBuf groups per-flow entries by (tenant, zone, direction)
	// before emission. Reused across Collect calls; clear(aggBuf)
	// resets without releasing the bucket allocations.
	aggBuf map[aggKey]aggValue
}

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

// New constructs a Collector. The TenantResolver is required —
// callers without a live resolver should pass [UnknownTenant]{}.
func New(st *state.GlobalState, sc ScraperStats, resolver TenantResolver) *Collector {
	return &Collector{
		state:    st,
		scraper:  sc,
		resolver: resolver,
		aggBuf:   make(map[aggKey]aggValue),
		bytesDesc: prometheus.NewDesc(
			"cubecos_bytes_total",
			"Network bytes observed by the agent, cumulative since first sight.",
			[]string{"tenant_id", "zone", "direction"}, nil,
		),
		packetsDesc: prometheus.NewDesc(
			"cubecos_packets_total",
			"Network packets observed by the agent, cumulative since first sight.",
			[]string{"tenant_id", "zone", "direction"}, nil,
		),
		flowsDesc: prometheus.NewDesc(
			"cubecos_state_flows",
			"Distinct flow keys currently tracked in GlobalState.",
			nil, nil,
		),
		scrapeErrorsDesc: prometheus.NewDesc(
			"cubecos_scraper_errors_total",
			"Cumulative count of failed BPF-map drain attempts since agent start.",
			nil, nil,
		),
		scrapeLastOKDesc: prometheus.NewDesc(
			"cubecos_scraper_last_success_unix_seconds",
			"Unix timestamp of the most recent successful BPF-map drain; 0 if never.",
			nil, nil,
		),
	}
}

// Describe implements [prometheus.Collector].
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.bytesDesc
	ch <- c.packetsDesc
	ch <- c.flowsDesc
	ch <- c.scrapeErrorsDesc
	ch <- c.scrapeLastOKDesc
}

// Collect implements [prometheus.Collector]. The GlobalState walk is
// guarded by the state's RLock and runs to completion before the
// (allocating) per-flow emission begins.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	c.collectMu.Lock()
	defer c.collectMu.Unlock()

	c.emitBuf = c.state.Snapshot(c.emitBuf[:0])
	clear(c.aggBuf)
	for i := range c.emitBuf {
		e := &c.emitBuf[i]
		k := aggKey{
			tenant: c.resolver.ResolveTenant(e.Key),
			zone:   e.Key.DstZone,
			dir:    e.Key.Direction,
		}
		v := c.aggBuf[k]
		v.bytes += e.Total.Bytes
		v.packets += e.Total.Packets
		c.aggBuf[k] = v
	}
	for k, v := range c.aggBuf {
		zone := zoneLabel(k.zone)
		dir := directionLabel(k.dir)
		ch <- prometheus.MustNewConstMetric(
			c.bytesDesc, prometheus.CounterValue, float64(v.bytes),
			k.tenant, zone, dir,
		)
		ch <- prometheus.MustNewConstMetric(
			c.packetsDesc, prometheus.CounterValue, float64(v.packets),
			k.tenant, zone, dir,
		)
	}

	ch <- prometheus.MustNewConstMetric(
		c.flowsDesc, prometheus.GaugeValue, float64(len(c.emitBuf)),
	)
	ch <- prometheus.MustNewConstMetric(
		c.scrapeErrorsDesc, prometheus.CounterValue, float64(c.scraper.ErrorCount()),
	)
	ch <- prometheus.MustNewConstMetric(
		c.scrapeLastOKDesc, prometheus.GaugeValue, float64(c.scraper.LastSuccessUnix()),
	)
}

// zoneLabel formats a [bpf.ZoneCode]. Unknown values fall back to the
// numeric encoding so a future zone-code addition that pre-dates this
// map is still visible in `/metrics`.
func zoneLabel(z bpf.ZoneCode) string {
	switch z {
	case bpf.ZoneExternal:
		return "external"
	case bpf.ZoneSameTenant:
		return "same_tenant"
	case bpf.ZoneOtherTenant:
		return "other_tenant"
	case bpf.ZoneInfra:
		return "infra"
	case bpf.ZoneMiss:
		return "miss"
	case bpf.ZoneShared:
		return "shared"
	}
	return strconv.FormatUint(uint64(z), 10)
}

func directionLabel(d bpf.Direction) string {
	switch d {
	case bpf.DirectionIngress:
		return "ingress"
	case bpf.DirectionEgress:
		return "egress"
	}
	return strconv.FormatUint(uint64(d), 10)
}

// UnknownTenant is the stub TenantResolver wired before the
// Neutron-backed `mac_tenant_map` reader is available. It returns
// "unknown" for every key.
type UnknownTenant struct{}

// ResolveTenant implements [TenantResolver].
func (UnknownTenant) ResolveTenant(bpf.FlowKey) string { return "unknown" }
