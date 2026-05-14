// Package metrics implements the Prometheus custom Collector for the
// agent. See Implementation Contract #2 (CLAUDE.md): Collect() holds
// the [state.GlobalState] RLock for the full iteration.
//
// # Why a custom Collector, not CounterVec
//
// CounterVec resets to zero on process restart. The agent restores
// [state.GlobalState] from the WAL on boot (Sprint 3); emitting from
// GlobalState directly preserves cumulative continuity across
// restarts so `rate()` does not go negative. See docs/DESIGN.md §C.7.
//
// # Allocation behaviour
//
// The Snapshot walk is zero-alloc thanks to the reused buffer in
// [Collector]. The Prometheus emission via
// [prometheus.MustNewConstMetric] does allocate; that cost is
// per-scrape (10s cadence), not per-flow per-packet, so it is left
// as-is. If profiling later shows the emission to be a hotspot, the
// fix is a custom [prometheus.Metric] implementation backed by a
// sync.Pool of *dto.Metric — deferred until a real signal arises.
package metrics

import (
	"strconv"
	"sync"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/state"
	"github.com/prometheus/client_golang/prometheus"
)

// TenantResolver maps a [bpf.FlowKey] to its tenant_id label.
// Implementations must be safe for concurrent use. Sprint 2 wires
// [UnknownTenant], which always returns "unknown"; Sprint 4 will
// supply a resolver backed by the kernel `mac_tenant_map`.
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

	bytesDesc          *prometheus.Desc
	packetsDesc        *prometheus.Desc
	flowsDesc          *prometheus.Desc
	scrapeErrorsDesc   *prometheus.Desc
	scrapeLastOKDesc   *prometheus.Desc

	// collectMu serialises concurrent Collect callers. The default
	// Prometheus registry is single-threaded but third-party
	// registries are not.
	collectMu sync.Mutex
	// emitBuf is reused across Collect calls so the snapshot walk is
	// zero-alloc in steady state.
	emitBuf []state.Entry
}

// New constructs a Collector. The TenantResolver is required —
// callers without a live resolver should pass [UnknownTenant]{}.
func New(st *state.GlobalState, sc ScraperStats, resolver TenantResolver) *Collector {
	return &Collector{
		state:    st,
		scraper:  sc,
		resolver: resolver,
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
	for i := range c.emitBuf {
		e := &c.emitBuf[i]
		tenant := c.resolver.ResolveTenant(e.Key)
		zone := zoneLabel(e.Key.DstZone)
		dir := directionLabel(e.Key.Direction)
		ch <- prometheus.MustNewConstMetric(
			c.bytesDesc, prometheus.CounterValue, float64(e.Total.Bytes),
			tenant, zone, dir,
		)
		ch <- prometheus.MustNewConstMetric(
			c.packetsDesc, prometheus.CounterValue, float64(e.Total.Packets),
			tenant, zone, dir,
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

// UnknownTenant is the Sprint 2 stub TenantResolver. It returns
// "unknown" for every key; Sprint 4 will replace it with the
// Neutron-backed `mac_tenant_map` reader.
type UnknownTenant struct{}

// ResolveTenant implements [TenantResolver].
func (UnknownTenant) ResolveTenant(bpf.FlowKey) string { return "unknown" }
