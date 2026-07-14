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
	"sync"
	"time"

	"github.com/bigstack-oss/lachesis/internal/bpf"
	"github.com/bigstack-oss/lachesis/internal/metadata"
	"github.com/bigstack-oss/lachesis/internal/state"
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
	settledDesc      *prometheus.Desc
	scrapeErrorsDesc *prometheus.Desc
	scrapeLastOKDesc *prometheus.Desc

	// collectDuration times each Collect pass (snapshot + aggregate +
	// emit). DESIGN §11 sizes the per-scrape cost by N_CPU and flow
	// count (~5 ms at 32-core/10k flows up to 100+ ms at 128-core/50k);
	// this histogram surfaces the actual cost per node so an
	// outgrown scrape budget is visible before it stalls the
	// exporter. Observed before its own emission, so the in-flight
	// pass is included in the scrape that reports it.
	collectDuration prometheus.Histogram

	// collectMu serialises concurrent Collect callers. The default
	// Prometheus registry is single-threaded but third-party
	// registries are not.
	collectMu sync.Mutex
	// emitBuf and settledBuf are reused across Collect calls so the
	// combined snapshot walk is zero-alloc in steady state.
	emitBuf    []state.Entry
	settledBuf []state.SettledRecord
	// aggBuf groups per-flow entries by (tenant, zone, direction)
	// before emission. Reused across Collect calls; clear(aggBuf)
	// resets without releasing the bucket allocations.
	aggBuf map[aggKey]aggValue
}

// New constructs a Collector. A nil resolver falls back to
// [UnknownTenant]{} so a missed wiring degrades to "unknown" labels
// rather than a nil-pointer panic inside the locked Collect loop on
// the first scrape.
func New(st *state.GlobalState, sc ScraperStats, resolver TenantResolver) *Collector {
	if resolver == nil {
		resolver = UnknownTenant{}
	}
	return &Collector{
		state:    st,
		scraper:  sc,
		resolver: resolver,
		aggBuf:   make(map[aggKey]aggValue),
		bytesDesc: prometheus.NewDesc(
			MetricBytesTotal,
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
		settledDesc: prometheus.NewDesc(
			"cubecos_state_settled_tuples",
			"Distinct (tenant, zone, direction) buckets in the settled-bytes accumulator — flows folded out when their tenant binding was about to disappear (docs/DESIGN.md §3.5).",
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
		collectDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "cubecos_collect_duration_seconds",
			Help:    "Duration of one Prometheus Collect pass over GlobalState (snapshot + aggregate + emit).",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 11), // 1ms..1.024s, same span as the WAL flush SLO buckets
		}),
	}
}

// Describe implements [prometheus.Collector].
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.bytesDesc
	ch <- c.packetsDesc
	ch <- c.flowsDesc
	ch <- c.settledDesc
	ch <- c.scrapeErrorsDesc
	ch <- c.scrapeLastOKDesc
	c.collectDuration.Describe(ch)
}

// Collect implements [prometheus.Collector]. It copies GlobalState —
// live flows and settled buckets together, in one RLock via
// SnapshotWithSettled so a concurrent settle fold cannot tear the
// exposure — into reusable buffers, and then does the allocating
// emission lock-free over those copies. Collect itself never locks
// GlobalState, so it cannot deadlock against the scraper writer or
// race a concurrent map iteration.
//
// The emitted value per (tenant, zone, direction) is live + settled:
// live flows resolve their tenant at scrape time; settled buckets
// carry the tenants of flows whose binding is gone (deleted VMs,
// reassigned ports). The sum is what stays monotonic (docs/DESIGN.md
// §3.5, §13.1 Contract 7).
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	c.collectMu.Lock()
	defer c.collectMu.Unlock()
	start := time.Now()

	c.emitBuf, c.settledBuf = c.state.SnapshotWithSettled(c.emitBuf[:0], c.settledBuf[:0])
	clear(c.aggBuf)
	for i := range c.settledBuf {
		s := &c.settledBuf[i]
		k := aggKey{tenant: s.Key.Tenant, zone: s.Key.Zone, dir: s.Key.Dir}
		v := c.aggBuf[k]
		v.bytes += s.Bytes
		v.packets += s.Packets
		c.aggBuf[k] = v
	}
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
		// ZoneCode.String / Direction.String return constant strings
		// for all known codes — no allocation in this loop.
		zone := k.zone.String()
		dir := k.dir.String()
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
		c.settledDesc, prometheus.GaugeValue, float64(len(c.settledBuf)),
	)
	ch <- prometheus.MustNewConstMetric(
		c.scrapeErrorsDesc, prometheus.CounterValue, float64(c.scraper.ErrorCount()),
	)
	ch <- prometheus.MustNewConstMetric(
		c.scrapeLastOKDesc, prometheus.GaugeValue, float64(c.scraper.LastSuccessUnix()),
	)

	c.collectDuration.Observe(time.Since(start).Seconds())
	c.collectDuration.Collect(ch)
}

// UnknownTenant is the stub TenantResolver wired before the
// Neutron-backed `mac_tenant_map` reader is available. It returns
// [metadata.UnknownTenantID] for every key — the same label a
// [metadata.Resolver] emits on a lookup miss, so Prometheus `rate()`
// queries spanning the cold-start transition see one continuous
// series.
type UnknownTenant struct{}

// ResolveTenant implements [TenantResolver].
func (UnknownTenant) ResolveTenant(bpf.FlowKey) string { return metadata.UnknownTenantID }
