// Package metrics implements the Prometheus custom Collector for the
// agent. Collect() holds the [state.GlobalState] RLock for the full
// iteration — without it the Prometheus scrape would race the
// scraper writer and the Go runtime would fatal on concurrent map
// iteration. See docs/architecture/contracts.md#required-contracts.
//
// # Why a custom Collector, not CounterVec
//
// CounterVec resets to zero on process restart. The agent restores
// [state.GlobalState] from its WAL on boot; emitting from
// GlobalState directly preserves cumulative continuity across
// restarts so `rate()` does not go negative. See docs/adr/0007-custom-collector-over-countervec.md.
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

// TenantResolver maps a [bpf.FlowKey] to its full label attribution —
// tenant_id, server_id, and the zone-gated external_network label — in
// one lookup ([metadata.Attribution]). Implementations must be safe for
// concurrent use and must not allocate: Resolve runs per live row inside
// Collect. The agent wires [metadata.Resolver]; [UnknownTenant] is the
// unwired fallback.
type TenantResolver interface {
	Resolve(key bpf.FlowKey) metadata.Attribution
}

// ScraperStats is the read-only subset of [scraper.Scraper] that
// the Collector exposes as internal-health metrics. Keeping it as
// an interface (rather than a concrete pointer) lets the metrics
// package stay independent of the scraper's internals.
type ScraperStats interface {
	ErrorCount() uint64
	LastSuccessUnix() int64
}

// Collector emits the four-layer billing hierarchy — total → tenant →
// server → port byte/packet counters — from a [state.GlobalState],
// plus a handful of internal-health gauges (docs/architecture/billing.md).
type Collector struct {
	state    *state.GlobalState
	scraper  ScraperStats
	resolver TenantResolver

	totalBytesDesc    *prometheus.Desc
	totalPacketsDesc  *prometheus.Desc
	bytesDesc         *prometheus.Desc
	packetsDesc       *prometheus.Desc
	serverBytesDesc   *prometheus.Desc
	serverPacketsDesc *prometheus.Desc
	portBytesDesc     *prometheus.Desc
	portPacketsDesc   *prometheus.Desc
	flowsDesc         *prometheus.Desc
	tenantSettledDesc *prometheus.Desc
	serverSettledDesc *prometheus.Desc
	totalSettledDesc  *prometheus.Desc
	scrapeErrorsDesc  *prometheus.Desc
	scrapeLastOKDesc  *prometheus.Desc

	// collectDuration times each Collect pass (snapshot + aggregate +
	// emit). docs/architecture/performance.md sizes the per-scrape cost by N_CPU and flow
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
	// emitBuf and the three settled buffers are reused across Collect
	// calls so the combined snapshot walk is zero-alloc in steady state.
	emitBuf          []state.Entry
	tenantSettledBuf []state.TenantSettledRecord
	serverSettledBuf []state.ServerSettledRecord
	totalSettledBuf  []state.TotalSettledRecord
	// The four per-tier aggregation buffers (docs/architecture/billing.md):
	// totalAggBuf sums the tenant tier's buckets with the tenant
	// dimension removed; aggBuf groups per-flow entries + tenant-settled
	// by (tenant, external_network, zone, direction); serverAggBuf
	// groups live rows + server-settled by the server tuple; portAggBuf
	// groups live rows by the port tuple (the mortal leaf). All reused
	// across Collect calls; clear() resets without releasing the bucket
	// allocations.
	totalAggBuf  map[totalAggKey]aggValue
	aggBuf       map[aggKey]aggValue
	serverAggBuf map[serverAggKey]aggValue
	portAggBuf   map[portAggKey]aggValue
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
		state:        st,
		scraper:      sc,
		resolver:     resolver,
		totalAggBuf:  make(map[totalAggKey]aggValue),
		aggBuf:       make(map[aggKey]aggValue),
		serverAggBuf: make(map[serverAggKey]aggValue),
		portAggBuf:   make(map[portAggKey]aggValue),
		totalBytesDesc: prometheus.NewDesc(
			MetricBytesTotal,
			"Total network bytes observed by the node, cumulative — the top of the four-layer billing hierarchy: Σ over all tenants (including \"unknown\") of live rows + settled. Immortal (docs/architecture/billing.md).",
			[]string{"zone", "external_network", "direction"}, nil,
		),
		totalPacketsDesc: prometheus.NewDesc(
			MetricPacketsTotal,
			"Total network packets (GSO/GRO superpackets) observed by the node, cumulative — the total tier's diagnostic companion to lachesis_bytes_total. Never a billing dimension (docs/architecture/billing.md).",
			[]string{"zone", "external_network", "direction"}, nil,
		),
		bytesDesc: prometheus.NewDesc(
			MetricTenantBytesTotal,
			"Per-tenant network bytes, cumulative since first sight — live rows + tenant-settled, so the series never decreases across VM churn. Immortal (docs/architecture/billing.md).",
			[]string{"tenant_id", "zone", "external_network", "direction"}, nil,
		),
		packetsDesc: prometheus.NewDesc(
			MetricTenantPacketsTotal,
			"Per-tenant network packets, cumulative since first sight — live rows + tenant-settled. Immortal (docs/architecture/billing.md).",
			[]string{"tenant_id", "zone", "external_network", "direction"}, nil,
		),
		serverBytesDesc: prometheus.NewDesc(
			MetricServerBytesTotal,
			"Per-server network bytes, cumulative — Σ live rows + server-settled, monotone for exactly the server's lifetime: port deletes/detaches fold into the server-settled absorber (a portless-but-alive server flat-lines), and the series ends when the server leaves the Nova list. Period subtraction is safe within the lifetime; never increase()/rate() for money (docs/architecture/billing.md).",
			[]string{"server_id", "tenant_id", "zone", "external_network", "direction"}, nil,
		),
		portBytesDesc: prometheus.NewDesc(
			MetricPortBytesTotal,
			"Per-port network bytes, cumulative while the port's binding lives — the mortal leaf of the billing hierarchy: a deleted port's series stops, and a detached-then-reattached port restarts from a fresh counter. Drill-down/monitoring view; billing exactness lives in lachesis_server_bytes_total (docs/architecture/billing.md).",
			[]string{"server_id", "port_id", "tenant_id", "zone", "external_network", "direction"}, nil,
		),
		serverPacketsDesc: prometheus.NewDesc(
			MetricServerPacketsTotal,
			"Per-server network packets (GSO/GRO superpackets), cumulative — Σ live rows + server-settled, same lifetime as lachesis_server_bytes_total. Diagnostic companion; never a billing dimension (docs/architecture/billing.md).",
			[]string{"server_id", "tenant_id", "zone", "external_network", "direction"}, nil,
		),
		portPacketsDesc: prometheus.NewDesc(
			MetricPortPacketsTotal,
			"Per-port network packets (GSO/GRO superpackets), cumulative while the port's binding lives — the mortal leaf's diagnostic companion to lachesis_port_bytes_total. Never a billing dimension (docs/architecture/billing.md).",
			[]string{"server_id", "port_id", "tenant_id", "zone", "external_network", "direction"}, nil,
		),
		flowsDesc: prometheus.NewDesc(
			"lachesis_state_flows",
			"Distinct flow keys currently tracked in GlobalState.",
			nil, nil,
		),
		tenantSettledDesc: prometheus.NewDesc(
			"lachesis_state_tenant_settled_tuples",
			"Distinct (tenant, zone, external_network, direction) buckets in the settled-bytes accumulator — flows folded out when their attribution was about to disappear (docs/architecture/data-structures.md#settled-bytes).",
			nil, nil,
		),
		serverSettledDesc: prometheus.NewDesc(
			"lachesis_state_server_settled_tuples",
			"Distinct (server_id, tenant, zone, external_network, direction) buckets in the server-settled accumulator — the server tier's fold absorber; buckets are released when their server leaves the Nova list (docs/architecture/data-structures.md#settled-bytes).",
			nil, nil,
		),
		totalSettledDesc: prometheus.NewDesc(
			"lachesis_state_total_settled_tuples",
			"Distinct (zone, external_network, direction) buckets in the total-settled accumulator — the total tier's fold absorber, credited when a deleted project's tenant-settled bucket is released. Never pruned (docs/architecture/data-structures.md#settled-bytes).",
			nil, nil,
		),
		scrapeErrorsDesc: prometheus.NewDesc(
			"lachesis_scraper_errors_total",
			"Cumulative count of failed BPF-map drain attempts since agent start.",
			nil, nil,
		),
		scrapeLastOKDesc: prometheus.NewDesc(
			"lachesis_scraper_last_success_unix_seconds",
			"Unix timestamp of the most recent successful BPF-map drain; 0 if never.",
			nil, nil,
		),
		collectDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "lachesis_collect_duration_seconds",
			Help:    "Duration of one Prometheus Collect pass over GlobalState (snapshot + aggregate + emit).",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 11), // 1ms..1.024s, same span as the WAL flush SLO buckets
		}),
	}
}

// Describe implements [prometheus.Collector].
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.totalBytesDesc
	ch <- c.totalPacketsDesc
	ch <- c.bytesDesc
	ch <- c.packetsDesc
	ch <- c.serverBytesDesc
	ch <- c.serverPacketsDesc
	ch <- c.portBytesDesc
	ch <- c.portPacketsDesc
	ch <- c.flowsDesc
	ch <- c.tenantSettledDesc
	ch <- c.serverSettledDesc
	ch <- c.totalSettledDesc
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
// The emitted value per tier (docs/architecture/billing.md,
// docs/architecture/data-structures.md#settled-bytes, docs/architecture/contracts.md#required-contracts Contract 7):
// tenant = live + tenant-settled; total = the tenant tier with the
// tenant dimension summed away; server = live + server-settled
// (settled-only tuples emitted — a portless-but-alive server
// flat-lines); port = live rows only, the mortal leaf.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	c.collectMu.Lock()
	defer c.collectMu.Unlock()
	start := time.Now()

	c.emitBuf, c.tenantSettledBuf, c.serverSettledBuf, c.totalSettledBuf = c.state.SnapshotWithSettled(c.emitBuf[:0], c.tenantSettledBuf[:0], c.serverSettledBuf[:0], c.totalSettledBuf[:0])
	c.aggregate()
	c.emitBilling(ch)
	c.emitHealth(ch)

	c.collectDuration.Observe(time.Since(start).Seconds())
	c.collectDuration.Collect(ch)
}

// aggregate builds the four per-tier maps from the snapshot buffers, in
// dependency order: tenant-settled and live rows feed the tenant tier
// (live rows also feed server + port), the server-settled absorber
// completes the server tier, and the total tier derives from the
// finished tenant tier. Pure bucket math — no emission, no locks.
func (c *Collector) aggregate() {
	clear(c.totalAggBuf)
	clear(c.aggBuf)
	clear(c.serverAggBuf)
	clear(c.portAggBuf)
	c.foldTenantSettled()
	c.aggregateLiveRows()
	c.foldServerSettled()
	c.deriveTotals()
	c.foldTotalSettled()
}

// foldTenantSettled credits the tenant tier with the settled buckets —
// the bytes of flows whose attribution is gone (deleted VMs, reassigned
// ports), which keep the tenant series monotone across churn
// (docs/architecture/data-structures.md#settled-bytes).
func (c *Collector) foldTenantSettled() {
	for i := range c.tenantSettledBuf {
		s := &c.tenantSettledBuf[i]
		k := aggKey{tenant: s.Key.Tenant, ext: s.Key.ExtNet, zone: s.Key.Zone, dir: s.Key.Dir}
		v := c.aggBuf[k]
		v.bytes += s.Bytes
		v.packets += s.Packets
		c.aggBuf[k] = v
	}
}

// aggregateLiveRows resolves each live flow row once and credits every
// tier it belongs to: always the tenant tier; the server and port tiers
// only when the MAC resolves to a server — unattributable traffic has
// no server_id (and no port_id) by definition and lives in the tenant
// tier's "unknown" series alone.
func (c *Collector) aggregateLiveRows() {
	for i := range c.emitBuf {
		e := &c.emitBuf[i]
		a := c.resolver.Resolve(e.Key)
		k := aggKey{
			tenant: a.Tenant,
			ext:    a.ExternalNetwork,
			zone:   e.Key.DstZone,
			dir:    e.Key.Direction,
		}
		v := c.aggBuf[k]
		v.bytes += e.Total.Bytes
		v.packets += e.Total.Packets
		c.aggBuf[k] = v
		if a.ServerID != "" {
			sk := serverAggKey{server: a.ServerID, tenant: a.Tenant, ext: a.ExternalNetwork,
				zone: e.Key.DstZone, dir: e.Key.Direction}
			sv := c.serverAggBuf[sk]
			sv.bytes += e.Total.Bytes
			sv.packets += e.Total.Packets
			c.serverAggBuf[sk] = sv
			pk := portAggKey{server: a.ServerID, port: a.PortID, tenant: a.Tenant, ext: a.ExternalNetwork,
				zone: e.Key.DstZone, dir: e.Key.Direction}
			pv := c.portAggBuf[pk]
			pv.bytes += e.Total.Bytes
			pv.packets += e.Total.Packets
			c.portAggBuf[pk] = pv
		}
	}
}

// foldServerSettled credits the server tier with its absorber, CREATING
// entries for tuples with no live rows: a server that momentarily has
// no ports (detached NIC, port recreate in flight) keeps emitting its
// cumulative as a flat line — the series is monotone for the server's
// whole lifetime, and it ends only when the reconciler releases the
// bucket on Nova-list absence (docs/architecture/data-structures.md#settled-bytes).
func (c *Collector) foldServerSettled() {
	for i := range c.serverSettledBuf {
		s := &c.serverSettledBuf[i]
		sk := serverAggKey{server: s.Key.ServerID, tenant: s.Key.Tenant, ext: s.Key.ExtNet,
			zone: s.Key.Zone, dir: s.Key.Dir}
		sv := c.serverAggBuf[sk]
		sv.bytes += s.Bytes
		sv.packets += s.Packets
		c.serverAggBuf[sk] = sv
	}
}

// deriveTotals builds the total tier as the finished tenant tier with
// the tenant dimension summed away — total = Σ tenant series by
// construction, so the two tiers can never disagree.
func (c *Collector) deriveTotals() {
	for k, v := range c.aggBuf {
		tk := totalAggKey{ext: k.ext, zone: k.zone, dir: k.dir}
		tv := c.totalAggBuf[tk]
		tv.bytes += v.bytes
		tv.packets += v.packets
		c.totalAggBuf[tk] = tv
	}
}

// foldTotalSettled credits the total tier with its absorber — the
// history of projects whose tenant-settled buckets were released on
// Keystone-list absence. Runs AFTER deriveTotals: the derived sum
// covers only living tenants, and this fold adds the dead ones' bytes
// back so the immortal total series never dips across a project
// deletion, CREATING the bucket's tuple if no living tenant occupies it
// (docs/architecture/data-structures.md#settled-bytes).
func (c *Collector) foldTotalSettled() {
	for i := range c.totalSettledBuf {
		s := &c.totalSettledBuf[i]
		tk := totalAggKey{ext: s.Key.ExtNet, zone: s.Key.Zone, dir: s.Key.Dir}
		tv := c.totalAggBuf[tk]
		tv.bytes += s.Bytes
		tv.packets += s.Packets
		c.totalAggBuf[tk] = tv
	}
}

// emitBilling emits the four billing tiers from the aggregated maps —
// bytes and packets per tier, labels per docs/architecture/metrics.md.
// ZoneCode.String / Direction.String return constant strings for all
// known codes — no allocation in these loops.
func (c *Collector) emitBilling(ch chan<- prometheus.Metric) {
	for k, v := range c.totalAggBuf {
		zone, dir := k.zone.String(), k.dir.String()
		ch <- prometheus.MustNewConstMetric(
			c.totalBytesDesc, prometheus.CounterValue, float64(v.bytes), zone, k.ext, dir)
		ch <- prometheus.MustNewConstMetric(
			c.totalPacketsDesc, prometheus.CounterValue, float64(v.packets), zone, k.ext, dir)
	}
	for k, v := range c.aggBuf {
		zone, dir := k.zone.String(), k.dir.String()
		ch <- prometheus.MustNewConstMetric(
			c.bytesDesc, prometheus.CounterValue, float64(v.bytes), k.tenant, zone, k.ext, dir)
		ch <- prometheus.MustNewConstMetric(
			c.packetsDesc, prometheus.CounterValue, float64(v.packets), k.tenant, zone, k.ext, dir)
	}
	for k, v := range c.serverAggBuf {
		zone, dir := k.zone.String(), k.dir.String()
		ch <- prometheus.MustNewConstMetric(
			c.serverBytesDesc, prometheus.CounterValue, float64(v.bytes), k.server, k.tenant, zone, k.ext, dir)
		ch <- prometheus.MustNewConstMetric(
			c.serverPacketsDesc, prometheus.CounterValue, float64(v.packets), k.server, k.tenant, zone, k.ext, dir)
	}
	for k, v := range c.portAggBuf {
		zone, dir := k.zone.String(), k.dir.String()
		ch <- prometheus.MustNewConstMetric(
			c.portBytesDesc, prometheus.CounterValue, float64(v.bytes), k.server, k.port, k.tenant, zone, k.ext, dir)
		ch <- prometheus.MustNewConstMetric(
			c.portPacketsDesc, prometheus.CounterValue, float64(v.packets), k.server, k.port, k.tenant, zone, k.ext, dir)
	}
}

// emitHealth emits the collector's internal-health gauges: state sizes
// from this pass's snapshot buffers plus the scraper's drain stats.
func (c *Collector) emitHealth(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(
		c.flowsDesc, prometheus.GaugeValue, float64(len(c.emitBuf)))
	ch <- prometheus.MustNewConstMetric(
		c.tenantSettledDesc, prometheus.GaugeValue, float64(len(c.tenantSettledBuf)))
	ch <- prometheus.MustNewConstMetric(
		c.serverSettledDesc, prometheus.GaugeValue, float64(len(c.serverSettledBuf)))
	ch <- prometheus.MustNewConstMetric(
		c.totalSettledDesc, prometheus.GaugeValue, float64(len(c.totalSettledBuf)))
	ch <- prometheus.MustNewConstMetric(
		c.scrapeErrorsDesc, prometheus.CounterValue, float64(c.scraper.ErrorCount()))
	ch <- prometheus.MustNewConstMetric(
		c.scrapeLastOKDesc, prometheus.GaugeValue, float64(c.scraper.LastSuccessUnix()))
}

// UnknownTenant is the stub TenantResolver wired before the
// Neutron-backed `mac_tenant_map` reader is available. It returns the
// [metadata.UnknownTenantID] / [metadata.NoExternalNetwork] sentinels
// for every key — the same labels a [metadata.Resolver] emits on a
// lookup miss, so Prometheus `rate()` queries spanning the cold-start
// transition see one continuous series. No ServerID: unresolved flows
// never enter the per-server family.
type UnknownTenant struct{}

// Resolve implements [TenantResolver].
func (UnknownTenant) Resolve(bpf.FlowKey) metadata.Attribution {
	return metadata.Attribution{
		Tenant:          metadata.UnknownTenantID,
		ExternalNetwork: metadata.NoExternalNetwork,
	}
}
