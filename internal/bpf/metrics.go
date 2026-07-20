package bpf

import (
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds Prometheus instruments for the kernel BPF maps
// the agent populates. The `current_entries` value is updated by the
// userspace writer (kernelwriter) after each successful map push —
// or, for telemetry_map, by the scraper drain, which counts the keys
// each BatchLookup returns; it's a userspace-tracked count, not a
// kernel-side ground truth, so a sudden drift would suggest a writer
// bug rather than kernel state. `max_entries` is static — set once
// at boot from the
// `MapXxxMaxEntries` constants — and serves as the denominator the
// Grafana fill-ratio panel divides into.
//
// The three instruments are:
//
//   - lachesis_bpf_map_max_entries{map}        gauge (static capacity)
//   - lachesis_bpf_map_current_entries{map}    gauge (last-written count)
//   - lachesis_bpf_update_failures_total{reason} counter (kernel telemetry_stats)
//   - lachesis_bpf_maps_pinned                 gauge (crash-recovery mode)
type Metrics struct {
	maxEntries     *prometheus.GaugeVec
	currentEntries *prometheus.GaugeVec
	updateFailures *statsCollector
	mapsPinned     prometheus.Gauge
}

// NewMetrics constructs the bundle. Callers populate static max
// values immediately after construction via [SetMax], then update
// current values via [SetCurrent] after each kernel write and the
// update-failure counters via [SetUpdateFailures] after each
// telemetry_stats drain.
func NewMetrics() *Metrics {
	return &Metrics{
		maxEntries: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "lachesis_bpf_map_max_entries",
			Help: "Compiled-in max_entries of each BPF map the agent populates.",
		}, []string{labelMap}),
		currentEntries: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "lachesis_bpf_map_current_entries",
			Help: "Userspace-tracked entry count of each BPF map after the most recent push.",
		}, []string{labelMap}),
		updateFailures: newStatsCollector(),
		mapsPinned: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "lachesis_bpf_maps_pinned",
			Help: "1 when the counter-bearing BPF maps are pinned (zero-loss agent-crash recovery); 0 when running unpinned (recovery degraded to the ≤60s WAL-bounded path).",
		}),
	}
}

// Collectors returns the underlying prometheus.Collector values.
func (m *Metrics) Collectors() []prometheus.Collector {
	return []prometheus.Collector{m.maxEntries, m.currentEntries, m.updateFailures, m.mapsPinned}
}

// SetMax records the static capacity of mapName.
func (m *Metrics) SetMax(mapName string, max float64) {
	if m == nil {
		return
	}
	m.maxEntries.WithLabelValues(mapName).Set(max)
}

// SetCurrent records the userspace-tracked entry count of mapName.
// Call after a successful push so the dashboard's fill-ratio panel
// reflects the new state.
func (m *Metrics) SetCurrent(mapName string, current float64) {
	if m == nil {
		return
	}
	m.currentEntries.WithLabelValues(mapName).Set(current)
}

// SetMapsPinned records whether the counter-bearing maps were pinned
// at boot: true → the agent-crash path is zero-loss; false → it
// degraded to the ≤60s WAL-bounded path (bpf.unsafe_allow_unpinned_maps).
// Set once during boot.
func (m *Metrics) SetMapsPinned(pinned bool) {
	if m == nil {
		return
	}
	if pinned {
		m.mapsPinned.Set(1)
		return
	}
	m.mapsPinned.Set(0)
}

// SetUpdateFailures records the most recent telemetry_stats drain.
// The values are the kernel's cumulative counters, so this is a
// set-to-absolute, not an add.
func (m *Metrics) SetUpdateFailures(c StatCounts) {
	if m == nil {
		return
	}
	for reason := StatReason(0); reason < statReasonCount; reason++ {
		m.updateFailures.last[reason].Store(c[reason])
	}
}

// statsCollector emits lachesis_bpf_update_failures_total{reason} from
// the last-drained kernel telemetry_stats values. It is a small custom
// Collector rather than a CounterVec because the kernel value is the
// cumulative truth and counters cannot be set to an absolute value —
// the same emit-from-source rationale as the billing Collector
// (docs/architecture/metrics.md). Collect always emits every [StatReason]
// series, so both reason labels are zero-seeded from the first scrape.
type statsCollector struct {
	desc *prometheus.Desc
	last [statReasonCount]atomic.Uint64
}

// newStatsCollector builds the collector with all counters at zero.
func newStatsCollector() *statsCollector {
	return &statsCollector{
		desc: prometheus.NewDesc(
			"lachesis_bpf_update_failures_total",
			"Kernel-side cumulative count of telemetry_map inserts the kernel rejected (reason=update_failure; those flows' bytes are lost) and non-IP frames passed through uncounted (reason=skipped_ethertype), drained from the telemetry_stats BPF map each scrape.",
			[]string{labelReason}, nil),
	}
}

// Describe implements prometheus.Collector.
func (c *statsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.desc
}

// Collect implements prometheus.Collector.
func (c *statsCollector) Collect(ch chan<- prometheus.Metric) {
	for reason := StatReason(0); reason < statReasonCount; reason++ {
		ch <- prometheus.MustNewConstMetric(c.desc, prometheus.CounterValue,
			float64(c.last[reason].Load()), reason.String())
	}
}
