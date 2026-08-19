package bpf

import (
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds the instruments for the kernel BPF maps: static
// capacity, last-written entry count, kernel-side update failures, and
// the crash-recovery pinning mode.
//
// current_entries is a USERSPACE-tracked count — written by the map
// writer after a push, or by the scraper drain for telemetry_map — not
// kernel ground truth. Drift between it and reality points at a writer
// bug rather than kernel state.
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

// statsCollector emits the kernel telemetry_stats failures. A custom
// Collector, not a CounterVec: the kernel value is the cumulative
// truth and a counter cannot be set to an absolute. Every [StatReason]
// is emitted, so both labels are zero-seeded from the first scrape.
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
