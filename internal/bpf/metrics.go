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
//   - cubecos_bpf_map_max_entries{map}        gauge (static capacity)
//   - cubecos_bpf_map_current_entries{map}    gauge (last-written count)
//   - cubecos_bpf_update_failures_total{reason} counter (kernel telemetry_stats)
type Metrics struct {
	maxEntries     *prometheus.GaugeVec
	currentEntries *prometheus.GaugeVec
	updateFailures *statsCollector
}

// NewMetrics constructs the bundle. Callers populate static max
// values immediately after construction via [SetMax], then update
// current values via [SetCurrent] after each kernel write and the
// update-failure counters via [SetUpdateFailures] after each
// telemetry_stats drain.
func NewMetrics() *Metrics {
	return &Metrics{
		maxEntries: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "cubecos_bpf_map_max_entries",
			Help: "Compiled-in max_entries of each BPF map the agent populates.",
		}, []string{labelMap}),
		currentEntries: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "cubecos_bpf_map_current_entries",
			Help: "Userspace-tracked entry count of each BPF map after the most recent push.",
		}, []string{labelMap}),
		updateFailures: newStatsCollector(),
	}
}

// Collectors returns the underlying prometheus.Collector values.
func (m *Metrics) Collectors() []prometheus.Collector {
	return []prometheus.Collector{m.maxEntries, m.currentEntries, m.updateFailures}
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

// statsCollector emits cubecos_bpf_update_failures_total{reason} from
// the last-drained kernel telemetry_stats values. It is a small custom
// Collector rather than a CounterVec because the kernel value is the
// cumulative truth and counters cannot be set to an absolute value —
// the same emit-from-source rationale as the billing Collector
// (docs/DESIGN.md §11.4). Collect always emits every [StatReason]
// series, so both reason labels are zero-seeded from the first scrape.
type statsCollector struct {
	desc *prometheus.Desc
	last [statReasonCount]atomic.Uint64
}

// newStatsCollector builds the collector with all counters at zero.
func newStatsCollector() *statsCollector {
	return &statsCollector{
		desc: prometheus.NewDesc(
			"cubecos_bpf_update_failures_total",
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
