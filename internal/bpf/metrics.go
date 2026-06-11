package bpf

import "github.com/prometheus/client_golang/prometheus"

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
// The two instruments are:
//
//   - cubecos_bpf_map_max_entries{map}      gauge (static capacity)
//   - cubecos_bpf_map_current_entries{map}  gauge (last-written count)
type Metrics struct {
	maxEntries     *prometheus.GaugeVec
	currentEntries *prometheus.GaugeVec
}

// NewMetrics constructs the bundle. Callers populate static max
// values immediately after construction via [SetMax], then update
// current values via [SetCurrent] after each kernel write.
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
	}
}

// Collectors returns the underlying prometheus.Collector values.
func (m *Metrics) Collectors() []prometheus.Collector {
	return []prometheus.Collector{m.maxEntries, m.currentEntries}
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
