package netlink

import "github.com/prometheus/client_golang/prometheus"

// Metrics holds the netlink-subscriber Prometheus instruments.
// Construct with [NewMetrics], register the slice from
// [Metrics.Collectors] with the agent's registry.
//
// The two instruments mirror docs/sprint-plan.md §5:
//
//   - cubecos_tc_attach_failures_total{iface_kind}  per-attempt
//     failure counter, labelled by iface_kind for which the attach
//     was attempted ("tap" for prefix-matched links, "other" for
//     explicit-allowlist entries)
//   - cubecos_attached_interfaces                   current size of
//     the Interface Registry
type Metrics struct {
	attachFailures *prometheus.CounterVec
	attached       prometheus.GaugeFunc
}

// NewMetrics constructs the bundle. The current-size gauge is
// backed by registrySize so it reflects live state on every scrape
// without the subscriber having to push updates.
func NewMetrics(registrySize func() int) *Metrics {
	return &Metrics{
		attachFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "cubecos_tc_attach_failures_total",
			Help: "TC clsact attach failures from the netlink subscriber, labelled by iface_kind (\"tap\" for prefix-matched, \"other\" for explicit-list entries).",
		}, []string{"iface_kind"}),
		attached: prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "cubecos_attached_interfaces",
			Help: "Number of interfaces currently carrying telemetry TC programs.",
		}, func() float64 { return float64(registrySize()) }),
	}
}

// Collectors returns every instrument in the bundle.
func (m *Metrics) Collectors() []prometheus.Collector {
	return []prometheus.Collector{m.attachFailures, m.attached}
}

// recordAttachFailure increments the failure counter for kind.
// Nil-safe so subscriber tests can omit the dependency.
func (m *Metrics) recordAttachFailure(kind string) {
	if m == nil {
		return
	}
	m.attachFailures.WithLabelValues(kind).Inc()
}
