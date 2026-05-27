package zombie

import "github.com/prometheus/client_golang/prometheus"

// Metrics holds the zombie-subsystem Prometheus instruments.
// Construct with [NewMetrics], register the slice from
// [Metrics.Collectors] with the agent's prometheus.Registry, then
// call [Metrics.RecordCleaned] once with the count returned by
// [Hunt].
//
// The single instrument mirrors docs/sprint-plan.md §5:
//
//   - cubecos_zombie_filters_cleaned_total  orphan TC filters
//     deleted at startup
type Metrics struct {
	cleaned prometheus.Counter
}

// NewMetrics constructs the zombie instrument bundle.
func NewMetrics() *Metrics {
	return &Metrics{
		cleaned: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "cubecos_zombie_filters_cleaned_total",
			Help: "Orphan TC telemetry filters deleted at agent startup (left over from a previous crashed run).",
		}),
	}
}

// Collectors returns every instrument in the bundle, suitable for
// passing to prometheus.Registerer.MustRegister.
func (m *Metrics) Collectors() []prometheus.Collector {
	return []prometheus.Collector{m.cleaned}
}

// RecordCleaned adds n to the cleaned-filters counter. Safe to call
// with n == 0 and on a nil receiver — the latter lets unit tests
// drop the metric dependency without writing a stub.
func (m *Metrics) RecordCleaned(n int) {
	if m == nil || n <= 0 {
		return
	}
	m.cleaned.Add(float64(n))
}
