package unresolved

import "github.com/prometheus/client_golang/prometheus"

// Metrics holds the Prometheus instruments for the UnresolvedBuffer
// (docs/DESIGN.md §11.4). The instruments are:
//
//   - cubecos_unresolved_buffer_depth              gauge
//   - cubecos_unresolved_buffer_evictions_total{reason}  counter
//   - cubecos_unresolved_resolved_total            counter
//
// depth tracks live buffer occupancy (an SLO panic threshold sits near
// the cap); evictions counts entries folded to "unknown", by reason;
// resolved counts late-binding successes — it stays at zero until the
// Kafka consumer can make a buffered MAC newly known (a later sprint),
// and is declared now so the series exists from the start.
type Metrics struct {
	depth     prometheus.Gauge
	evictions *prometheus.CounterVec
	resolved  prometheus.Counter
}

// NewMetrics constructs the bundle with both eviction reasons seeded at
// zero so cubecos_unresolved_buffer_evictions_total{reason="lru"} and
// {reason="expired"} both exist before either path first fires.
func NewMetrics() *Metrics {
	m := &Metrics{
		depth: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "cubecos_unresolved_buffer_depth",
			Help: "Distinct unknown-MAC flows currently held in the UnresolvedBuffer (capped; nearing the cap is an SLO panic threshold).",
		}),
		evictions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "cubecos_unresolved_buffer_evictions_total",
			Help: "Buffer entries folded to the \"unknown\" tenant and dropped, by reason: lru = evicted to stay under the cap; expired = the late-binding TTL elapsed.",
		}, []string{labelReason}),
		resolved: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "cubecos_unresolved_resolved_total",
			Help: "Buffered flows whose MAC became known within the TTL and were attributed to the right tenant (late-binding success path; lands with the Kafka consumer).",
		}),
	}
	m.evictions.WithLabelValues(reasonLRU)
	m.evictions.WithLabelValues(reasonExpired)
	return m
}

// Collectors returns the underlying prometheus.Collector values for
// registration by the agent.
func (m *Metrics) Collectors() []prometheus.Collector {
	return []prometheus.Collector{m.depth, m.evictions, m.resolved}
}

// SetDepth records current buffer occupancy. Called after each sweep.
func (m *Metrics) SetDepth(n int) {
	if m == nil {
		return
	}
	m.depth.Set(float64(n))
}

// RecordLRUEviction counts one entry evicted to stay under the cap.
func (m *Metrics) RecordLRUEviction() {
	if m == nil {
		return
	}
	m.evictions.WithLabelValues(reasonLRU).Inc()
}

// RecordExpiredEvictions adds n entries dropped because their TTL
// elapsed (the per-sweep count).
func (m *Metrics) RecordExpiredEvictions(n int) {
	if m == nil || n == 0 {
		return
	}
	m.evictions.WithLabelValues(reasonExpired).Add(float64(n))
}

// RecordResolved counts one buffered flow whose MAC became known and was
// handed off to the right tenant — call once per late-binding success.
func (m *Metrics) RecordResolved() {
	if m == nil {
		return
	}
	m.resolved.Inc()
}
