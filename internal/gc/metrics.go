package gc

import "github.com/prometheus/client_golang/prometheus"

// Metrics holds the Prometheus instruments for the GC subsystem. The
// bundle owns both halves of the GC: the lingering-ghost sweep (this
// package's [GhostSweeper]) and pressure-relief eviction (run inside
// the scraper's drain goroutine, which holds a reference to this
// bundle). Keeping the cubecos_gc_evictions_total family in one place
// — rather than splitting it across two packages — means Prometheus
// registers each series once and the reason label is seeded whole.
//
// The instruments are:
//
//   - cubecos_gc_evictions_total{reason}        counter
//   - cubecos_gc_pressure_relief_runs_total     counter
//   - cubecos_lingering_ghosts_active           gauge
type Metrics struct {
	evictions         *prometheus.CounterVec
	pressureReliefRun prometheus.Counter
	ghostsActive      prometheus.Gauge
}

// NewMetrics constructs the bundle with both eviction reasons seeded at
// zero so cubecos_gc_evictions_total{reason="ttl"} and
// {reason="pressure_relief"} both exist before either path first fires.
func NewMetrics() *Metrics {
	m := &Metrics{
		evictions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "cubecos_gc_evictions_total",
			Help: "Map entries the GC evicted, by reason: ttl = lingering-ghost expiry from mac_tenant_map; pressure_relief = oldest-flow eviction from telemetry_map above the configured fill high watermark.",
		}, []string{labelReason}),
		pressureReliefRun: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "cubecos_gc_pressure_relief_runs_total",
			Help: "Pressure-relief passes run after a scrape drain found telemetry_map above the configured fill high watermark (docs/DESIGN.md §3.1).",
		}),
		ghostsActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "cubecos_lingering_ghosts_active",
			Help: "Metadata entries currently in the 60s Lingering-Ghost grace window (DeleteAt set, not yet swept).",
		}),
	}
	m.evictions.WithLabelValues(reasonTTL)
	m.evictions.WithLabelValues(reasonPressureRelief)
	m.evictions.WithLabelValues(reasonGhostResidualFlow)
	return m
}

// Collectors returns the underlying prometheus.Collector values for
// registration by the agent.
func (m *Metrics) Collectors() []prometheus.Collector {
	return []prometheus.Collector{m.evictions, m.pressureReliefRun, m.ghostsActive}
}

// RecordTTLEvictions adds n lingering-ghost expiries to
// cubecos_gc_evictions_total{reason="ttl"}.
func (m *Metrics) RecordTTLEvictions(n int) {
	if m == nil || n == 0 {
		return
	}
	m.evictions.WithLabelValues(reasonTTL).Add(float64(n))
}

// RecordPressureReliefEvictions adds n telemetry_map evictions to
// cubecos_gc_evictions_total{reason="pressure_relief"}.
func (m *Metrics) RecordPressureReliefEvictions(n int) {
	if m == nil || n == 0 {
		return
	}
	m.evictions.WithLabelValues(reasonPressureRelief).Add(float64(n))
}

// RecordResidualFlowEvictions adds n telemetry_map flows deleted because
// their VM's MAC was swept, to
// cubecos_gc_evictions_total{reason="ghost_residual_flow"}.
func (m *Metrics) RecordResidualFlowEvictions(n int) {
	if m == nil || n == 0 {
		return
	}
	m.evictions.WithLabelValues(reasonGhostResidualFlow).Add(float64(n))
}

// IncPressureReliefRuns increments cubecos_gc_pressure_relief_runs_total
// by one — call once per pressure-relief pass.
func (m *Metrics) IncPressureReliefRuns() {
	if m == nil {
		return
	}
	m.pressureReliefRun.Inc()
}

// SetGhostsActive sets cubecos_lingering_ghosts_active to the number of
// entries still inside their grace window after a sweep.
func (m *Metrics) SetGhostsActive(n int) {
	if m == nil {
		return
	}
	m.ghostsActive.Set(float64(n))
}
