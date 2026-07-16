package runtime

import "github.com/prometheus/client_golang/prometheus"

// Metrics is the runtime subsystem's instrument bundle: reload
// outcomes, so a failed SIGHUP (malformed YAML kept the old config
// running) is observable instead of silent. Registered centrally by
// the agent like every per-package bundle.
type Metrics struct {
	reloads *prometheus.CounterVec
}

// NewMetrics constructs the bundle and pre-seeds every result label so
// the series exist before the first reload.
func NewMetrics() *Metrics {
	m := &Metrics{
		reloads: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "lachesis_config_reloads_total",
			Help: "SIGHUP config reloads by outcome: applied, invalid (validation or apply failure — running config kept), read_error (file unreadable — running config kept).",
		}, []string{labelResult}),
	}
	for _, r := range []string{reloadApplied, reloadInvalid, reloadReadError} {
		m.reloads.WithLabelValues(r).Add(0)
	}
	return m
}

// RecordReload counts one reload outcome.
func (m *Metrics) RecordReload(result string) {
	m.reloads.WithLabelValues(result).Inc()
}

// Collectors returns the bundle's instruments for central registration.
func (m *Metrics) Collectors() []prometheus.Collector {
	return []prometheus.Collector{m.reloads}
}

const (
	labelResult     = "result"
	reloadApplied   = "applied"
	reloadInvalid   = "invalid"
	reloadReadError = "read_error"
)
