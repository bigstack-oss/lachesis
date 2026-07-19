package reconcile

import "github.com/prometheus/client_golang/prometheus"

// Metrics holds the Prometheus instruments for the reconcile subsystem.
// It is the dedicated error sink for the runtime incremental-update path
// that docs/architecture/metrics.md anticipated: a kernel trie-write failure
// during a reconcile surfaces as lachesis_reconcile_runs_total{result="apply_error"}
// rather than a generic counter.
//
// The instruments are:
//
//   - lachesis_reconcile_runs_total{result}   counter
type Metrics struct {
	runs *prometheus.CounterVec
}

// NewMetrics constructs the bundle with all three result outcomes seeded
// at zero so each series exists before the first reconcile fires.
func NewMetrics() *Metrics {
	m := &Metrics{
		runs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "lachesis_reconcile_runs_total",
			Help: "Periodic Neutron reconcile passes by outcome: ok = snapshot fetched, trie delta applied, state committed; sync_error = Neutron snapshot fetch failed; apply_error = a kernel trie write failed and state was not committed (retried next pass).",
		}, []string{labelResult}),
	}
	m.runs.WithLabelValues(resultOK)
	m.runs.WithLabelValues(resultSyncError)
	m.runs.WithLabelValues(resultApplyError)
	return m
}

// Collectors returns the underlying prometheus.Collector values for
// registration by the agent.
func (m *Metrics) Collectors() []prometheus.Collector {
	return []prometheus.Collector{m.runs}
}

// RecordRun increments lachesis_reconcile_runs_total for one terminal
// outcome — call exactly once per reconcile pass.
func (m *Metrics) RecordRun(result string) {
	if m == nil {
		return
	}
	m.runs.WithLabelValues(result).Inc()
}
