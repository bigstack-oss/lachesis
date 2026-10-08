package reconcile

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds the Prometheus instruments for the reconcile subsystem.
// It is the dedicated error sink for the runtime incremental-update
// path: a kernel trie-write failure during a reconcile surfaces as
// lachesis_reconcile_runs_total{result="apply_error"} rather than a
// generic counter.
//
// Metric catalogue: docs/architecture/metrics.md
//
// The instruments are:
//
//   - lachesis_reconcile_runs_total{result}        counter
//   - lachesis_reconcile_duration_seconds{trigger} histogram
//   - lachesis_reconcile_kicks_total               counter
type Metrics struct {
	runs     *prometheus.CounterVec
	duration *prometheus.HistogramVec
	kicks    prometheus.Counter
}

// NewMetrics constructs the bundle with every label value seeded so each
// series exists before the first reconcile or kick fires.
func NewMetrics() *Metrics {
	m := &Metrics{
		runs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "lachesis_reconcile_runs_total",
			Help: "Periodic Neutron reconcile passes by outcome: ok = snapshot fetched, trie delta applied, state committed; sync_error = Neutron snapshot fetch failed; apply_error = a kernel trie write failed and state was not committed (retried next pass).",
		}, []string{labelResult}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "lachesis_reconcile_duration_seconds",
			Help:    "Wall time of one reconcile pass (Neutron snapshot fetch, kernel apply, commit), by what started it: tick = the periodic timer, kick = a Kafka-driven Neutron change.",
			Buckets: prometheus.ExponentialBuckets(0.05, 2, 10), // 50ms..25.6s: a pass is a full set of Neutron list calls
		}, []string{labelTrigger}),
		kicks: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "lachesis_reconcile_kicks_total",
			Help: "Reconcile kicks: one per committed Neutron metadata change from Kafka, plus one per SIGHUP config reload. Kick-started passes are lachesis_reconcile_duration_seconds_count{trigger=\"kick\"}; the gap between the two is kicks folded into a pass.",
		}),
	}
	m.runs.WithLabelValues(resultOK)
	m.runs.WithLabelValues(resultSyncError)
	m.runs.WithLabelValues(resultApplyError)
	m.duration.WithLabelValues(triggerTick)
	m.duration.WithLabelValues(triggerKick)
	return m
}

// Collectors returns the underlying prometheus.Collector values for
// registration by the agent.
func (m *Metrics) Collectors() []prometheus.Collector {
	return []prometheus.Collector{m.runs, m.duration, m.kicks}
}

// RecordRun increments lachesis_reconcile_runs_total for one terminal
// outcome — call exactly once per reconcile pass.
func (m *Metrics) RecordRun(result string) {
	if m == nil {
		return
	}
	m.runs.WithLabelValues(result).Inc()
}

// ObservePass records one reconcile pass's wall time under trigger.
func (m *Metrics) ObservePass(trigger string, d time.Duration) {
	if m == nil {
		return
	}
	m.duration.WithLabelValues(trigger).Observe(d.Seconds())
}

// RecordKick increments lachesis_reconcile_kicks_total for one kick.
func (m *Metrics) RecordKick() {
	if m == nil {
		return
	}
	m.kicks.Inc()
}
