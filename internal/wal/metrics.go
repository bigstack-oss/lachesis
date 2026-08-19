package wal

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds the WAL instruments: the three flush phases
// (copy-under-lock, marshal, write+fsync+rename), the per-stage failure
// counter, the boot-load fallback counter, and the state-restart epoch
// the boot restore decides. nil is acceptable everywhere observations
// land.
//
// docs/architecture/metrics.md
type Metrics struct {
	snapshotCopySeconds prometheus.Histogram
	marshalSeconds      prometheus.Histogram
	flushLatencySeconds prometheus.Histogram
	flushFailures       *prometheus.CounterVec
	loadFallback        *prometheus.CounterVec
	countersReset       prometheus.Gauge
}

// NewMetrics constructs the WAL instrument bundle. Buckets follow
// the design SLOs: 1 ms..1 s for the flush phase (where the p99
// target is < 50 ms), Prometheus defaults for the other two. Every
// known label child of the two counters is seeded at zero — a
// labelled counter emits no series until its first increment, so
// without the seed a healthy agent shows "No data" instead of 0 on
// the dashboard.
func NewMetrics() *Metrics {
	m := &Metrics{
		snapshotCopySeconds: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "lachesis_wal_snapshot_copy_seconds",
			Help:    "WAL writer, copy-under-lock phase (critical section).",
			Buckets: prometheus.DefBuckets,
		}),
		marshalSeconds: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "lachesis_wal_marshal_seconds",
			Help:    "WAL writer, JSON marshal phase (no lock held).",
			Buckets: prometheus.DefBuckets,
		}),
		flushLatencySeconds: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "lachesis_wal_flush_latency_seconds",
			Help:    "WAL writer, write+fsync+rename phase (no lock held).",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 11), // 1ms..1.024s
		}),
		flushFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "lachesis_wal_flush_failures_total",
			Help: "Failed WAL flush attempts, labelled by which sub-stage tripped.",
		}, []string{"stage"}),
		loadFallback: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "lachesis_wal_load_fallback_total",
			Help: "WAL boot loader fallbacks — bak when primary was unusable, empty on first boot or when both files were unreadable.",
		}, []string{"from"}),
		countersReset: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "lachesis_agent_counters_reset_timestamp_seconds",
			Help: "Unix time the agent's billing state last restarted — counter baselines are not comparable across this instant. Constant per process; each distinct value in a TSDB window is one declared discontinuity the billing ETL splits its day segments at (docs/architecture/billing.md).",
		}),
	}
	for _, stage := range []string{StageWrite, StageFsync, StageRenameBak, StageRenameCurrent, StageDirSync} {
		m.flushFailures.WithLabelValues(stage).Add(0)
	}
	for _, from := range []string{LoadFallbackBak, LoadFallbackEmpty} {
		m.loadFallback.WithLabelValues(from).Add(0)
	}
	return m
}

// Collectors returns every instrument in the bundle, suitable for
// passing to prometheus.Registerer.MustRegister.
func (m *Metrics) Collectors() []prometheus.Collector {
	return []prometheus.Collector{
		m.snapshotCopySeconds,
		m.marshalSeconds,
		m.flushLatencySeconds,
		m.flushFailures,
		m.loadFallback,
		m.countersReset,
	}
}

// ObserveCopy records one snapshot-copy duration. Intended for the
// caller of [GlobalState.SnapshotForWAL] (it's the only place that
// can time the RLock-held section).
func (m *Metrics) ObserveCopy(d time.Duration) {
	if m == nil {
		return
	}
	m.snapshotCopySeconds.Observe(d.Seconds())
}

// observeMarshal / observeFlush / observeFailure / observeLoadFallback
// are the internal nil-safe call sites. Tests reach the underlying
// instruments via Collectors() + a Registry.Gather.
func (m *Metrics) observeMarshal(d time.Duration) {
	if m == nil {
		return
	}
	m.marshalSeconds.Observe(d.Seconds())
}

func (m *Metrics) observeFlush(d time.Duration) {
	if m == nil {
		return
	}
	m.flushLatencySeconds.Observe(d.Seconds())
}

func (m *Metrics) observeFailure(stage string) {
	if m == nil {
		return
	}
	m.flushFailures.WithLabelValues(stage).Inc()
}

// SetCountersReset publishes the state-restart epoch the boot
// restore decided — once, before workers start; the value then holds
// for the process lifetime (the process_start_time_seconds idiom).
func (m *Metrics) SetCountersReset(unixSeconds int64) {
	if m == nil {
		return
	}
	m.countersReset.Set(float64(unixSeconds))
}

// RecordLoadFallback bumps the load-fallback counter. The caller
// (typically the boot loader) decides whether the bak / empty
// outcome is a fallback worth recording — primary loads should not
// call this.
func (m *Metrics) RecordLoadFallback(from string) {
	if m == nil {
		return
	}
	m.loadFallback.WithLabelValues(from).Inc()
}
