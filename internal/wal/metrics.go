package wal

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds the WAL-subsystem Prometheus instruments. Construct
// with [NewMetrics], register the slice from [Metrics.Collectors]
// with your prometheus.Registry, then pass the *Metrics through to
// [Save] and to the boot loader. nil is acceptable everywhere
// observations land — the Observe* helpers handle it.
//
// The five instruments mirror docs/DESIGN.md §11.4:
//
//   - cubecos_wal_snapshot_copy_seconds        copy-under-lock phase
//   - cubecos_wal_marshal_seconds              JSON marshal phase
//   - cubecos_wal_flush_latency_seconds        write+fsync+rename phase
//   - cubecos_wal_flush_failures_total{stage}  per-stage failure counter
//   - cubecos_wal_load_fallback_total{from}    boot-load fallback counter
type Metrics struct {
	snapshotCopySeconds prometheus.Histogram
	marshalSeconds      prometheus.Histogram
	flushLatencySeconds prometheus.Histogram
	flushFailures       *prometheus.CounterVec
	loadFallback        *prometheus.CounterVec
}

// NewMetrics constructs the WAL instrument bundle. Buckets follow
// the design SLOs: 1 ms..1 s for the flush phase (where the p99
// target is < 50 ms), Prometheus defaults for the other two.
func NewMetrics() *Metrics {
	return &Metrics{
		snapshotCopySeconds: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "cubecos_wal_snapshot_copy_seconds",
			Help:    "WAL writer, copy-under-lock phase (critical section).",
			Buckets: prometheus.DefBuckets,
		}),
		marshalSeconds: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "cubecos_wal_marshal_seconds",
			Help:    "WAL writer, JSON marshal phase (no lock held).",
			Buckets: prometheus.DefBuckets,
		}),
		flushLatencySeconds: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "cubecos_wal_flush_latency_seconds",
			Help:    "WAL writer, write+fsync+rename phase (no lock held).",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 11), // 1ms..1.024s
		}),
		flushFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "cubecos_wal_flush_failures_total",
			Help: "Failed WAL flush attempts, labelled by which sub-stage tripped.",
		}, []string{"stage"}),
		loadFallback: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "cubecos_wal_load_fallback_total",
			Help: "WAL boot loader fallbacks — bak when primary was unusable, empty on first boot or when both files were unreadable.",
		}, []string{"from"}),
	}
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
