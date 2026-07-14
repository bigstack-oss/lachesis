package agent

import (
	"bytes"
	"regexp"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/bigstack-oss/lachesis/internal/bpf"
	"github.com/bigstack-oss/lachesis/internal/config"
	"github.com/bigstack-oss/lachesis/internal/logging"
)

// convNoopReader is a stub scraper.MapReader: the convention test only
// needs a constructed Agent to enumerate the metrics it registers, never
// a running scrape loop.
type convNoopReader struct{}

func (convNoopReader) BatchLookup(map[bpf.FlowKey]bpf.FlowMetrics) error { return nil }

// metricName accepts the lachesis_ prefix followed by clean snake_case:
// lowercase alphanumeric segments joined by single underscores. It
// rejects uppercase, leading/trailing/double underscores, and any other
// prefix.
var metricName = regexp.MustCompile(`^lachesis_[a-z0-9]+(_[a-z0-9]+)*$`)

// descFqName pulls the fully-qualified name out of a [prometheus.Desc]'s
// String() form (`Desc{fqName: "lachesis_x", ...}`). Describe — not
// Gather — is the enumeration source so unobserved CounterVec /
// HistogramVec metrics (which emit no series until first use but are
// still part of the exposed surface) are included.
var descFqName = regexp.MustCompile(`fqName: "([^"]+)"`)

// TestMetricNamingConventions is the one centralized guard over the
// otherwise-decentralized metric definitions. Metrics live in each
// subsystem's package by design; this test walks every collector the
// agent actually registers — the billing Collector plus each bundle, via
// the real [subsystemMetrics.registrations] list, so it cannot drift from
// what /metrics exposes — and asserts the cross-cutting rules no single
// package owns: the lachesis_ prefix, clean snake_case, and no duplicate
// name across subsystems.
//
// Type-specific Prometheus suffixes (counters end _total, time
// histograms end _seconds) currently all hold and are reviewed per-PR;
// they are not machine-checked here because Describe does not carry the
// metric type (that needs an observed Gather).
func TestMetricNamingConventions(t *testing.T) {
	cfg := config.Defaults()
	cfg.HTTP.Listen = "127.0.0.1:0" // ephemeral; the test never serves
	cfg.WAL.Enabled = false         // no flush goroutine / disk touch
	log, err := logging.Init(cfg.Logging, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("logging.Init: %v", err)
	}
	a, err := New(Options{Config: cfg, Reader: convNoopReader{}, Log: log})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer a.listener.Close()

	// The exact set buildRegistry binds to /metrics, in the same order.
	collectors := []prometheus.Collector{a.collector}
	for _, r := range a.mx.registrations() {
		collectors = append(collectors, r.collectors...)
	}

	seen := make(map[string]bool)
	for _, c := range collectors {
		for _, name := range descNames(c) {
			if !metricName.MatchString(name) {
				t.Errorf("metric %q violates naming convention %s", name, metricName)
			}
			if seen[name] {
				t.Errorf("duplicate metric name %q registered by more than one collector", name)
			}
			seen[name] = true
		}
	}
	if len(seen) == 0 {
		t.Fatal("no metric descriptors enumerated — did the registration path change?")
	}
}

// descNames returns the fully-qualified names a collector declares via
// Describe.
func descNames(c prometheus.Collector) []string {
	ch := make(chan *prometheus.Desc, 64)
	go func() {
		c.Describe(ch)
		close(ch)
	}()
	var names []string
	for d := range ch {
		if m := descFqName.FindStringSubmatch(d.String()); m != nil {
			names = append(names, m[1])
		}
	}
	return names
}
