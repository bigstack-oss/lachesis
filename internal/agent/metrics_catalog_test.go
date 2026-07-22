package agent

import (
	"bytes"
	"os"
	"regexp"
	"sort"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/bigstack-oss/lachesis/internal/config"
	"github.com/bigstack-oss/lachesis/internal/logging"
)

// catalogPath locates the metrics catalog chapter relative to this
// package directory.
const catalogPath = "../../docs/architecture/metrics.md"

// catalogRow matches a markdown table row whose first cell is a
// backticked metric name — the shape every cataloged metric uses in
// docs/architecture/metrics.md. Names appearing in prose or PromQL
// examples are deliberately not matched: only a table row makes a
// metric part of the catalog.
var catalogRow = regexp.MustCompile("(?m)^\\|\\s*`(lachesis_[a-z0-9_]+)`\\s*\\|")

// TestMetricsCatalogInSync is the companion guard to
// [TestMetricNamingConventions]: names stay well-formed there, and the
// full set stays documented here. It walks every collector the agent
// actually registers — the same enumeration as buildRegistry, so it
// cannot drift from /metrics — and asserts the name set equals the
// catalog tables in docs/architecture/metrics.md. This is the test the
// catalog's "pinned by tests" preamble promises: adding a metric
// without a catalog row, or removing one while its row lingers, fails
// CI by name.
func TestMetricsCatalogInSync(t *testing.T) {
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

	registered := make(map[string]bool)
	collectors := []prometheus.Collector{a.collector}
	for _, r := range a.mx.registrations() {
		collectors = append(collectors, r.collectors...)
	}
	for _, c := range collectors {
		for _, name := range descNames(c) {
			registered[name] = true
		}
	}
	if len(registered) == 0 {
		t.Fatal("no metric descriptors enumerated — did the registration path change?")
	}

	doc, err := os.ReadFile(catalogPath)
	if err != nil {
		t.Fatalf("read catalog: %v", err)
	}
	documented := make(map[string]bool)
	for _, m := range catalogRow.FindAllStringSubmatch(string(doc), -1) {
		documented[m[1]] = true
	}
	if len(documented) == 0 {
		t.Fatalf("no metric rows parsed from %s — did the table format change?", catalogPath)
	}

	for _, name := range sortedDiff(registered, documented) {
		t.Errorf("metric %q is registered but has no catalog row in %s", name, catalogPath)
	}
	for _, name := range sortedDiff(documented, registered) {
		t.Errorf("catalog row %q in %s names a metric the agent no longer registers", name, catalogPath)
	}
}

// sortedDiff returns the keys of a that are absent from b, sorted for
// stable failure output.
func sortedDiff(a, b map[string]bool) []string {
	var diff []string
	for k := range a {
		if !b[k] {
			diff = append(diff, k)
		}
	}
	sort.Strings(diff)
	return diff
}
