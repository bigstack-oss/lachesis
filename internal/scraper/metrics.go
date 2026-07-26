package scraper

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds the scraper-subsystem Prometheus instruments. Construct
// with [NewMetrics], register the slice from [Metrics.Collectors] with
// your prometheus.Registry, then hand the *Metrics to
// [Scraper.SetMetrics]. nil is acceptable — the Observe* helpers handle
// it, so a Scraper without metrics simply records nothing.
//
// The bundle mirrors docs/architecture/metrics.md:
//
//   - lachesis_scrape_duration_seconds   one successful drain+integrate tick
type Metrics struct {
	scrapeDuration prometheus.Histogram
}

// NewMetrics constructs the scraper instrument bundle. The bucket span
// matches the WAL flush and Collect histograms (1 ms..1 s) so the three
// per-tick costs are directly comparable on a dashboard; the upper decade
// matters here because the drain grows with entries × N_CPU and is
// expected to reach tens of milliseconds on high-core hosts
// (docs/architecture/performance.md).
func NewMetrics() *Metrics {
	return &Metrics{
		scrapeDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "lachesis_scrape_duration_seconds",
			Help:    "Duration of one successful scraper tick: telemetry_map BatchLookup drain, delta integration, and the pressure-relief pass. Failed drains are excluded (see lachesis_scraper_errors_total).",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 11), // 1ms..1.024s
		}),
	}
}

// Collectors returns every instrument in the bundle, suitable for
// passing to prometheus.Registerer.MustRegister.
func (m *Metrics) Collectors() []prometheus.Collector {
	return []prometheus.Collector{m.scrapeDuration}
}

// ObserveScrape records one completed tick's wall time. Only successful
// ticks are observed — a tick whose drain failed did a fraction of the
// work, and mixing those in would pull the quantiles down precisely when
// drains are failing; lachesis_scraper_errors_total carries that signal.
// nil-safe.
func (m *Metrics) ObserveScrape(d time.Duration) {
	if m == nil {
		return
	}
	m.scrapeDuration.Observe(d.Seconds())
}
