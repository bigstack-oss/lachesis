// schema.go gathers the agent package's package-level constants and
// pure-data types: the slog "component" label vocabulary, the HTTP and
// shutdown time budgets, the Neutron cold-start backoff bounds, and the
// labelledCollectors holder. Behavioural types (Agent, subsystemMetrics,
// Options) and the functions that consume these values live alongside
// their logic in agent.go / options.go / subsystem_metrics.go / retry.go.

package agent

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Component values for the "component" slog attribute. Logs are
// tagged by the **subsystem they're about**, not by the package or
// file that emits them — so the WAL flush goroutine in agent.go
// tags componentWAL, the Neutron cold-start orchestrator in
// coldstart_linux.go tags componentNeutron, and so on. An operator
// filtering `component=<subsystem>` sees the full story of that
// subsystem regardless of code location; grep-by-message-text is
// the recommended way to find the emission site in code.
//
// These values double as the subsystem labels in [subsystemMetrics.registrations];
// keeping a single vocabulary means a /metrics registration error and a
// log line name the same subsystem.
const (
	componentAgent   = "agent"
	componentWAL     = "wal"
	componentNeutron = "neutron"
	componentBPF     = "bpf"
	componentZombie  = "zombie"
	componentNetlink = "netlink"
	componentGC      = "gc"
)

// httpReadHeaderTimeout bounds how long the HTTP server will wait
// for request headers before tearing the connection down. Standard
// guard against slow-header attacks (Slowloris); set above the
// Prometheus scrape's typical RTT but well below operator patience.
const httpReadHeaderTimeout = 5 * time.Second

// Whole-connection timeouts so a trickling client cannot hold a
// handler (and its goroutine) open indefinitely on the
// unauthenticated listener.
//
//   - httpReadTimeout covers the entire request read, body included.
//     Every request body the server accepts is tiny (PUT
//     /debug/log-level is capped at 1 KiB), so 30s is already
//     generous.
//   - httpWriteTimeout covers writing the response. It must
//     comfortably fit the largest responses — the full /metrics
//     exposition at production scale and the /debug HTML pages — and
//     the /debug/pprof/profile handler, which blocks for the profile
//     duration (default 30s) before writing a byte. 60s clears the
//     default profile with margin; longer captures need an explicit
//     ?seconds= under ~55s.
//   - httpIdleTimeout reaps idle keep-alive connections. Prometheus
//     reuses its connection between 15s-interval scrapes, so 120s
//     keeps that reuse intact.
const (
	httpReadTimeout  = 30 * time.Second
	httpWriteTimeout = 60 * time.Second
	httpIdleTimeout  = 120 * time.Second
)

// shutdownTimeout caps the time spent gracefully draining the HTTP
// server and the scraper goroutine on shutdown. The HTTP server uses
// the full budget; the scraper gets a fresh budget after the server
// has stopped — its in-flight Tick is bounded by the configured
// scrape interval, not the shutdown budget.
const shutdownTimeout = 5 * time.Second

// neutronBackoffInitial / neutronBackoffMax bound the exponential
// backoff used while waiting for Neutron at cold-start.
// docs/DESIGN.md §9 specifies "fail-closed" — the agent must not
// start without metadata — so the loop never times out on its own;
// only ctx cancellation breaks it.
const (
	neutronBackoffInitial = 1 * time.Second
	neutronBackoffMax     = 30 * time.Second
)

// labelledCollectors pairs a subsystem label with its instruments;
// the label names the subsystem in registration-error messages.
type labelledCollectors struct {
	label      string
	collectors []prometheus.Collector
}
