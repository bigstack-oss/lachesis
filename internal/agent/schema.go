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

// Component values for the "component" slog attribute. Tag by the
// subsystem a log is ABOUT, not the file that emits it — so filtering
// `component=<subsystem>` shows that subsystem's whole story wherever
// the code lives. The same values label the metric registrations, so
// one vocabulary covers both.
const (
	componentAgent      = "agent"
	componentWAL        = "wal"
	componentNeutron    = "neutron"
	componentBPF        = "bpf"
	componentZombie     = "zombie"
	componentNetlink    = "netlink"
	componentGC         = "gc"
	componentUnresolved = "unresolved"
	componentReconcile  = "reconcile"
	componentScraper    = "scraper"
	componentKafka      = "kafka"
	componentRuntime    = "runtime"
)

// httpReadHeaderTimeout bounds how long the HTTP server will wait
// for request headers before tearing the connection down. Standard
// guard against slow-header attacks (Slowloris); set above the
// Prometheus scrape's typical RTT but well below operator patience.
const httpReadHeaderTimeout = 5 * time.Second

// Whole-connection timeouts, so a trickling client cannot hold a
// handler open on the unauthenticated listener. The write timeout is
// the constrained one: it must clear /debug/pprof/profile, which blocks
// for the profile duration (30s default) before writing a byte — a
// longer capture needs ?seconds= under ~55s. The idle timeout is set to
// preserve Prometheus's keep-alive reuse between scrapes.
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
// backoff used while waiting for Neutron at cold-start. The boot
// sequence is fail-closed — the agent must not start without metadata
// — so the loop never times out on its own; only ctx cancellation
// breaks it.
//
// Boot sequence: docs/architecture/boot-and-recovery.md#boot-sequence
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
