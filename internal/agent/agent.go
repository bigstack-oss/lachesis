// Package agent wires the spine packages — state, scraper, metrics,
// runtime, logging — onto an HTTP server. It is the in-process glue
// between the BPF data plane and the Prometheus endpoint.
//
// # Composition
//
//   - state.GlobalState owns cumulative counters.
//   - scraper.Scraper periodically drains a MapReader into it.
//   - metrics.Collector emits Prometheus metrics from it.
//   - runtime.Manager re-reads YAML on SIGHUP and serves /debug.
//
// # Cross-platform boundary
//
// This file is cross-platform: it depends only on the scraper.MapReader
// interface, so unit tests can run on macOS with a synthetic reader.
// The production BPF reader and the TC clsact attach helper live in
// `reader_linux.go` and `attach_linux.go` respectively.
package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/config"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/logging"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/metrics"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/runtime"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/scraper"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/state"
)

// Options bundles the inputs to [New]. ConfigPath is the YAML file
// the [runtime.Manager] will re-read on SIGHUP; empty disables
// SIGHUP reload while keeping /debug functional.
type Options struct {
	Config     config.Config
	ConfigPath string
	Reader     scraper.MapReader
	Log        *logging.Handle
	// Resolver maps FlowKey → tenant_id label. nil means
	// [metrics.UnknownTenant]{}.
	Resolver metrics.TenantResolver
}

// validate rejects required fields that the caller forgot to fill.
// Returned errors are intended for [New]; no validation is done on
// optional fields here (defaults are applied elsewhere).
func (o Options) validate() error {
	if o.Reader == nil {
		return errors.New("agent: Options.Reader is nil")
	}
	if o.Log == nil {
		return errors.New("agent: Options.Log is nil")
	}
	return nil
}

// resolverOrDefault returns the caller's [TenantResolver] when set,
// otherwise the no-Neutron stub. Centralising the default keeps
// [New] free of branches that aren't about wiring.
func (o Options) resolverOrDefault() metrics.TenantResolver {
	if o.Resolver != nil {
		return o.Resolver
	}
	return metrics.UnknownTenant{}
}

// Agent owns the in-process composition of the telemetry data plane:
// [state.GlobalState], the [scraper.Scraper] goroutine, the metrics
// Collector, the runtime manager, and the HTTP server. Construct one
// with [New] (or [Bootstrap] for the full Linux startup sequence),
// then call [Agent.Run]; Run blocks until ctx is cancelled.
type Agent struct {
	cfg       config.Config
	state     *state.GlobalState
	scraper   *scraper.Scraper
	collector *metrics.Collector
	runtime   *runtime.Manager
	log       *logging.Handle
	listener  net.Listener
	server    *http.Server
}

// New constructs the agent. The HTTP listener is opened immediately so
// callers can use [Agent.Addr] before [Agent.Run] starts serving — useful
// for tests that request an ephemeral port (":0") and then need the
// resolved address.
//
// New reads top-to-bottom as the agent's composition order: validate
// inputs, build the data plane (state + scraper + collector), wire the
// Prometheus registry, mount the HTTP surface, open the listener.
func New(opts Options) (*Agent, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}

	st := state.New()
	sc := scraper.New(opts.Reader, st, opts.Config.Scrape.Interval)
	col := metrics.New(st, sc, opts.resolverOrDefault())

	reg, err := buildRegistry(col)
	if err != nil {
		return nil, err
	}

	mgr := runtime.New(opts.ConfigPath, opts.Config, opts.Log)
	handler := buildHTTPHandler(reg, mgr)

	ln, err := net.Listen("tcp", opts.Config.HTTP.Listen)
	if err != nil {
		return nil, fmt.Errorf("agent: listen %s: %w", opts.Config.HTTP.Listen, err)
	}

	return &Agent{
		cfg:       opts.Config,
		state:     st,
		scraper:   sc,
		collector: col,
		runtime:   mgr,
		log:       opts.Log,
		listener:  ln,
		server:    &http.Server{Handler: handler, ReadHeaderTimeout: httpReadHeaderTimeout},
	}, nil
}

// buildRegistry creates a fresh Prometheus registry and binds the
// agent's custom Collector to it. Wrapping the call here keeps the
// "construct the registry" intent visible in [New] without making
// the registration error path a sibling of the data-plane wiring.
func buildRegistry(col *metrics.Collector) (*prometheus.Registry, error) {
	reg := prometheus.NewRegistry()
	if err := reg.Register(col); err != nil {
		return nil, fmt.Errorf("agent: register collector: %w", err)
	}
	return reg, nil
}

// buildHTTPHandler returns the mux the HTTP server will serve.
// Centralising the route table here is the seam future subsystems
// (e.g. a /healthz, a /reload, a /pprof under debug) attach to —
// rather than each one widening [New].
func buildHTTPHandler(reg *prometheus.Registry, mgr *runtime.Manager) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.Handle("/debug/", mgr.DebugHandler())
	return mux
}

// httpReadHeaderTimeout bounds how long the HTTP server will wait
// for request headers before tearing the connection down. Standard
// guard against slow-header attacks (Slowloris); set above the
// Prometheus scrape's typical RTT but well below operator patience.
const httpReadHeaderTimeout = 5 * time.Second

// Addr returns the address the HTTP server is bound to. Stable as
// soon as [New] returns; remains valid after Run starts and after it
// returns.
func (a *Agent) Addr() string {
	return a.listener.Addr().String()
}

// shutdownTimeout caps the time spent gracefully draining the HTTP
// server and the scraper goroutine on shutdown. The HTTP server uses
// the full budget; the scraper gets a fresh budget after the server
// has stopped — its in-flight Tick is bounded by the configured
// scrape interval, not the shutdown budget.
const shutdownTimeout = 5 * time.Second

// Run starts the scraper and HTTP server and blocks until ctx is
// cancelled or the server fails. On graceful shutdown it stops
// accepting new HTTP requests, drains in-flight scrapes, then waits
// for the scraper goroutine to finish its current Tick so callers
// can safely release BPF resources without racing the kernel-map
// read.
//
// TC programs are not detached on shutdown — the qdisc and filter
// outlive the process. The next agent start replaces them via
// netlink's idempotent QdiscReplace / FilterReplace. A clean detach
// + a recovery path for filters orphaned by crashes are planned.
func (a *Agent) Run(ctx context.Context) error {
	a.runtime.InstallSIGHUP(ctx)

	scraperDone := make(chan struct{})
	go func() {
		a.scraper.Run(ctx)
		close(scraperDone)
	}()

	srvErr := make(chan error, 1)
	go func() {
		if err := a.server.Serve(a.listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			srvErr <- err
			return
		}
		srvErr <- nil
	}()

	slog.Info("agent: serving", "addr", a.Addr(), "scrape_interval", a.cfg.Scrape.Interval)

	select {
	case <-ctx.Done():
		return a.shutdown(srvErr, scraperDone)
	case err := <-srvErr:
		return err
	}
}

// shutdown drains the HTTP server, then awaits the scraper. Called
// after ctx fires. Returns an error only if HTTP shutdown itself
// fails — a scraper timeout is logged but not promoted to an error,
// because by then the agent's job is done.
func (a *Agent) shutdown(srvErr <-chan error, scraperDone <-chan struct{}) error {
	slog.Info("agent: shutdown initiated")

	httpCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := a.server.Shutdown(httpCtx); err != nil {
		return fmt.Errorf("agent: http shutdown: %w", err)
	}
	<-srvErr
	slog.Info("agent: http server stopped")

	// The scraper checks ctx.Done() between Ticks; an in-flight Tick
	// must finish (drain kernel map, apply deltas) before Run returns
	// so callers' BPF-collection close does not race the read.
	select {
	case <-scraperDone:
		slog.Info("agent: scraper stopped")
	case <-time.After(shutdownTimeout):
		slog.Warn("agent: scraper did not exit within shutdown budget",
			"budget", shutdownTimeout)
	}

	slog.Info("agent: shutdown complete")
	return nil
}
