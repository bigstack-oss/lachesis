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
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/wal"
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

	walMetrics *wal.Metrics

	// walRecBuf is the reused SnapshotForWAL destination so a
	// steady-state flush does not allocate a fresh records slice.
	// Owned solely by the WAL flush goroutine; no lock needed.
	walRecBuf []state.Record
}

// WALMetrics returns the WAL instrument bundle the agent registered
// with its prometheus.Registry. Exposed so the boot path can record
// load-fallback observations on the same Metrics that the periodic
// flush will later contribute timings to.
func (a *Agent) WALMetrics() *wal.Metrics { return a.walMetrics }

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

	walMx := wal.NewMetrics()
	reg, err := buildRegistry(col, walMx)
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
		cfg:        opts.Config,
		state:      st,
		scraper:    sc,
		collector:  col,
		runtime:    mgr,
		log:        opts.Log,
		listener:   ln,
		server:     &http.Server{Handler: handler, ReadHeaderTimeout: httpReadHeaderTimeout},
		walMetrics: walMx,
	}, nil
}

// buildRegistry creates a fresh Prometheus registry and binds the
// agent's custom Collector plus the WAL instruments to it. The two
// register in tandem so /metrics is the single endpoint operators
// scrape — billing and WAL health on one wire.
func buildRegistry(col *metrics.Collector, walMx *wal.Metrics) (*prometheus.Registry, error) {
	reg := prometheus.NewRegistry()
	if err := reg.Register(col); err != nil {
		return nil, fmt.Errorf("agent: register collector: %w", err)
	}
	for _, c := range walMx.Collectors() {
		if err := reg.Register(c); err != nil {
			return nil, fmt.Errorf("agent: register wal metric: %w", err)
		}
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

// Component values for the "component" slog attribute. Logs about
// agent lifecycle use componentAgent; logs about the WAL flush
// goroutine and the WAL boot loader use componentWAL even though
// they're emitted from this package.
const (
	componentAgent = "agent"
	componentWAL   = "wal"
)

// SeedState seeds the agent's [state.GlobalState] from records,
// intended to run between [New] and [Run] (for example, after a
// WAL restore on boot). Takes the state's write lock; safe to call
// before any other goroutine touches the agent.
func (a *Agent) SeedState(records []state.Record) {
	a.state.Restore(records)
}

// Run starts the scraper, WAL flush goroutine (when enabled), and
// HTTP server. Blocks until ctx is cancelled or the server fails.
//
// On graceful shutdown it stops accepting new HTTP requests, drains
// in-flight scrapes, waits for the scraper goroutine to finish its
// current Tick (so callers can safely release BPF resources without
// racing the kernel-map read), then lets the WAL flush goroutine
// run its final flush.
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

	walDone := make(chan struct{})
	if a.cfg.WAL.Enabled {
		go a.walFlushLoop(ctx, walDone)
	} else {
		close(walDone)
	}

	srvErr := make(chan error, 1)
	go func() {
		if err := a.server.Serve(a.listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			srvErr <- err
			return
		}
		srvErr <- nil
	}()

	slog.Info("serving",
		"component", componentAgent,
		"addr", a.Addr(),
		"scrape_interval", a.cfg.Scrape.Interval,
		"wal_enabled", a.cfg.WAL.Enabled,
	)

	select {
	case <-ctx.Done():
		return a.shutdown(srvErr, scraperDone, walDone)
	case err := <-srvErr:
		return err
	}
}

// walFlushLoop drains [state.GlobalState] to disk on the configured
// cadence. On ctx cancellation it runs one final flush before
// signalling done — that's how a clean shutdown captures the latest
// deltas the scraper applied between the last periodic flush and
// the SIGINT/SIGTERM.
func (a *Agent) walFlushLoop(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	t := time.NewTicker(a.cfg.WAL.FlushInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			if err := a.flushWAL(); err != nil {
				slog.Warn("final flush failed", "component", componentWAL, "err", err)
				return
			}
			slog.Info("final flush ok", "component", componentWAL, "records", len(a.walRecBuf))
			return
		case <-t.C:
			if err := a.flushWAL(); err != nil {
				slog.Warn("periodic flush failed", "component", componentWAL, "err", err)
			}
		}
	}
}

// flushWAL snapshots GlobalState and writes it via [wal.Save]. The
// snapshot uses a reused buffer; steady-state flushes do not
// allocate beyond the JSON marshal that wal.Save performs. The
// copy-under-lock duration is recorded here because only this
// function sees the RLock window; marshal + write+fsync+rename
// timings are recorded inside Save.
func (a *Agent) flushWAL() error {
	copyStart := time.Now()
	a.walRecBuf = a.state.SnapshotForWAL(a.walRecBuf[:0])
	a.walMetrics.ObserveCopy(time.Since(copyStart))
	return wal.Save(a.cfg.WAL.Path, "", a.walRecBuf, a.walMetrics)
}

// shutdown drains the HTTP server, awaits the scraper, then awaits
// the WAL flush goroutine's final flush. Returns an error only if
// HTTP shutdown itself fails — scraper / WAL timeouts are logged
// but not promoted to errors, because by then the agent's job is
// done.
//
// Drain order matters: scraper drains first so the latest deltas
// land in state, then the WAL final flush captures them. Both
// drains are deferred so they run even on an HTTP shutdown error
// (otherwise the BPF-collection close in main could race the
// kernel-map read, and the latest in-memory state could be lost).
func (a *Agent) shutdown(srvErr <-chan error, scraperDone, walDone <-chan struct{}) error {
	slog.Info("shutdown initiated", "component", componentAgent)
	defer a.awaitWAL(walDone)
	defer a.awaitScraper(scraperDone)

	httpCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := a.server.Shutdown(httpCtx); err != nil {
		return fmt.Errorf("agent: http shutdown: %w", err)
	}
	<-srvErr
	slog.Info("http server stopped", "component", componentAgent)
	return nil
}

// awaitScraper blocks until the scraper goroutine has exited its
// current Tick, or shutdownTimeout elapses. Always runs as part of
// shutdown so a slow HTTP drain does not leave the scraper holding
// a BPF map read while the caller closes the collection.
func (a *Agent) awaitScraper(scraperDone <-chan struct{}) {
	select {
	case <-scraperDone:
		slog.Info("scraper stopped", "component", componentAgent)
	case <-time.After(shutdownTimeout):
		slog.Warn("scraper did not exit within shutdown budget",
			"component", componentAgent,
			"budget", shutdownTimeout)
	}
}

// awaitWAL blocks until the WAL flush goroutine has run its final
// flush and exited, or shutdownTimeout elapses. The final flush is
// best-effort: a timeout here means we lose the last in-memory
// deltas the periodic flush did not capture (≤flush_interval of
// data), which is the design's stated worst case.
func (a *Agent) awaitWAL(walDone <-chan struct{}) {
	select {
	case <-walDone:
		slog.Info("wal stopped", "component", componentAgent)
	case <-time.After(shutdownTimeout):
		slog.Warn("wal did not exit within shutdown budget",
			"component", componentAgent,
			"budget", shutdownTimeout)
	}
	slog.Info("shutdown complete", "component", componentAgent)
}
