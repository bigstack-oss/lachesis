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
	// [metrics.UnknownTenant]{} (Sprint 2 default).
	Resolver metrics.TenantResolver
}

// App is the running agent. Construct one with [New], then call
// [App.Run]. Run blocks until ctx is cancelled.
type App struct {
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
// callers can use [App.Addr] before [App.Run] starts serving — useful
// for tests that request an ephemeral port (":0") and then need the
// resolved address.
func New(opts Options) (*App, error) {
	if opts.Reader == nil {
		return nil, errors.New("agent: Options.Reader is nil")
	}
	if opts.Log == nil {
		return nil, errors.New("agent: Options.Log is nil")
	}
	resolver := opts.Resolver
	if resolver == nil {
		resolver = metrics.UnknownTenant{}
	}

	st := state.New()
	sc := scraper.New(opts.Reader, st, opts.Config.Scrape.Interval)
	col := metrics.New(st, sc, resolver)

	reg := prometheus.NewRegistry()
	if err := reg.Register(col); err != nil {
		return nil, fmt.Errorf("agent: register collector: %w", err)
	}

	mgr := runtime.New(opts.ConfigPath, opts.Config, opts.Log)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.Handle("/debug/", mgr.DebugHandler())

	ln, err := net.Listen("tcp", opts.Config.HTTP.Listen)
	if err != nil {
		return nil, fmt.Errorf("agent: listen %s: %w", opts.Config.HTTP.Listen, err)
	}

	return &App{
		cfg:       opts.Config,
		state:     st,
		scraper:   sc,
		collector: col,
		runtime:   mgr,
		log:       opts.Log,
		listener:  ln,
		server:    &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second},
	}, nil
}

// Addr returns the address the HTTP server is bound to. Stable as
// soon as [New] returns; remains valid after Run starts and after it
// returns.
func (a *App) Addr() string {
	return a.listener.Addr().String()
}

// Run starts the scraper and HTTP server and blocks until ctx is
// cancelled. Graceful shutdown waits up to 5s for in-flight scrapes.
func (a *App) Run(ctx context.Context) error {
	a.runtime.InstallSIGHUP(ctx)

	go a.scraper.Run(ctx)

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
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := a.server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("agent: shutdown: %w", err)
		}
		// Drain srvErr so the Serve goroutine exits cleanly.
		<-srvErr
		return nil
	case err := <-srvErr:
		return err
	}
}
