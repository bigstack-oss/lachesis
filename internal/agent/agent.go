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
// The production BPF reader and the boot sequence live in
// `reader_linux.go` and `bootstrap_linux.go` respectively.
package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/config"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/metadata"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/metrics"
	cnetlink "github.com/bigstack-oss/cube-cos-network-telemetry/internal/netlink"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/runtime"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/scraper"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/state"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/wal"
)

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
	listener  net.Listener
	server    *http.Server

	// mx bundles the per-subsystem Prometheus instruments and the
	// netlink Interface Registry. Grouping them makes subsystemMetrics
	// the single place touched when a subsystem is added and gives
	// [Agent.buildRegistry] one ordered registration list.
	mx subsystemMetrics

	// netlinkSubscriber listens for RTM_NEWLINK/DELLINK and attaches
	// TC programs to discovered taps. Set by Linux Bootstrap when
	// AttachPrefixes / AttachInterfaces are configured; nil on
	// darwin and in unit tests that don't need it.
	netlinkSubscriber cnetlink.Subscriber

	// lastNeutronSync is the unix-nanos timestamp of the most
	// recent successful Neutron cold-start or full-resync. Read by
	// the `cubecos_neutron_sync_age_seconds` gauge on every
	// Prometheus scrape; updated by `coldStartNeutron` and the
	// future Kafka updater. Zero means never-synced — the gauge
	// reports -1 in that case so dashboards can spot the condition
	// with `< 0`.
	lastNeutronSync atomic.Int64

	// meta is the userspace MAC → TenantMeta store. Constructed
	// empty in [New]; populated by Bootstrap from Neutron and, in
	// a future change, from Kafka events. The metrics Collector's
	// Resolver reads it on every emission.
	meta *metadata.ShardedMetadataMap
	// interner assigns the u32 tenant_id values the kernel maps
	// key on. Lives on Agent because both the cold-start writer
	// and the incremental Kafka updater share it.
	interner *metadata.TenantInterner

	// walRecBuf is the reused SnapshotForWAL destination so a
	// steady-state flush does not allocate a fresh records slice.
	// Owned solely by the WAL flush goroutine; no lock needed.
	walRecBuf []state.Record
}

// New constructs the agent. The HTTP listener is opened immediately so
// callers can use [Agent.Addr] before [Agent.Run] starts serving — useful
// for tests that request an ephemeral port (":0") and then need the
// resolved address.
//
// New reads top-to-bottom as the agent's composition order: validate
// inputs, wire the data plane (state + scraper + collector), bundle
// the subsystem metrics, then mount the HTTP surface and open the
// listener. The latter two live in [newSubsystemMetrics] and
// [Agent.openHTTP]; New itself only composes.
func New(opts Options) (*Agent, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}

	st := state.New()
	meta := metadata.New()
	sc := scraper.New(opts.Reader, st, opts.Config.Scrape.Interval)

	a := &Agent{
		cfg:       opts.Config,
		state:     st,
		scraper:   sc,
		collector: metrics.New(st, sc, opts.resolverOrDefault(meta)),
		meta:      meta,
		interner:  metadata.NewTenantInterner(),
	}
	a.mx = newSubsystemMetrics(a.lastNeutronSyncTime)

	if err := a.openHTTP(opts); err != nil {
		return nil, err
	}
	return a, nil
}

// openHTTP wires the agent's HTTP surface: the Prometheus registry,
// the runtime manager's /debug routes, and the server bound to the
// configured listen address. Split from [New] so construction reads
// as data plane → metrics → HTTP, with the HTTP details here.
func (a *Agent) openHTTP(opts Options) error {
	reg, err := a.buildRegistry()
	if err != nil {
		return err
	}

	mgr := runtime.New(opts.ConfigPath, opts.Config, opts.Log)
	handler := buildHTTPHandler(reg, mgr)

	ln, err := net.Listen("tcp", opts.Config.HTTP.Listen)
	if err != nil {
		return fmt.Errorf("agent: listen %s: %w", opts.Config.HTTP.Listen, err)
	}

	a.runtime = mgr
	a.listener = ln
	a.server = &http.Server{Handler: handler, ReadHeaderTimeout: httpReadHeaderTimeout}
	return nil
}

// WALMetrics returns the WAL instrument bundle the agent registered
// with its prometheus.Registry. The boot path reads a.mx.wal
// directly; this accessor exists for the package's external tests,
// which record load-fallback observations on the same Metrics that
// the periodic flush contributes timings to.
func (a *Agent) WALMetrics() *wal.Metrics { return a.mx.wal }

// markNeutronSync records `t` as the most recent successful Neutron
// sync. Read by the `cubecos_neutron_sync_age_seconds` gauge.
func (a *Agent) markNeutronSync(t time.Time) {
	a.lastNeutronSync.Store(t.UnixNano())
}

// lastNeutronSyncTime returns the timestamp marked by the most
// recent [Agent.markNeutronSync] call, or the zero time.Time if
// none. Used by the neutron metrics' sync_age gauge provider.
func (a *Agent) lastNeutronSyncTime() time.Time {
	ns := a.lastNeutronSync.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// buildRegistry creates a fresh Prometheus registry and binds the
// agent's custom Collector plus every subsystem instrument bundle to
// it, so /metrics is the single endpoint operators scrape — billing
// and subsystem health on one wire.
func (a *Agent) buildRegistry() (*prometheus.Registry, error) {
	reg := prometheus.NewRegistry()
	if err := reg.Register(a.collector); err != nil {
		return nil, fmt.Errorf("agent: register collector: %w", err)
	}
	for _, r := range a.mx.registrations() {
		for _, c := range r.collectors {
			if err := reg.Register(c); err != nil {
				return nil, fmt.Errorf("agent: register %s metric: %w", r.label, err)
			}
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

// Addr returns the address the HTTP server is bound to. Stable as
// soon as [New] returns; remains valid after Run starts and after it
// returns.
func (a *Agent) Addr() string {
	return a.listener.Addr().String()
}

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
// run its final flush. The same drain runs if the HTTP server itself
// fails, so a server crash never leaks the worker goroutines or skips
// the final WAL flush.
//
// TC programs are not detached on shutdown — the qdisc and filter
// outlive the process. The next agent start replaces them via
// netlink's idempotent QdiscReplace / FilterReplace. A clean detach
// + a recovery path for filters orphaned by crashes are planned.
func (a *Agent) Run(ctx context.Context) error {
	a.runtime.InstallSIGHUP(ctx)

	// runCtx derives from the caller's ctx so that an HTTP server
	// failure can tear down the scraper, WAL, and netlink goroutines
	// the same way a caller cancellation does. Without it, the srvErr
	// exit path below would return while those goroutines run on against
	// a live context — leaking them and skipping the WAL final flush.
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	scraperDone := make(chan struct{})
	go func() {
		a.scraper.Run(runCtx)
		close(scraperDone)
	}()

	walDone := make(chan struct{})
	if a.cfg.WAL.Enabled {
		go a.walFlushLoop(runCtx, walDone)
	} else {
		close(walDone)
	}

	netlinkDone := make(chan struct{})
	if a.netlinkSubscriber != nil {
		go func() {
			defer close(netlinkDone)
			if err := a.netlinkSubscriber.Run(runCtx); err != nil {
				slog.Error("subscriber exited", "component", componentNetlink, "err", err)
			}
		}()
	} else {
		close(netlinkDone)
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
		return a.shutdown(srvErr, scraperDone, walDone, netlinkDone)
	case err := <-srvErr:
		// The HTTP server failed on its own (the listener died, say).
		// srvErr is already drained, so we can't route through the full
		// shutdown (which reads it). Cancel the workers and drain them
		// directly — including the WAL final flush — so a server crash
		// doesn't leak goroutines or lose the last deltas.
		slog.Info("shutdown initiated by server error", "component", componentAgent)
		cancel()
		a.drainWorkers(scraperDone, walDone, netlinkDone)
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
	a.mx.wal.ObserveCopy(time.Since(copyStart))
	return wal.Save(a.cfg.WAL.Path, "", a.walRecBuf, a.mx.wal)
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
func (a *Agent) shutdown(srvErr <-chan error, scraperDone, walDone, netlinkDone <-chan struct{}) error {
	slog.Info("shutdown initiated", "component", componentAgent)
	defer a.drainWorkers(scraperDone, walDone, netlinkDone)

	httpCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := a.server.Shutdown(httpCtx); err != nil {
		return fmt.Errorf("agent: http shutdown: %w", err)
	}
	<-srvErr
	slog.Info("http server stopped", "component", componentAgent)
	return nil
}

// drainWorkers waits for the netlink, scraper, and WAL goroutines to
// exit, in that order. Scraper drains before WAL so the latest deltas
// land in state before the WAL final flush captures them. Used by both
// shutdown paths (caller-ctx cancel and HTTP server failure), so the
// goroutine teardown and final flush are identical regardless of why
// the agent is stopping. The caller must have cancelled the workers'
// context first.
func (a *Agent) drainWorkers(scraperDone, walDone, netlinkDone <-chan struct{}) {
	a.await("netlink subscriber", netlinkDone)
	a.await("scraper", scraperDone)
	a.await("wal", walDone)
	slog.Info("shutdown complete", "component", componentAgent)
}

// await blocks until done is closed or shutdownTimeout elapses,
// logging which goroutine stopped or timed out. drainWorkers calls it
// once per drained goroutine (netlink subscriber, scraper, WAL flush)
// so a slow HTTP drain never leaves a goroutine holding a BPF map read
// while the caller closes the collection. A WAL-flush timeout is the
// design's stated worst case: the last ≤flush_interval of in-memory
// deltas are lost.
func (a *Agent) await(name string, done <-chan struct{}) {
	select {
	case <-done:
		slog.Info(name+" stopped", "component", componentAgent)
	case <-time.After(shutdownTimeout):
		slog.Warn(name+" did not exit within shutdown budget",
			"component", componentAgent,
			"budget", shutdownTimeout)
	}
}
