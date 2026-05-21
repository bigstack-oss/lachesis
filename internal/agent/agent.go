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
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/config"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/logging"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/metadata"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/metrics"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/neutron"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/runtime"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/scraper"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/state"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/wal"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/web"
)

// Options bundles the inputs to [New]. ConfigPath is the YAML file
// the [runtime.Manager] will re-read on SIGHUP; empty disables
// SIGHUP reload while keeping /debug functional.
type Options struct {
	Config     config.Config
	ConfigPath string
	Reader     scraper.MapReader
	Log        *logging.Handle
	// Resolver maps FlowKey → tenant_id label. nil means a
	// [metadata.NewResolver] wrapping the Agent's own
	// [metadata.ShardedMetadataMap], which starts empty and is
	// populated by Bootstrap (Linux) from Neutron. Tests can
	// inject a mock resolver to pin label outputs without
	// pre-populating the metadata map.
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
// otherwise a [metadata.NewResolver] wrapping meta. Centralising
// the default keeps [New] free of branches that aren't about
// wiring. An empty meta yields the same "tenant_id=unknown" labels
// the old [metrics.UnknownTenant] stub produced, so pre-Bootstrap
// scrapes (and the no-Neutron loadtest harness) behave
// indistinguishably from before this change.
func (o Options) resolverOrDefault(meta *metadata.ShardedMetadataMap) metrics.TenantResolver {
	if o.Resolver != nil {
		return o.Resolver
	}
	return metadata.NewResolver(meta)
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

	walMetrics     *wal.Metrics
	neutronMetrics *neutron.Metrics
	bpfMapMetrics  *bpf.MapMetrics

	// lastNeutronSync is the unix-nanos timestamp of the most
	// recent successful Neutron cold-start or full-resync. Read by
	// the `cubecos_neutron_sync_age_seconds` gauge on every
	// Prometheus scrape; updated by `coldStartNeutron` and the
	// future Kafka updater. Zero means never-synced — the gauge
	// reports -1 in that case so dashboards can spot the condition
	// with `< 0`.
	lastNeutronSync atomic.Int64

	// meta is the userspace MAC → TenantMeta store. Constructed
	// empty in [New]; populated by Bootstrap from Neutron and
	// from Kafka events in later sprints. The metrics Collector's
	// Resolver reads it on every emission.
	meta *metadata.ShardedMetadataMap
	// interner assigns the u32 tenant_id values the kernel maps
	// key on. Lives on Agent because both the cold-start writer
	// and the incremental Kafka updater share it.
	interner *metadata.TenantInterner

	// neutronSnapshot is the userspace copy of the most-recently
	// consumed Neutron resource bundle. Cold-start populates it
	// after the kernel maps are written; the future Kafka updater
	// swaps it in atomically. Read by the /debug/topology HTML
	// page; nil means neutron is disabled or has not yet synced.
	neutronSnapshot atomic.Pointer[neutron.Snapshot]
	// trieEntries is the deduped row set the kernel
	// `subnet_zone_trie` was last written with. Read by the
	// /debug/zones HTML page so operators can see the
	// (tenant, prefix, zone) classification the kernel will apply.
	// Same lifecycle as [neutronSnapshot].
	trieEntries atomic.Pointer[[]neutron.TrieEntry]
	// anomalies bundles every health issue [neutron.DetectAnomalies]
	// derived from the last cold-start: static-route cycles,
	// ambiguities, dangling extraroutes, zero-trie tenants, and
	// duplicate router MACs. Read by the /debug landing page.
	// Same lifecycle as [neutronSnapshot]; nil before first sync.
	anomalies atomic.Pointer[neutron.Anomalies]

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

// NeutronMetrics returns the Neutron-subsystem instrument bundle.
// The cold-start path uses it to record API errors and
// unknown-owner admissions; sync_age reads the agent's
// [Agent.lastNeutronSync] timestamp at scrape time.
func (a *Agent) NeutronMetrics() *neutron.Metrics { return a.neutronMetrics }

// BPFMapMetrics returns the BPF-map instrument bundle. Cold-start
// and any subsequent incremental update set the current-entries
// gauge after each successful kernel push.
func (a *Agent) BPFMapMetrics() *bpf.MapMetrics { return a.bpfMapMetrics }

// MarkNeutronSync records `t` as the most recent successful Neutron
// sync. Read by the `cubecos_neutron_sync_age_seconds` gauge.
func (a *Agent) MarkNeutronSync(t time.Time) {
	a.lastNeutronSync.Store(t.UnixNano())
}

// lastNeutronSyncTime returns the timestamp marked by the most
// recent [MarkNeutronSync] call, or the zero time.Time if none.
// Used by the neutron metrics' sync_age gauge provider.
func (a *Agent) lastNeutronSyncTime() time.Time {
	ns := a.lastNeutronSync.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// Metadata returns the userspace MAC → TenantMeta store. Bootstrap
// populates it after Neutron cold-start; Kafka events update it
// incrementally. The metrics Collector reads it through the
// wired-in [metadata.Resolver].
func (a *Agent) Metadata() *metadata.ShardedMetadataMap { return a.meta }

// Interner returns the ProjectID → u32 mapping the kernel maps key
// on. Shared between cold-start map writes and any future
// incremental writes so the kernel sees a stable assignment within
// one agent lifetime. The mapping is rebuilt fresh on every agent
// boot; see the doc on [metadata.TenantInterner] for why that is
// correctness-safe.
func (a *Agent) Interner() *metadata.TenantInterner { return a.interner }

// SetNeutronSnapshot atomically replaces the snapshot the
// /debug/topology page renders from. Cold-start calls this once the
// kernel maps have been written; the future Kafka updater calls it
// on each successful incremental sync.
func (a *Agent) SetNeutronSnapshot(s *neutron.Snapshot) {
	a.neutronSnapshot.Store(s)
}

// NeutronSnapshot returns the snapshot last set by
// [SetNeutronSnapshot], or nil if neutron is disabled or has not
// yet synced.
func (a *Agent) NeutronSnapshot() *neutron.Snapshot {
	return a.neutronSnapshot.Load()
}

// SetTrieEntries atomically replaces the trie row set the
// /debug/zones page renders from. Same lifecycle as
// [SetNeutronSnapshot].
func (a *Agent) SetTrieEntries(entries []neutron.TrieEntry) {
	a.trieEntries.Store(&entries)
}

// TrieEntries returns the trie row set last set by
// [SetTrieEntries], or nil if none has been written yet.
func (a *Agent) TrieEntries() []neutron.TrieEntry {
	p := a.trieEntries.Load()
	if p == nil {
		return nil
	}
	return *p
}

// SetAnomalies atomically replaces the anomaly bundle the /debug
// landing page renders from. Cold-start calls this after the
// kernel maps have been written; the future Kafka updater calls it
// on each successful incremental sync.
func (a *Agent) SetAnomalies(an *neutron.Anomalies) {
	a.anomalies.Store(an)
}

// Anomalies returns the anomaly bundle last set by [SetAnomalies],
// or nil if neutron is disabled or has not yet synced.
func (a *Agent) Anomalies() *neutron.Anomalies {
	return a.anomalies.Load()
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
	meta := metadata.New()
	interner := metadata.NewTenantInterner()
	sc := scraper.New(opts.Reader, st, opts.Config.Scrape.Interval)
	col := metrics.New(st, sc, opts.resolverOrDefault(meta))

	walMx := wal.NewMetrics()
	bpfMx := bpf.NewMapMetrics()
	bpfMx.SetMax(bpf.MapMacTenant, float64(bpf.MapMacTenantMaxEntries))
	bpfMx.SetMax(bpf.MapSubnetZoneTrie, float64(bpf.MapSubnetZoneTrieMaxEntries))
	// Both current_entries seed at 0; cold-start will overwrite after
	// the first successful kernel push.
	bpfMx.SetCurrent(bpf.MapMacTenant, 0)
	bpfMx.SetCurrent(bpf.MapSubnetZoneTrie, 0)

	a := &Agent{
		cfg:           opts.Config,
		state:         st,
		scraper:       sc,
		collector:     col,
		log:           opts.Log,
		walMetrics:    walMx,
		bpfMapMetrics: bpfMx,
		meta:          meta,
		interner:      interner,
	}
	a.neutronMetrics = neutron.NewMetrics(a.lastNeutronSyncTime)

	reg, err := buildRegistry(col, walMx, a.neutronMetrics, bpfMx)
	if err != nil {
		return nil, err
	}

	mgr := runtime.New(opts.ConfigPath, opts.Config, opts.Log)
	handler := a.buildHTTPHandler(reg, mgr)

	ln, err := net.Listen("tcp", opts.Config.HTTP.Listen)
	if err != nil {
		return nil, fmt.Errorf("agent: listen %s: %w", opts.Config.HTTP.Listen, err)
	}

	a.runtime = mgr
	a.listener = ln
	a.server = &http.Server{Handler: handler, ReadHeaderTimeout: httpReadHeaderTimeout}
	return a, nil
}

// buildRegistry creates a fresh Prometheus registry and binds the
// agent's custom Collector plus the WAL instruments to it. The two
// register in tandem so /metrics is the single endpoint operators
// scrape — billing and WAL health on one wire.
func buildRegistry(
	col *metrics.Collector,
	walMx *wal.Metrics,
	neutronMx *neutron.Metrics,
	bpfMx *bpf.MapMetrics,
) (*prometheus.Registry, error) {
	reg := prometheus.NewRegistry()
	if err := reg.Register(col); err != nil {
		return nil, fmt.Errorf("agent: register collector: %w", err)
	}
	for label, bundle := range map[string][]prometheus.Collector{
		"wal":     walMx.Collectors(),
		"neutron": neutronMx.Collectors(),
		"bpf":     bpfMx.Collectors(),
	} {
		for _, c := range bundle {
			if err := reg.Register(c); err != nil {
				return nil, fmt.Errorf("agent: register %s metric: %w", label, err)
			}
		}
	}
	return reg, nil
}

// buildHTTPHandler returns the mux the HTTP server will serve.
// Centralising the route table here is the seam future subsystems
// (e.g. a /healthz, a /reload, a /pprof under debug) attach to —
// rather than each one widening [New]. The Agent receiver gives
// /debug/* handlers access to userspace state (snapshot, trie
// entries) without threading parameters through the call chain.
func (a *Agent) buildHTTPHandler(reg *prometheus.Registry, mgr *runtime.Manager) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.Handle("/debug/", mgr.DebugHandler())
	mux.HandleFunc("/debug/zones", a.handleDebugZones)
	mux.HandleFunc("/debug/topology", a.handleDebugTopology)
	// Per-tenant focused topology view. The {tenant} pattern is a
	// Go 1.22+ ServeMux capture; r.PathValue("tenant") retrieves it.
	mux.HandleFunc("/debug/topology/{tenant}", a.handleDebugTopologyTenant)
	// /debug/static/<file> → vendored browser assets. StripPrefix maps
	// the URL path to the embed.FS root (which carries `static/...`
	// directly). FileServer adds Content-Type from the extension.
	mux.Handle("/debug/static/", http.StripPrefix("/debug/", http.FileServer(http.FS(web.Static))))
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

// Component values for the "component" slog attribute. Logs are
// tagged by the **subsystem they're about**, not by the package or
// file that emits them — so the WAL flush goroutine in agent.go
// tags componentWAL, the Neutron cold-start orchestrator in
// coldstart_linux.go tags componentNeutron, and so on. An operator
// filtering `component=<subsystem>` sees the full story of that
// subsystem regardless of code location; grep-by-message-text is
// the recommended way to find the emission site in code.
const (
	componentAgent   = "agent"
	componentWAL     = "wal"
	componentNeutron = "neutron"
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
