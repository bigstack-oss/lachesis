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
// # File layout
//
// One [Agent] struct, method files by functionality: construction
// here, the HTTP surface in http.go, the Run/shutdown lifecycle in
// run.go, the worker table in worker.go, the WAL flush slice in
// walflush.go. Options and the subsystem metric bundle have their
// own files.
//
// # Cross-platform boundary
//
// The Agent and its method files depend only on the
// scraper.MapReader interface, so unit tests can run on macOS with a
// synthetic reader. The production BPF reader and the boot sequence
// live in `reader_linux.go` and `bootstrap_linux.go`.
package agent

import (
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/config"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/metadata"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/metrics"
	cnetlink "github.com/bigstack-oss/cube-cos-network-telemetry/internal/netlink"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/neutron"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/runtime"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/scraper"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/state"
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

	// neutronSnapshot, trieEntries, and anomalies retain the most
	// recent cold-start / full-resync outputs for the /debug pages.
	// Written by `coldStartNeutron` (and the future Kafka updater)
	// via atomic pointer swap — whole-value replace, never in-place
	// mutation — so the debug handlers read lock-free while a resync
	// runs. nil until the first successful sync (Neutron disabled or
	// not yet synced); the handlers render the empty state.
	neutronSnapshot atomic.Pointer[neutron.Snapshot]
	trieEntries     atomic.Pointer[[]neutron.TrieEntry]
	anomalies       atomic.Pointer[neutron.Anomalies]

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
// inputs, bundle the subsystem metrics, wire the data plane (state +
// scraper + collector — the scraper's reader is wrapped in
// [telemetryFillReader], which feeds the bundle's telemetry_map fill
// gauge), then mount the HTTP surface and open the listener. The
// bundle and HTTP steps live in [newSubsystemMetrics] and
// [Agent.openHTTP]; New itself only composes.
func New(opts Options) (*Agent, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}

	st := state.New()
	meta := metadata.New()

	a := &Agent{
		cfg:      opts.Config,
		state:    st,
		meta:     meta,
		interner: metadata.NewTenantInterner(),
	}
	a.mx = newSubsystemMetrics(a.lastNeutronSyncTime)
	a.scraper = scraper.New(
		telemetryFillReader{inner: opts.Reader, mx: a.mx.bpf},
		st, opts.Config.Scrape.Interval)
	a.collector = metrics.New(st, a.scraper, opts.resolverOrDefault(meta))

	if err := a.openHTTP(opts); err != nil {
		return nil, err
	}
	return a, nil
}

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

// SeedState seeds the agent's [state.GlobalState] from records,
// intended to run between [New] and [Run] (for example, after a
// WAL restore on boot). Takes the state's write lock; safe to call
// before any other goroutine touches the agent.
func (a *Agent) SeedState(records []state.Record) {
	a.state.Restore(records)
}
