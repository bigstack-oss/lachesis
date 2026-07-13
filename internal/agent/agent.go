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
	"fmt"
	"net"
	"net/http"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/boot"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/config"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/gc"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/kafka"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/metadata"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/metrics"
	cnetlink "github.com/bigstack-oss/cube-cos-network-telemetry/internal/netlink"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/neutron"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/reconcile"
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

	// seq is the boot phase sequencer. Workers that must not run before
	// a boot phase completes (the ghost sweeper awaits PhaseStateRestored)
	// block on it. Bootstrap advances it through the startup phases;
	// unit-test agents constructed via New get a fresh sequencer that
	// stays at PhaseInit.
	seq *boot.Sequencer

	// ghostSweeper drops metadata entries whose 60s Lingering-Ghost
	// grace window has elapsed, deleting kernel-first then userspace.
	// Set by Linux Bootstrap (it needs the kernel mac_tenant_map
	// handle); nil on darwin and in unit tests, which disables its
	// workers() row.
	ghostSweeper *gc.GhostSweeper

	// neutron carries the whole Neutron subsystem: the resolved
	// credentials, the API client, its metrics bundle, and the
	// retained outputs of the most recent successful sync (snapshot,
	// trie rows, anomalies, sync time) that the /debug pages read.
	// `coldStartNeutron` (and the future Kafka updater) drive it via
	// Sync/Commit.
	neutron *neutron.Neutron

	// reconciler periodically re-syncs Neutron and applies the trie
	// delta to the kernel, bounding metadata staleness to one interval
	// if Kafka is unavailable. Set by Linux Bootstrap when Neutron is
	// enabled (it needs the kernel subnet_zone_trie handle); nil on
	// darwin, in unit tests, and when Neutron is disabled — which
	// disables its workers() row.
	reconciler *reconcile.Reconciler

	// kafkaConsumer reads OpenStack notifications and kicks the
	// reconciler on each committed Neutron change, so metadata refreshes
	// in seconds rather than at the reconcile interval. Set by Linux
	// Bootstrap when Kafka is enabled and a reconciler exists; nil
	// otherwise — which disables its workers() row.
	kafkaConsumer *kafka.Consumer

	// meta is the userspace MAC → TenantMeta store. Constructed
	// empty in [New]; populated by Bootstrap from Neutron and, in
	// a future change, from Kafka events. The metrics Collector's
	// Resolver reads it on every emission.
	meta *metadata.ShardedMetadataMap
	// interner assigns the u32 tenant_id values the kernel maps
	// key on. Lives on Agent because both the cold-start writer
	// and the incremental Kafka updater share it.
	interner *metadata.TenantInterner

	// walRecBuf and walSettledBuf are the reused SnapshotForWAL
	// destinations so a steady-state flush does not allocate fresh
	// slices. Owned solely by the WAL flush goroutine; no lock needed.
	walRecBuf     []state.Record
	walSettledBuf []state.SettledRecord

	// buildID stamps the WAL envelope's agent_build field. Resolved
	// once at construction from the binary's embedded VCS revision;
	// see agentBuildID in walflush.go.
	buildID string
}

// New constructs the agent. The HTTP listener is opened immediately so
// callers can use [Agent.Addr] before [Agent.Run] starts serving — useful
// for tests that request an ephemeral port (":0") and then need the
// resolved address.
//
// New reads top-to-bottom as the agent's composition order: validate
// inputs, construct the Neutron subsystem (credentials resolve here,
// so a malformed openrc fails construction instead of the cold-start
// retry loop), bundle the subsystem metrics, wire the data plane
// (state + scraper + collector — the scraper's reader is wrapped in
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
	n, err := neutron.New(opts.Config.Neutron)
	if err != nil {
		return nil, fmt.Errorf("agent: neutron credentials: %w", err)
	}

	a := &Agent{
		cfg:      opts.Config,
		state:    st,
		meta:     meta,
		neutron:  n,
		interner: metadata.NewTenantInterner(),
		seq:      opts.sequencerOrDefault(),
		buildID:  agentBuildID(),
	}
	a.mx = newSubsystemMetrics(n.Metrics(), opts.Config.Kafka.Topic)
	a.scraper = scraper.New(
		telemetryFillReader{inner: opts.Reader, stats: opts.Stats, mx: a.mx.bpf},
		st, opts.Config.Scrape.Interval)
	a.collector = metrics.New(st, a.scraper, opts.resolverOrDefault(meta))

	if err := a.openHTTP(opts); err != nil {
		return nil, err
	}
	return a, nil
}

// SeedState seeds the agent's [state.GlobalState] from records,
// intended to run between [New] and [Run] (for example, after a
// WAL restore on boot). Takes the state's write lock; safe to call
// before any other goroutine touches the agent.
func (a *Agent) SeedState(records []state.Record) {
	a.state.Restore(records)
}

// SeedSettled seeds the agent's settled-bytes accumulator, the
// companion of [Agent.SeedState] for the WAL's settled section.
func (a *Agent) SeedSettled(records []state.SettledRecord) {
	a.state.RestoreSettled(records)
}
