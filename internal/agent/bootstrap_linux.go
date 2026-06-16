//go:build linux

package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	kafkago "github.com/segmentio/kafka-go"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/boot"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/config"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/gc"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/kafka"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/logging"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/metadata"
	cnetlink "github.com/bigstack-oss/cube-cos-network-telemetry/internal/netlink"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/reconcile"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/tcattach"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/unresolved"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/wal"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/zombie"
)

// Bootstrap runs the agent's startup sequence and returns a ready
// [Agent] plus an [io.Closer] that releases the BPF collection — call
// its Close after [Agent.Run] returns.
//
// The body is a flat, ordered list of named steps executed by
// [bootstrapper.run]; each step does one part of the sequence and
// advances the [boot.Sequencer] to the phase it establishes. Read the
// list here for the order; read the individual step methods for what
// each one guarantees.
//
// Phases (see [boot.Phase] and docs/DESIGN.md §9):
//
//  1. [boot.PhaseBPFLoaded]      — collection loaded + map-size validated
//  2. [boot.PhaseMetadataReady]  — Neutron cold-start populated the
//     LPM trie and mac_tenant_map
//  3. [boot.PhaseAttached]       — netlink subscriber wired; the TC
//     attach itself happens dynamically once [Agent.Run] starts it
//  4. [boot.PhaseStateRestored]  — WAL load complete; GlobalState
//     seeded so the first scrape computes deltas correctly
//
// Neutron is fetched BEFORE TC attach so the very first packet sees
// a populated trie; mis-classified flows become permanent entries
// in telemetry_map because dst_zone is part of FlowKey.
//
// ctx propagates through the Neutron HTTP calls — a SIGINT during
// cold-start aborts the boot.
//
// Bootstrap is Linux-only because the BPF lifecycle is. The
// cross-platform path used by unit tests constructs [Agent] directly
// via [New] with a synthetic [scraper.MapReader].
//
// Errors are wrapped with the step they failed in so the caller need
// not understand the internals to print a useful message.
func Bootstrap(ctx context.Context, args []string) (*Agent, io.Closer, error) {
	b := &bootstrapper{ctx: ctx, args: args, seq: boot.New()}
	return b.run([]step{
		{"prepare process", b.prepareProcess},
		{"hunt zombies", b.huntZombies},
		{"load BPF collection", b.loadBPF},
		{"build agent", b.buildAgent},
		{"cold-start Neutron", b.coldStart},
		{"subscribe netlink", b.subscribeNetlink},
		{"wire GC", b.wireGC},
		{"wire reconcile", b.wireReconcile},
		{"wire kafka", b.wireKafka},
		{"prepare WAL directory", b.prepareWALDir},
		{"restore WAL", b.restoreWAL},
	})
}

// step is one named entry in the [Bootstrap] sequence. name labels a
// failure; fn does the work and advances the [boot.Sequencer] when it
// establishes a phase.
type step struct {
	name string
	fn   func() error
}

// bootstrapper carries the state shared across the [Bootstrap] steps.
// Each step reads what earlier steps stored and writes what later
// steps need; the step list in [Bootstrap] is the authoritative
// order. It exists so every step can be a uniform func() error and
// Bootstrap can stay a flat list rather than a thread of locals.
type bootstrapper struct {
	ctx  context.Context
	args []string

	seq  *boot.Sequencer
	cfg  config.Config
	log  *logging.Handle
	coll *ebpf.Collection
	ag   *Agent

	zombiesCleaned int
}

// run executes steps in order, stopping at the first failure. On any
// error it releases the BPF collection — a no-op until [loadBPF]
// stores one, so an early failure is safe — and wraps the error with
// the failing step's name. On success it hands the live collection to
// the caller as an [io.Closer] to close after [Agent.Run] returns.
func (b *bootstrapper) run(steps []step) (*Agent, io.Closer, error) {
	for _, s := range steps {
		if err := s.fn(); err != nil {
			b.closeCollection()
			return nil, nil, fmt.Errorf("bootstrap: %s: %w", s.name, err)
		}
	}
	return b.ag, collectionCloser{b.coll}, nil
}

// prepareProcess parses configuration, initialises logging, and lifts
// the memlock rlimit so the kernel will accept the BPF maps. These are
// process-wide prerequisites, independent of the agent's data plane.
func (b *bootstrapper) prepareProcess() error {
	cfg, err := config.Load(config.Options{}, b.args)
	if err != nil {
		return err
	}
	log, err := logging.Init(cfg.Logging, os.Stderr)
	if err != nil {
		return fmt.Errorf("init logging: %w", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock rlimit: %w", err)
	}
	b.cfg, b.log = cfg, log
	return nil
}

// huntZombies removes TC filters orphaned by a previous crash, before
// any program is loaded (docs/DESIGN.md §9 step 1). Hunt errors are
// non-fatal — a partial cleanup still leaves a working agent — so the
// count is stashed for [buildAgent] to record once the metrics exist.
func (b *bootstrapper) huntZombies() error {
	cleaned, err := zombie.Hunt()
	switch {
	case err != nil:
		slog.Warn("hunt encountered errors; continuing with partial cleanup",
			"component", componentZombie, "cleaned", cleaned, "err", err)
	case cleaned > 0:
		slog.Info("removed orphan filters from a previous run",
			"component", componentZombie, "cleaned", cleaned)
	}
	b.zombiesCleaned = cleaned
	return nil
}

// loadBPF loads and validates the embedded BPF collection, then
// advances to [boot.PhaseBPFLoaded].
func (b *bootstrapper) loadBPF() error {
	coll, err := loadCollection()
	if err != nil {
		return err
	}
	b.coll = coll
	return b.seq.Advance(boot.PhaseBPFLoaded)
}

// buildAgent wires the map and stats readers over the loaded
// collection and constructs the [Agent], then records the
// orphan-filter count [huntZombies] found on the agent's zombie
// metrics.
func (b *bootstrapper) buildAgent() error {
	reader, err := readerFromCollection(b.coll)
	if err != nil {
		return err
	}
	stats, err := statsFromCollection(b.coll)
	if err != nil {
		return err
	}
	ag, err := New(Options{
		Config:     b.cfg,
		ConfigPath: config.FindConfigPath(config.Options{}, b.args),
		Reader:     reader,
		Log:        b.log,
		Stats:      stats,
		Sequencer:  b.seq,
	})
	if err != nil {
		return err
	}
	ag.mx.zombie.RecordCleaned(b.zombiesCleaned)
	b.ag = ag
	return nil
}

// coldStart fetches the Neutron snapshot and pushes it into the kernel
// maps, then advances to [boot.PhaseMetadataReady]. Runs before attach
// so the first packet classifies against a populated trie.
func (b *bootstrapper) coldStart() error {
	if err := coldStartNeutron(b.ctx, b.cfg.Neutron, b.ag, b.coll); err != nil {
		return err
	}
	return b.seq.Advance(boot.PhaseMetadataReady)
}

// subscribeNetlink builds the RTM_NEWLINK/DELLINK subscriber (when an
// attach allowlist is configured) and hands it to the agent, then
// advances to [boot.PhaseAttached]. The subscriber is only started
// later by [Agent.Run]; this step just wires it.
func (b *bootstrapper) subscribeNetlink() error {
	sub, err := buildNetlinkSubscriber(b.ag, b.cfg.BPF, b.coll)
	if err != nil {
		return err
	}
	if sub != nil {
		b.ag.netlinkSubscriber = sub
	}
	return b.seq.Advance(boot.PhaseAttached)
}

// wireGC constructs the two GC mechanisms over the kernel maps and
// hands them to the agent: the lingering-ghost sweeper (its own worker)
// and the pressure-relief evictor (injected into the scraper, which
// runs it inline after each drain). It establishes no boot phase — it
// only wires goroutine work that [Agent.Run] starts later, and the
// sweeper awaits [boot.PhaseStateRestored] itself. Both maps must be
// present (they are cold-start write / drain targets); a missing map is
// a build-time problem, never a runtime one.
func (b *bootstrapper) wireGC() error {
	macMap := b.coll.Maps[bpf.MapMacTenant]
	if macMap == nil {
		return fmt.Errorf("%s map missing from collection", bpf.MapMacTenant)
	}
	telMap := b.coll.Maps[bpf.MapTelemetry]
	if telMap == nil {
		return fmt.Errorf("%s map missing from collection", bpf.MapTelemetry)
	}
	b.ag.ghostSweeper = gc.New(gc.Options{
		Meta:        b.ag.meta,
		Evictor:     macTenantEvictor{m: macMap},
		FlowEvictor: telemetryMacFlowEvictor{m: telMap},
		MapGauge:    b.ag.mx.bpf,
		Seq:         b.ag.seq,
		Metrics:     b.ag.mx.gc,
	})
	telEvictor := telemetryFlowEvictor{m: telMap}
	reliever := gc.NewPressureReliever(gc.PressureOptions{
		Evictor:       telEvictor,
		MaxEntries:    bpf.MapTelemetryMaxEntries,
		Metrics:       b.ag.mx.gc,
		HighWatermark: b.cfg.GC.PressureHighWatermark,
		LowWatermark:  b.cfg.GC.PressureLowWatermark,
		MaxPerPass:    b.cfg.GC.PressureMaxPerPass,
	})
	b.ag.scraper.SetEvictor(reliever)
	// Make the gc.* config hot-reloadable: SIGHUP reloads swap the
	// reliever's tuning snapshot through this seam.
	b.ag.runtime.SetPressureTunable(reliever)

	// Divert unknown-MAC flows into the capped UnresolvedBuffer rather
	// than letting them grow GlobalState without bound; known flows (and
	// lingering ghosts) integrate directly. The buffer shares the kernel
	// telemetry_map evictor — it resets a flow's kernel counter when it
	// folds the flow to "unknown", so reappearance never double-counts.
	buf := unresolved.NewBuffer(unresolved.Options{
		State:   b.ag.state,
		Evictor: telEvictor,
		Metrics: b.ag.mx.unresolved,
	})
	b.ag.scraper.SetSink(unresolved.NewClassifier(b.ag.state, b.ag.meta, buf))
	return nil
}

// wireReconcile constructs the periodic Neutron reconciler over the
// kernel subnet_zone_trie and hands it to the agent as its own worker.
// It establishes no boot phase — the reconciler awaits
// [boot.PhaseStateRestored] itself before its first pass. Skipped when
// Neutron is disabled: there is no metadata to keep fresh, so the
// workers() row stays off. *neutron.Neutron satisfies the reconciler's
// MetadataSource seam structurally. A missing trie map is a build-time
// problem, never a runtime one.
func (b *bootstrapper) wireReconcile() error {
	if !b.cfg.Neutron.Enabled {
		return nil
	}
	trieMap := b.coll.Maps[bpf.MapSubnetZoneTrie]
	if trieMap == nil {
		return fmt.Errorf("%s map missing from collection", bpf.MapSubnetZoneTrie)
	}
	macMap := b.coll.Maps[bpf.MapMacTenant]
	if macMap == nil {
		return fmt.Errorf("%s map missing from collection", bpf.MapMacTenant)
	}
	b.ag.reconciler = reconcile.New(reconcile.Options{
		Source:    b.ag.neutron,
		Trie:      trieMap,
		Meta:      b.ag.meta,
		MacWriter: macTenantWriter{m: macMap},
		Interner:  b.ag.interner,
		Seq:       b.ag.seq,
		Metrics:   b.ag.mx.reconcile,
		BPFGauge:  b.ag.mx.bpf,
	})
	return nil
}

// wireKafka constructs the notification consumer and hands it to the
// agent as its own worker. It kicks the reconciler on each committed
// Neutron change, so the consumer only runs when a reconciler exists.
// Skipped when Kafka is disabled; when Kafka is enabled but Neutron is
// not (so no reconciler), it logs and skips rather than failing boot —
// the agent still runs on the (disabled) metadata path. Establishes no
// boot phase; the consumer awaits [boot.PhaseStateRestored] itself.
func (b *bootstrapper) wireKafka() error {
	if !b.cfg.Kafka.Enabled {
		return nil
	}
	if b.ag.reconciler == nil {
		slog.Warn("kafka enabled but neutron disabled; consumer not started (nothing to reconcile)",
			"component", componentKafka)
		return nil
	}
	reader := kafkago.NewReader(kafkago.ReaderConfig{
		Brokers: b.cfg.Kafka.Brokers,
		GroupID: b.cfg.Kafka.GroupID,
		Topic:   b.cfg.Kafka.Topic,
	})
	b.ag.kafkaConsumer = kafka.New(kafka.Options{
		Reader:  reader,
		Trigger: b.ag.reconciler,
		Seq:     b.ag.seq,
		Metrics: b.ag.mx.kafka,
		Topic:   b.cfg.Kafka.Topic,
	})
	return nil
}

// macTenantEvictor adapts a kernel mac_tenant_map [*ebpf.Map] to the
// [gc.MacEvictor] seam the ghost sweeper deletes through. A MAC already
// absent from the kernel (ErrKeyNotExist) is treated as success: the
// sweep's job is "ensure this MAC is gone", and a concurrent reload may
// have removed it first.
type macTenantEvictor struct{ m *ebpf.Map }

// Delete removes mac from the kernel mac_tenant_map.
func (e macTenantEvictor) Delete(mac uint64) error {
	if err := e.m.Delete(&mac); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}

// macTenantWriter adapts a kernel mac_tenant_map [*ebpf.Map] to the
// [reconcile.MacWriter] seam: the reconcile worker inserts a learned MAC's
// interned tenant id through it (upsert). Removals are not its concern —
// those go through the lingering-ghost path (userspace MarkDelete + GC).
type macTenantWriter struct{ m *ebpf.Map }

// Update upserts mac → tenantID in the kernel mac_tenant_map.
func (w macTenantWriter) Update(mac uint64, tenantID uint32) error {
	return w.m.Update(&mac, &tenantID, ebpf.UpdateAny)
}

// telemetryFlowEvictor adapts the kernel telemetry_map [*ebpf.Map] to
// the [gc.FlowEvictor] seam the pressure-relief pass deletes through. As
// with the MAC evictor, a key already gone (ErrKeyNotExist) is success.
type telemetryFlowEvictor struct{ m *ebpf.Map }

// Delete removes one flow key from the kernel telemetry_map. The map is
// a PERCPU_HASH; a single Delete drops the key across all CPUs.
func (e telemetryFlowEvictor) Delete(key bpf.FlowKey) error {
	if err := e.m.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}

// telemetryMacFlowEvictor adapts the kernel telemetry_map [*ebpf.Map] to
// the [gc.MacFlowEvictor] seam: it deletes the residual flow counters of
// a swept VM's MAC set so they are not re-drained as "unknown" after the
// MAC leaves mac_tenant_map (docs/DESIGN.md §3.3). telemetry_map is a
// PERCPU_HASH keyed by [bpf.FlowKey]; the VM-side MAC of each flow is
// [metadata.VMMAC]. Keys are collected during the single Iterate pass
// and deleted after it — deleting mid-iteration can skip or repeat
// entries.
type telemetryMacFlowEvictor struct{ m *ebpf.Map }

// DeleteFlowsForMACs scans telemetry_map once and deletes every flow
// whose VM MAC is in macs. Best-effort: per-key delete failures are
// counted out (not returned) except the first, so one bad key does not
// abort the rest. A key already gone (ErrKeyNotExist) is success.
func (e telemetryMacFlowEvictor) DeleteFlowsForMACs(macs map[uint64]struct{}) (int, error) {
	var key bpf.FlowKey
	var vals []bpf.FlowMetrics // PERCPU value; unused but required by Iterate
	it := e.m.Iterate()
	var toDelete []bpf.FlowKey
	for it.Next(&key, &vals) {
		if _, ok := macs[metadata.VMMAC(key)]; ok {
			toDelete = append(toDelete, key)
		}
	}
	if err := it.Err(); err != nil {
		return 0, fmt.Errorf("iterate telemetry_map: %w", err)
	}
	var firstErr error
	deleted := 0
	for i := range toDelete {
		if err := e.m.Delete(&toDelete[i]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			if firstErr == nil {
				firstErr = fmt.Errorf("delete telemetry_map flow: %w", err)
			}
			continue
		}
		deleted++
	}
	return deleted, firstErr
}

// prepareWALDir creates the WAL directory if missing and probes it
// for writability via [wal.EnsureDir]. Boot-fatal — unlike a restore
// failure, an unusable directory means every future flush would fail
// and the agent would run with zero crash durability while looking
// healthy. Runs before [bootstrapper.restoreWAL] so Load never
// mistakes a missing directory for a first boot.
func (b *bootstrapper) prepareWALDir() error {
	if !b.cfg.WAL.Enabled {
		return nil
	}
	return wal.EnsureDir(b.cfg.WAL.Path)
}

// restoreWAL seeds GlobalState from the on-disk snapshot and advances
// to [boot.PhaseStateRestored]. Most restore failures are handled
// inside restoreFromWAL (warn, quarantine the unreadable primary,
// start empty); the one fatal class — a snapshot written by a newer
// build — propagates here and aborts the boot (docs/DESIGN.md §3.2
// migration policy).
func (b *bootstrapper) restoreWAL() error {
	if err := restoreFromWAL(b.ag, b.cfg.WAL); err != nil {
		return err
	}
	return b.seq.Advance(boot.PhaseStateRestored)
}

// closeCollection releases the BPF collection if [loadBPF] stored one.
// Safe before loadBPF runs (coll is nil) and on any error path.
func (b *bootstrapper) closeCollection() {
	if b.coll != nil {
		b.coll.Close()
	}
}

// loadCollection compiles the embedded BPF spec into a kernel-loaded
// [*ebpf.Collection]. The caller owns Close on the returned value.
//
// Before loading, the spec is checked against [bpf.ValidateMapSizes]
// — a drift between the compiled `.o` and the Go-side `MaxEntries`
// constants is treated as boot-fatal so an operator who forgot to
// run `task generate` after a size bump sees an explicit error
// instead of silently shipping with stale capacity.
func loadCollection() (*ebpf.Collection, error) {
	spec, err := bpf.LoadTelemetry()
	if err != nil {
		return nil, fmt.Errorf("load BPF spec: %w", err)
	}
	if err := bpf.ValidateMapSizes(spec); err != nil {
		return nil, fmt.Errorf("BPF spec validation: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load BPF collection: %w", err)
	}
	return coll, nil
}

// readerFromCollection wires a [BPFMapReader] over [bpf.MapTelemetry]
// inside coll. Returns an error if the map is missing — that is
// always a build-time problem, never a runtime one.
func readerFromCollection(coll *ebpf.Collection) (*BPFMapReader, error) {
	m := coll.Maps[bpf.MapTelemetry]
	if m == nil {
		return nil, fmt.Errorf("%s not present in BPF collection", bpf.MapTelemetry)
	}
	return NewBPFMapReader(m)
}

// statsFromCollection wires a [bpf.StatsReader] over
// [bpf.MapTelemetryStats] inside coll. Returns an error if the map is
// missing — that is always a build-time problem, never a runtime one.
func statsFromCollection(coll *ebpf.Collection) (*bpf.StatsReader, error) {
	m := coll.Maps[bpf.MapTelemetryStats]
	if m == nil {
		return nil, fmt.Errorf("%s not present in BPF collection", bpf.MapTelemetryStats)
	}
	return bpf.NewStatsReader(m)
}

// buildNetlinkSubscriber constructs the RTM_NEWLINK/DELLINK
// subscriber when the BPFConfig allowlist is non-empty. Returns a
// nil Subscriber (no error) when both lists are empty — that means
// the operator opted out of dynamic discovery and attach is managed
// out-of-band (e.g. the integration tests attach their own filters).
func buildNetlinkSubscriber(ag *Agent, bpfCfg config.BPFConfig, coll *ebpf.Collection) (cnetlink.Subscriber, error) {
	if len(bpfCfg.AttachPrefixes) == 0 && len(bpfCfg.AttachInterfaces) == 0 {
		slog.Info("no allowlist configured; subscriber disabled",
			"component", componentNetlink)
		return nil, nil
	}
	ingress := coll.Programs[bpf.ProgramIngress]
	egress := coll.Programs[bpf.ProgramEgress]
	if ingress == nil || egress == nil {
		return nil, fmt.Errorf("netlink subscriber: %s / %s not present in BPF collection",
			bpf.ProgramIngress, bpf.ProgramEgress)
	}
	sub, err := cnetlink.New(cnetlink.Options{
		Attacher: tcattach.NewLinkAttacher(ingress, egress),
		Prefixes: bpfCfg.AttachPrefixes,
		Explicit: bpfCfg.AttachInterfaces,
		Registry: ag.mx.registry,
		Metrics:  ag.mx.netlink,
	})
	if err != nil {
		return nil, fmt.Errorf("netlink subscriber: %w", err)
	}
	return sub, nil
}

// collectionCloser adapts [*ebpf.Collection] to [io.Closer]. The
// underlying Close has no return value, so we swallow nothing.
type collectionCloser struct{ c *ebpf.Collection }

// Close releases the wrapped BPF collection. Always returns nil.
func (cc collectionCloser) Close() error {
	cc.c.Close()
	return nil
}
