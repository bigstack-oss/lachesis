//go:build linux

package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	kafkago "github.com/segmentio/kafka-go"

	"github.com/bigstack-oss/lachesis/internal/boot"
	"github.com/bigstack-oss/lachesis/internal/bpf"
	"github.com/bigstack-oss/lachesis/internal/config"
	"github.com/bigstack-oss/lachesis/internal/gc"
	"github.com/bigstack-oss/lachesis/internal/kafka"
	"github.com/bigstack-oss/lachesis/internal/logging"
	"github.com/bigstack-oss/lachesis/internal/metadata"
	cnetlink "github.com/bigstack-oss/lachesis/internal/netlink"
	"github.com/bigstack-oss/lachesis/internal/reconcile"
	"github.com/bigstack-oss/lachesis/internal/tcattach"
	"github.com/bigstack-oss/lachesis/internal/unresolved"
	"github.com/bigstack-oss/lachesis/internal/wal"
	"github.com/bigstack-oss/lachesis/internal/zombie"
)

// Bootstrap runs the agent's startup sequence and returns a ready
// [Agent] plus an [io.Closer] releasing the BPF collection. The body is
// a flat ordered list of named steps, each advancing the
// [boot.Sequencer] to the phase it establishes — read it for the order.
//
// The order is load-bearing: Neutron is fetched BEFORE TC attach, so the
// first packet sees a populated trie. A flow classified against an empty
// trie is miskeyed permanently, because dst_zone is part of FlowKey.
//
// docs/architecture/boot-and-recovery.md#boot-sequence
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
	mapsPinned     bool
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
// any program is loaded (boot step 1). Hunt errors are non-fatal — a
// partial cleanup still leaves a working agent — so the count is
// stashed for [buildAgent] to record once the metrics exist.
//
// Boot sequence: docs/architecture/boot-and-recovery.md#boot-sequence
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

// loadBPF loads and validates the embedded BPF collection — pinning
// the counter-bearing maps for zero-loss agent-crash recovery — then
// advances to [boot.PhaseBPFLoaded]. It records whether pinning
// succeeded so [buildAgent] can surface the recovery mode on the BPF
// metrics once they exist.
func (b *bootstrapper) loadBPF() error {
	coll, pinned, err := loadCollection(b.cfg.BPF)
	if err != nil {
		return err
	}
	b.coll = coll
	b.mapsPinned = pinned
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
	ag.mx.bpf.SetMapsPinned(b.mapsPinned)
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

// wireGC hands the agent its ghost sweeper (own worker) and
// pressure-relief evictor (run inline by the scraper). Establishes no
// boot phase: the sweeper awaits [boot.PhaseStateRestored] itself.
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
		Settler:     b.ag.state,
		Routers:     b.ag.routers,
		Tunables:    b.ag.tun,
		MapGauge:    b.ag.mx.bpf,
		Seq:         b.ag.seq,
		Metrics:     b.ag.mx.gc,
	})
	telEvictor := telemetryFlowEvictor{m: telMap}
	reliever := gc.NewPressureReliever(gc.PressureOptions{
		Evictor:    telEvictor,
		MaxEntries: bpf.MapTelemetryMaxEntries,
		Metrics:    b.ag.mx.gc,
		Tunables:   b.ag.tun,
	})
	b.ag.scraper.SetEvictor(reliever)
	// Make the gc.* config hot-reloadable: SIGHUP reloads swap the
	// reliever's tuning snapshot through this seam.

	// Divert unknown-MAC flows into the capped UnresolvedBuffer rather
	// than letting them grow GlobalState without bound; known flows (and
	// lingering ghosts) integrate directly. The buffer shares the kernel
	// telemetry_map evictor — it resets a flow's kernel counter when it
	// folds the flow to "unknown", so reappearance never double-counts.
	buf := unresolved.NewBuffer(unresolved.Options{
		Tunables: b.ag.tun,
		State:    b.ag.state,
		Evictor:  telEvictor,
		Metrics:  b.ag.mx.unresolved,
	})
	b.ag.scraper.SetSink(unresolved.NewClassifier(b.ag.state, b.ag.meta, buf))
	return nil
}

// wireReconcile hands the agent the periodic Neutron reconciler as its
// own worker, skipped when Neutron is disabled. Establishes no boot
// phase: the reconciler awaits [boot.PhaseStateRestored] itself.
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
	amphoraMap := b.coll.Maps[bpf.MapAmphoraBaseIP]
	if amphoraMap == nil {
		return fmt.Errorf("%s map missing from collection", bpf.MapAmphoraBaseIP)
	}
	b.ag.reconciler = reconcile.New(reconcile.Options{
		Source:       b.ag.neutron,
		Trie:         trieMap,
		AmphoraIPs:   amphoraMap,
		Meta:         b.ag.meta,
		MacWriter:    macTenantWriter{m: macMap},
		Routers:      b.ag.routers,
		Settler:      b.ag.state,
		Tunables:     b.ag.tun,
		Interner:     b.ag.interner,
		Seq:          b.ag.seq,
		Metrics:      b.ag.mx.reconcile,
		BPFGauge:     b.ag.mx.bpf,
		AmphoraGauge: b.ag.mx.neutron,
	})
	// A SIGHUP reload kicks the reconciler so a retuned reconcile
	// interval (or any operator edit) is picked up within seconds rather
	// than after the running ticker's current period elapses.
	if b.ag.runtime != nil {
		b.ag.runtime.SetOnReload(b.ag.reconciler.Kick)
	}
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
	// Per-agent group so every agent gets every notification (the stream
	// is a fanout, not a work queue). Prefer the hostname (stable across
	// restarts, readable on the broker); if it's unavailable fall back to
	// a random token — never to the shared group, which would starve the
	// peers of reconcile kicks.
	host, err := os.Hostname()
	if err != nil || host == "" {
		slog.Warn("hostname unavailable; using a random kafka consumer-group suffix to keep it per-agent",
			"component", componentKafka, "err", err)
	}
	reader := kafkago.NewReader(kafkago.ReaderConfig{
		Brokers: b.cfg.Kafka.Brokers,
		GroupID: b.cfg.Kafka.EffectiveGroupID(host, fmt.Sprintf("%08x", rand.Uint32())),
		Topic:   b.cfg.Kafka.Topic,
		// A fresh per-host group has no committed offset; start from the
		// newest event, not the topic's history — cold-start Sync already
		// loaded current state, so only new events need a kick.
		StartOffset: kafkago.LastOffset,
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

// telemetryMacFlowEvictor adapts telemetry_map to the
// [gc.MacFlowEvictor] seam, deleting a swept VM's residual flows before
// they re-drain as "unknown". Keys are collected during the Iterate
// pass and deleted after it — deleting mid-iteration can skip or repeat
// entries.
//
// docs/architecture/data-structures.md#lingering-ghost
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

// restoreWAL seeds GlobalState from disk and advances to
// [boot.PhaseStateRestored]. Only one failure is fatal: a snapshot from
// a newer build, which aborts the boot rather than let flush rotation
// destroy it.
//
// docs/architecture/data-structures.md#userspace-structures
func (b *bootstrapper) restoreWAL() error {
	if err := restoreFromWAL(b.ag); err != nil {
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

// pinnedMaps are the counter-bearing maps pinned under bpf.pin_path, so
// a restarted agent reuses the kernel's cumulative counters instead of
// resetting them. The metadata maps are deliberately not pinned — cold
// start rebuilds them every boot, so a pin would buy nothing and force
// reconciling stale state against a fresh snapshot.
//
// docs/architecture/boot-and-recovery.md#agent-crash-process-killed-kernel-intact
var pinnedMaps = []string{bpf.MapTelemetry, bpf.MapTelemetryStats}

// loadCollection loads the embedded BPF spec, pinning [pinnedMaps]
// under bpfCfg.PinPath and reusing compatible existing pins. Returns
// whether pinning succeeded — false means degraded (≤60s) crash
// recovery. The caller owns Close.
//
// [bpf.ValidateMapSizes] runs first and is boot-fatal on drift, so a
// forgotten `task generate` fails loudly instead of shipping stale
// capacity. An incompatible pin is never adopted: it is removed and
// recreated, self-healing across a map-ABI bump at the cost of that
// boot's crash recovery. When pinning is unavailable entirely, strict
// mode refuses to boot unless the operator opts into unpinned running.
//
// docs/architecture/boot-and-recovery.md#boot-sequence
func loadCollection(bpfCfg config.BPFConfig) (*ebpf.Collection, bool, error) {
	spec, err := bpf.LoadTelemetry()
	if err != nil {
		return nil, false, fmt.Errorf("load BPF spec: %w", err)
	}
	if err := bpf.ValidateMapSizes(spec); err != nil {
		return nil, false, fmt.Errorf("BPF spec validation: %w", err)
	}

	coll, err := loadPinnedCollection(spec, bpfCfg.PinPath)
	if err == nil {
		return coll, true, nil
	}

	// A stale pin whose sizing/type no longer matches the current build
	// must never be silently adopted (deferred item 7). Remove it and
	// retry once with a fresh pin — the designed refuse-to-reuse path,
	// self-healing across a map-ABI bump rather than bricking boot.
	if errors.Is(err, ebpf.ErrMapIncompatible) {
		slog.Warn("pinned map incompatible with current build; removing stale pins and recreating fresh (crash recovery skipped this boot)",
			"component", componentBPF, "pin_path", bpfCfg.PinPath, "err", err)
		if rmErr := removeStalePins(bpfCfg.PinPath); rmErr != nil {
			err = fmt.Errorf("%w; removing stale pins also failed: %v", err, rmErr)
		} else if coll, err = loadPinnedCollection(spec, bpfCfg.PinPath); err == nil {
			return coll, true, nil
		}
	}

	// Pinning could not be established. Strict mode (the default)
	// refuses to boot rather than silently downgrade to the ≤60s
	// WAL-bounded recovery the whole feature exists to remove.
	if !bpfCfg.UnsafeAllowUnpinnedMaps {
		return nil, false, fmt.Errorf("pin maps under %s: %w "+
			"(set bpf.unsafe_allow_unpinned_maps=true to boot with unpinned maps and ≤60s crash recovery)",
			bpfCfg.PinPath, err)
	}
	slog.Warn("could not pin maps; booting UNPINNED — agent-crash recovery degraded to ≤60s WAL-bounded loss",
		"component", componentBPF, "pin_path", bpfCfg.PinPath, "err", err)
	coll, err = loadUnpinnedCollection(spec)
	if err != nil {
		return nil, false, err
	}
	return coll, false, nil
}

// loadPinnedCollection marks [pinnedMaps] PinByName and loads the
// collection against pinPath, so cilium/ebpf reuses a compatible
// existing pin or creates and pins a fresh map. It returns an error
// wrapping [ebpf.ErrMapIncompatible] when an existing pin's
// sizing/type no longer matches the spec.
func loadPinnedCollection(spec *ebpf.CollectionSpec, pinPath string) (*ebpf.Collection, error) {
	if err := os.MkdirAll(pinPath, 0o700); err != nil {
		return nil, fmt.Errorf("create pin dir %s: %w", pinPath, err)
	}
	for _, name := range pinnedMaps {
		m := spec.Maps[name]
		if m == nil {
			return nil, fmt.Errorf("%s not present in BPF spec", name)
		}
		m.Pinning = ebpf.PinByName
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinPath},
	})
	if err != nil {
		return nil, fmt.Errorf("load BPF collection (pinned under %s): %w", pinPath, err)
	}
	return coll, nil
}

// loadUnpinnedCollection resets [pinnedMaps] back to PinNone and loads
// the collection without pins — the fallback when pinning is
// unavailable and the operator opted into unpinned operation. Resetting
// is required because loadPinnedCollection mutated the shared spec.
func loadUnpinnedCollection(spec *ebpf.CollectionSpec) (*ebpf.Collection, error) {
	for _, name := range pinnedMaps {
		if m := spec.Maps[name]; m != nil {
			m.Pinning = ebpf.PinNone
		}
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load BPF collection (unpinned): %w", err)
	}
	return coll, nil
}

// removeStalePins unlinks every [pinnedMaps] pin under pinPath so a
// subsequent load recreates them fresh. A pin already absent is
// success. Used only on the incompatible-pin self-heal path.
func removeStalePins(pinPath string) error {
	var errs []error
	for _, name := range pinnedMaps {
		p := filepath.Join(pinPath, name)
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("remove %s: %w", p, err))
		}
	}
	return errors.Join(errs...)
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
