// Package gc owns the agent's eviction work: the lingering-ghost sweep
// of deleted metadata (this file) and the metrics for both that sweep
// and the scraper-driven pressure-relief eviction (metrics.go). It is a
// Service in the package-anatomy sense (docs/development/conventions.md#package-anatomy): the
// [GhostSweeper] owns a long-running loop started by the agent's worker
// table.
//
// # Lingering Ghost
//
// When Neutron deletes a port or subnet, the agent does not drop the
// metadata immediately — dying TCP FIN/RST packets can still arrive
// from a VM that is going away, and they must classify to the right
// tenant rather than "unknown". Instead the entry is marked with
// DeleteAt = now + 60s (via [metadata.ShardedMetadataMap.MarkDelete],
// driven by the Kafka consumer in a later sprint). The GhostSweeper
// runs every 60s and drops entries whose grace window has elapsed.
//
// # Deletion ordering
//
// Expired entries are deleted kernel-first, then userspace
// (docs/architecture/data-structures.md#map-lifecycle-invariants). The kernel mac_tenant_map is a strict subset
// of the userspace ShardedMetadataMap; deleting the kernel side first
// preserves that invariant at every instant, so a packet that races
// the sweep either still classifies (kernel entry present) or misses
// the kernel and falls through — it never returns a tenant_id that
// userspace can no longer translate. If the kernel delete fails, the
// userspace entry is kept and retried on the next sweep, never leaving
// a kernel entry without its userspace mirror.
package gc

import (
	"context"
	"log/slog"
	"time"

	"github.com/bigstack-oss/lachesis/internal/boot"
	"github.com/bigstack-oss/lachesis/internal/bpf"
	"github.com/bigstack-oss/lachesis/internal/metadata"
	"github.com/bigstack-oss/lachesis/internal/state"
	"github.com/bigstack-oss/lachesis/internal/tunables"
)

// MapGauge refreshes the kernel mac_tenant_map current-entry gauge after
// the sweep deletes ghosts — cold-start sets it once, so without this it
// over-reports fill until the next reconcile. Consumer-defined seam;
// *bpf.Metrics satisfies it.
type MapGauge interface {
	SetCurrent(mapName string, value float64)
}

// MacEvictor deletes a MAC entry from the kernel mac_tenant_map. It is
// the consumer-defined seam over the kernel map: the agent wires a thin
// *ebpf.Map adapter, and tests wire a recording mock. Delete must be
// idempotent — a MAC already gone from the kernel is not an error.
type MacEvictor interface {
	Delete(mac uint64) error
}

// MacFlowEvictor deletes the kernel telemetry_map flow counters that
// belong to a set of VM MACs — the residual flows of a deleted VM, which
// outlive the MAC (the sweep removes mac_tenant_map, not telemetry_map)
// and would otherwise be re-drained as "unknown" once the MAC leaves the
// metadata map (docs/architecture/data-structures.md#lingering-ghost). The agent wires a telemetry_map
// adapter that scans by [metadata.VMMAC]; tests wire a recording mock.
// Optional: a nil evictor skips residual-flow cleanup. Returns the count
// deleted and the first error encountered (best-effort — a failure just
// means a flow may re-fold to unknown once).
type MacFlowEvictor interface {
	DeleteFlowsForMACs(macs map[uint64]struct{}) (int, error)
}

// FlowSettler folds userspace flow rows into the settled-bytes
// accumulator (docs/architecture/data-structures.md#settled-bytes). The sweep calls it just before
// deleting a dead MAC's userspace metadata — the last moment the MAC
// still resolves to its tenant — so the VM's lifetime bytes stay
// attributed instead of re-bucketing to "unknown" at the next scrape.
// The agent wires *state.GlobalState; tests may wire it too (it is
// cheap to construct) or leave it nil to skip settling.
type FlowSettler interface {
	Settle(mode state.SettleMode, resolve func(bpf.FlowKey) (tenant, extNet, server string, ok bool)) int
}

// GhostSweeper periodically drops metadata entries whose 60s grace
// window has elapsed. Construct with [New], then run [GhostSweeper.Run]
// on a long-lived goroutine.
type GhostSweeper struct {
	meta        *metadata.ShardedMetadataMap
	evictor     MacEvictor
	flowEvictor MacFlowEvictor
	settler     FlowSettler
	routers     *metadata.RouterMACs
	tun         *tunables.Store
	mapGauge    MapGauge
	seq         *boot.Sequencer
	mx          *Metrics
}

// Options bundles the inputs to [New]. Meta, Evictor, and Metrics are
// required; FlowEvictor is optional (nil skips residual-flow cleanup —
// used by tests without a kernel telemetry_map); Settler is optional
// (nil skips the settled-bytes fold — pre-fold unit tests); Seq is
// optional (nil skips the boot barrier — used by sweep-only unit
// tests); the sweep cadence is the live gc.ghost_sweep_interval tunable.
type Options struct {
	Meta        *metadata.ShardedMetadataMap
	Evictor     MacEvictor
	FlowEvictor MacFlowEvictor
	// Settler folds swept MACs' flow rows into the settled-bytes
	// accumulator before their metadata (the tenant binding) is
	// deleted. The agent wires its *state.GlobalState.
	Settler FlowSettler
	// Routers resolves each folded row's per-flow external_network
	// label ([metadata.FlowExternalLabel]) so the fold lands in exactly
	// the series the Collector was emitting. Optional (nil = per-VM
	// fallback only — pre-per-flow unit tests).
	Routers *metadata.RouterMACs
	// Tunables supplies the live sweep cadence (hot-reload; applies at
	// the next tick). REQUIRED — operational knobs have exactly one
	// source; unit tests construct a store with the values they
	// exercise.
	Tunables *tunables.Store
	// MapGauge refreshes the mac_tenant_map fill gauge after a sweep.
	// Optional (nil skips); the agent wires its bpf metrics bundle.
	MapGauge MapGauge
	Seq      *boot.Sequencer
	Metrics  *Metrics
}

// New constructs a GhostSweeper from opts.
func New(opts Options) *GhostSweeper {
	return &GhostSweeper{
		meta:        opts.Meta,
		evictor:     opts.Evictor,
		flowEvictor: opts.FlowEvictor,
		settler:     opts.Settler,
		routers:     opts.Routers,
		tun:         opts.Tunables,
		mapGauge:    opts.MapGauge,
		seq:         opts.Seq,
		mx:          opts.Metrics,
	}
}

// Run sweeps expired ghosts every interval until ctx is cancelled. It
// first blocks on [boot.PhaseStateRestored] so no eviction races the
// boot sequence; if the boot aborts (or ctx is cancelled) before that
// phase, Run returns without sweeping. There is no immediate first
// sweep: metadata is freshly populated at boot and ghosts need a full
// grace window to expire, so the first sweep fires one interval in.
func (g *GhostSweeper) Run(ctx context.Context) {
	if g.seq != nil {
		if err := g.seq.Await(ctx, boot.PhaseStateRestored); err != nil {
			slog.Info("ghost sweeper stopping before first sweep",
				"component", component, "err", err)
			return
		}
	}
	cur := g.tun.Get().GhostSweepInterval
	t := time.NewTicker(cur)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			g.sweep(now)
			if next := g.tun.Get().GhostSweepInterval; next != cur {
				t.Reset(next)
				cur = next
			}
		}
	}
}

// sweep removes the ghosts whose grace has elapsed as of now. It is pure
// orchestration: the load-bearing part is the order of the four phases,
// which is exactly the sequence of calls below.
//
//  1. [GhostSweeper.deleteKernelMACs]  — mac_tenant_map, kernel-first for
//     the kernel ⊆ userspace invariant (docs/architecture/data-structures.md#map-lifecycle-invariants).
//  2. [GhostSweeper.evictResidualFlows] — the swept MACs' telemetry_map
//     flows, BEFORE phases 3–4.
//  3. [GhostSweeper.settleSwept]       — fold the swept MACs' GlobalState
//     rows into the settled accumulator, BEFORE phase 4.
//  4. [GhostSweeper.deleteUserspace]   — the metadata map.
//
// Phase 2 precedes phase 4 deliberately: the Classifier decides
// known-vs-unknown off the userspace map, so while a swept MAC is still
// present there a concurrent scrape classifies its flows as known
// (harmless). Removing the residual flows first means that once the MAC
// becomes unknown there is nothing left to re-bill as "unknown"
// (docs/architecture/data-structures.md#lingering-ghost).
//
// Phase 3 precedes phase 4 because settling needs the tenant, and the
// userspace metadata entry is the last place the swept MAC still
// resolves. Its position after phase 2 matters too: the kernel flows
// are gone, so [state.SettleEvict] (fold + delete the row) is safe —
// nothing will feed the evicted rows again (docs/architecture/data-structures.md#settled-bytes).
func (g *GhostSweeper) sweep(now time.Time) {
	expired, active := g.classify(now)
	swept := g.deleteKernelMACs(expired)
	residual := g.evictResidualFlows(swept)
	settled := g.settleSwept(swept)
	g.deleteUserspace(swept)
	g.refreshMacGauge()
	g.report(len(swept), residual, settled, active)
}

// refreshMacGauge keeps lachesis_bpf_map_current_entries{map="mac_tenant_map"}
// current after the sweep's deletes — cold-start sets it once, so without
// this it over-reports fill until the next reconcile. The count tracks
// the userspace metadata map, which the kernel map mirrors. No-op when no
// gauge is wired (sweep-only unit tests).
func (g *GhostSweeper) refreshMacGauge() {
	if g.mapGauge == nil {
		return
	}
	g.mapGauge.SetCurrent(bpf.MapMacTenant, float64(g.meta.Len()))
}

// classify partitions the metadata map as of now into the MACs whose
// ghost grace has elapsed (returned, ready to sweep) and a count of
// those still inside it. Collecting under Range's shard read locks and
// acting afterwards keeps the syscall and write-lock work out of the
// walk.
func (g *GhostSweeper) classify(now time.Time) (expired []uint64, active int) {
	g.meta.Range(func(mac uint64, meta *metadata.TenantMeta) bool {
		switch {
		case meta.DeleteAt.IsZero():
			// Live entry — not a ghost.
		case meta.DeleteAt.After(now):
			active++ // ghosted, grace not yet elapsed
		default:
			expired = append(expired, mac)
		}
		return true
	})
	return expired, active
}

// deleteKernelMACs removes each expired MAC from the kernel
// mac_tenant_map and returns the set that succeeded — the only MACs safe
// to finish removing. A failed delete leaves the userspace entry in place
// (preserving kernel ⊆ userspace) for retry on the next sweep.
func (g *GhostSweeper) deleteKernelMACs(expired []uint64) map[uint64]struct{} {
	swept := make(map[uint64]struct{}, len(expired))
	for _, mac := range expired {
		if err := g.evictor.Delete(mac); err != nil {
			slog.Warn("ghost kernel delete failed; retaining userspace entry for next sweep",
				"component", component, "mac", mac, "err", err)
			continue
		}
		swept[mac] = struct{}{}
	}
	return swept
}

// evictResidualFlows deletes the swept MACs' residual telemetry_map flows
// and returns the flow count removed. No-op when no flow evictor is wired
// (darwin, tests) or nothing was swept. A failure is logged, not fatal —
// the worst case is a flow re-folding to "unknown" once.
func (g *GhostSweeper) evictResidualFlows(swept map[uint64]struct{}) int {
	if g.flowEvictor == nil || len(swept) == 0 {
		return 0
	}
	n, err := g.flowEvictor.DeleteFlowsForMACs(swept)
	if err != nil {
		slog.Warn("ghost residual-flow eviction failed; some flows may re-fold to unknown once",
			"component", component, "err", err)
	}
	return n
}

// settleSwept folds the swept MACs' GlobalState flow rows into the
// settled-bytes accumulator, attributing each row to the tenant and
// external network its MAC still resolves to — the metadata entries are
// deleted only in the next phase, so the binding is intact here. Rows
// fold with [state.SettleEvict]: their kernel counters were removed in
// phase 2, so the rows are dead and deleting them is what stops
// GlobalState (and the WAL) growing with every VM that ever lived
// (docs/architecture/data-structures.md#settled-bytes). The per-row external_network label resolves
// per flow exactly as the Collector does ([metadata.FlowExternalLabel]:
// peer router-interface MAC first, per-VM fallback behind the zone
// gate), so each fold lands in exactly the series its live flow
// occupied. Returns the number of
// rows folded. No-op when no settler is wired or nothing was swept.
func (g *GhostSweeper) settleSwept(swept map[uint64]struct{}) int {
	if g.settler == nil || len(swept) == 0 {
		return 0
	}
	metas := make(map[uint64]*metadata.TenantMeta, len(swept))
	for mac := range swept {
		if meta, ok := g.meta.Lookup(mac); ok {
			metas[mac] = meta
		}
	}
	return g.settler.Settle(state.SettleEvict, metadata.SettleResolver(g.routers,
		func(k bpf.FlowKey) (*metadata.TenantMeta, bool) {
			meta, ok := metas[metadata.VMMAC(k)]
			return meta, ok
		}))
}

// deleteUserspace drops the swept MACs from the userspace metadata map.
// Runs last so a MAC never becomes unknown while its residual flows still
// exist (docs/architecture/data-structures.md#lingering-ghost) and so settleSwept could still resolve the
// tenant (docs/architecture/data-structures.md#settled-bytes).
func (g *GhostSweeper) deleteUserspace(swept map[uint64]struct{}) {
	for mac := range swept {
		g.meta.Delete(mac)
	}
}

// report records the pass's outcome on the GC metrics and logs a line
// when anything was swept.
func (g *GhostSweeper) report(evicted, residual, settled, active int) {
	g.mx.RecordTTLEvictions(evicted)
	g.mx.RecordResidualFlowEvictions(residual)
	g.mx.RecordSettledFlows(settled)
	g.mx.SetGhostsActive(active)
	if evicted > 0 {
		slog.Info("swept expired lingering ghosts",
			"component", component, "evicted", evicted,
			"residual_flows", residual, "settled_flows", settled,
			"still_active", active)
	}
}
