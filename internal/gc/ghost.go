// Package gc owns the agent's eviction work: the lingering-ghost sweep
// (this file) and pressure-relief eviction (pressure.go).
//
// Deleted metadata lingers so a dying VM's FIN/RST packets still
// classify. The sweep then deletes kernel-first, then userspace, which
// preserves the kernel ⊆ userspace subset at every instant.
//
// docs/architecture/data-structures.md#map-lifecycle-invariants
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

// MacFlowEvictor deletes a swept VM's residual telemetry_map counters,
// which outlive its MAC and would otherwise re-drain as "unknown". nil
// skips cleanup; best-effort, so a failure just means one flow may fold
// to unknown once.
//
// docs/architecture/data-structures.md#lingering-ghost
type MacFlowEvictor interface {
	DeleteFlowsForMACs(macs map[uint64]struct{}) (int, error)
}

// FlowSettler folds flow rows into the settled-bytes accumulator. The
// sweep calls it at the last moment the MAC still resolves to its
// tenant, so the VM's lifetime bytes stay attributed. nil skips
// settling.
//
// docs/architecture/data-structures.md#settled-bytes
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

// sweep removes ghosts whose grace has elapsed. Pure orchestration —
// the load-bearing part is the phase order, which each phase's own doc
// comment justifies:
//
//	deleteKernelMACs → evictResidualFlows → settleSwept → deleteUserspace
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

// settleSwept folds the swept MACs' rows into settled while the MAC
// still resolves — its metadata dies only in the next phase. Uses
// [state.SettleEvict]: the kernel counters went in phase 2, so deleting
// the rows is what stops GlobalState growing with every VM that lived.
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
// Runs last so a MAC never becomes unknown while its residual flows
// still exist, and so settleSwept could still resolve the tenant.
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
