// Package gc owns the agent's eviction work: the lingering-ghost sweep
// of deleted metadata (this file) and the metrics for both that sweep
// and the scraper-driven pressure-relief eviction (metrics.go). It is a
// Service in the package-anatomy sense (docs/DESIGN.md §13.4): the
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
// (docs/DESIGN.md §3.4). The kernel mac_tenant_map is a strict subset
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

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/boot"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/metadata"
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
// metadata map (docs/DESIGN.md §3.3). The agent wires a telemetry_map
// adapter that scans by [metadata.VMMAC]; tests wire a recording mock.
// Optional: a nil evictor skips residual-flow cleanup. Returns the count
// deleted and the first error encountered (best-effort — a failure just
// means a flow may re-fold to unknown once).
type MacFlowEvictor interface {
	DeleteFlowsForMACs(macs map[uint64]struct{}) (int, error)
}

// GhostSweeper periodically drops metadata entries whose 60s grace
// window has elapsed. Construct with [New], then run [GhostSweeper.Run]
// on a long-lived goroutine.
type GhostSweeper struct {
	meta        *metadata.ShardedMetadataMap
	evictor     MacEvictor
	flowEvictor MacFlowEvictor
	mapGauge    MapGauge
	seq         *boot.Sequencer
	mx          *Metrics
	interval    time.Duration
}

// Options bundles the inputs to [New]. Meta, Evictor, and Metrics are
// required; FlowEvictor is optional (nil skips residual-flow cleanup —
// used by tests without a kernel telemetry_map); Seq is optional (nil
// skips the boot barrier — used by sweep-only unit tests); Interval
// defaults to the 60s sweep cadence when zero.
type Options struct {
	Meta        *metadata.ShardedMetadataMap
	Evictor     MacEvictor
	FlowEvictor MacFlowEvictor
	// MapGauge refreshes the mac_tenant_map fill gauge after a sweep.
	// Optional (nil skips); the agent wires its bpf metrics bundle.
	MapGauge MapGauge
	Seq      *boot.Sequencer
	Metrics  *Metrics
	Interval time.Duration
}

// New constructs a GhostSweeper from opts, applying the default sweep
// interval when Interval is zero.
func New(opts Options) *GhostSweeper {
	interval := opts.Interval
	if interval == 0 {
		interval = ghostSweepInterval
	}
	return &GhostSweeper{
		meta:        opts.Meta,
		evictor:     opts.Evictor,
		flowEvictor: opts.FlowEvictor,
		mapGauge:    opts.MapGauge,
		seq:         opts.Seq,
		mx:          opts.Metrics,
		interval:    interval,
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
	t := time.NewTicker(g.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			g.sweep(now)
		}
	}
}

// sweep removes the ghosts whose grace has elapsed as of now. It is pure
// orchestration: the load-bearing part is the order of the three delete
// phases, which is exactly the sequence of calls below.
//
//  1. [GhostSweeper.deleteKernelMACs]  — mac_tenant_map, kernel-first for
//     the kernel ⊆ userspace invariant (docs/DESIGN.md §3.4).
//  2. [GhostSweeper.evictResidualFlows] — the swept MACs' telemetry_map
//     flows, BEFORE phase 3.
//  3. [GhostSweeper.deleteUserspace]   — the metadata map.
//
// Phase 2 precedes phase 3 deliberately: the Classifier decides
// known-vs-unknown off the userspace map, so while a swept MAC is still
// present there a concurrent scrape classifies its flows as known
// (harmless). Removing the residual flows first means that once the MAC
// becomes unknown there is nothing left to re-bill as "unknown"
// (docs/DESIGN.md §3.3).
func (g *GhostSweeper) sweep(now time.Time) {
	expired, active := g.classify(now)
	swept := g.deleteKernelMACs(expired)
	residual := g.evictResidualFlows(swept)
	g.deleteUserspace(swept)
	g.refreshMacGauge()
	g.report(len(swept), residual, active)
}

// refreshMacGauge keeps cubecos_bpf_map_current_entries{map="mac_tenant_map"}
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

// deleteUserspace drops the swept MACs from the userspace metadata map.
// Runs last so a MAC never becomes unknown while its residual flows still
// exist (docs/DESIGN.md §3.3).
func (g *GhostSweeper) deleteUserspace(swept map[uint64]struct{}) {
	for mac := range swept {
		g.meta.Delete(mac)
	}
}

// report records the pass's outcome on the GC metrics and logs a line
// when anything was swept.
func (g *GhostSweeper) report(evicted, residual, active int) {
	g.mx.RecordTTLEvictions(evicted)
	g.mx.RecordResidualFlowEvictions(residual)
	g.mx.SetGhostsActive(active)
	if evicted > 0 {
		slog.Info("swept expired lingering ghosts",
			"component", component, "evicted", evicted,
			"residual_flows", residual, "still_active", active)
	}
}
