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
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/metadata"
)

// MacEvictor deletes a MAC entry from the kernel mac_tenant_map. It is
// the consumer-defined seam over the kernel map: the agent wires a thin
// *ebpf.Map adapter, and tests wire a recording mock. Delete must be
// idempotent — a MAC already gone from the kernel is not an error.
type MacEvictor interface {
	Delete(mac uint64) error
}

// GhostSweeper periodically drops metadata entries whose 60s grace
// window has elapsed. Construct with [New], then run [GhostSweeper.Run]
// on a long-lived goroutine.
type GhostSweeper struct {
	meta     *metadata.ShardedMetadataMap
	evictor  MacEvictor
	seq      *boot.Sequencer
	mx       *Metrics
	interval time.Duration
}

// Options bundles the inputs to [New]. Meta, Evictor, and Metrics are
// required; Seq is optional (nil skips the boot barrier — used by
// sweep-only unit tests); Interval defaults to the 60s sweep cadence
// when zero.
type Options struct {
	Meta     *metadata.ShardedMetadataMap
	Evictor  MacEvictor
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
		meta:     opts.Meta,
		evictor:  opts.Evictor,
		seq:      opts.Seq,
		mx:       opts.Metrics,
		interval: interval,
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

// sweep drops every entry whose DeleteAt has elapsed as of now. It
// collects the expired MACs under the shard read locks (via Range),
// then deletes outside the walk — a kernel Delete is a syscall, and
// metadata.Delete takes a shard write lock, neither of which is safe to
// call from inside Range. The active-ghosts gauge is set to the count
// of entries still within their grace window after the pass.
func (g *GhostSweeper) sweep(now time.Time) {
	var expired []uint64
	activeGhosts := 0
	g.meta.Range(func(mac uint64, meta *metadata.TenantMeta) bool {
		switch {
		case meta.DeleteAt.IsZero():
			// Live entry — not a ghost.
		case meta.DeleteAt.After(now):
			activeGhosts++ // ghosted, grace not yet elapsed
		default:
			expired = append(expired, mac)
		}
		return true
	})

	evicted := 0
	for _, mac := range expired {
		if err := g.evictor.Delete(mac); err != nil {
			// Keep the userspace entry so the kernel⊆userspace invariant
			// holds; retry on the next sweep.
			slog.Warn("ghost kernel delete failed; retaining userspace entry for next sweep",
				"component", component, "mac", mac, "err", err)
			continue
		}
		g.meta.Delete(mac)
		evicted++
	}

	g.mx.RecordTTLEvictions(evicted)
	g.mx.SetGhostsActive(activeGhosts)
	if evicted > 0 {
		slog.Info("swept expired lingering ghosts",
			"component", component, "evicted", evicted, "still_active", activeGhosts)
	}
}
