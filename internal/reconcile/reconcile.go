// Package reconcile owns the periodic Neutron reconcile: a 5-minute
// safety net that re-fetches the full OpenStack snapshot, diffs it
// against the kernel trie, and applies only the rows that changed. It
// is a Service in the package-anatomy sense (docs/DESIGN.md §13.4) —
// the [Reconciler] owns a long-running loop started by the agent's
// worker table.
//
// # Why it exists
//
// The Kafka consumer (a later sprint) keeps metadata fresh in real
// time, but a Kafka outage would otherwise let the trie drift
// unboundedly. This periodic reconcile bounds that drift: every
// interval it does a full [MetadataSource.Sync] and applies the
// difference as if Kafka had delivered it, so metadata staleness never
// exceeds one interval regardless of Kafka availability (docs/DESIGN.md
// §9). It shares the incremental write path — [kernelwriter.ApplyTrieDelta],
// with its docs/DESIGN.md §5.7 insert-then-delete ordering — that the
// Kafka consumer will also use.
//
// # Scope
//
// This reconcile covers the LPM subnet_zone_trie (subnet / router /
// route changes). The mac_tenant_map reconcile (port add → insert,
// port remove → lingering-ghost MarkDelete) lands alongside the
// late-binding resolve path in a sibling change.
package reconcile

import (
	"context"
	"log/slog"
	"time"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/boot"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/kernelwriter"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/metadata"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/neutron"
)

// MetadataSource is the subset of [neutron.Neutron] the reconcile loop
// drives: a full list-and-build [MetadataSource.Sync], the retained
// trie of the last committed sync ([MetadataSource.Trie], the "old"
// side of the diff), and [MetadataSource.Commit] to publish the new
// state once the kernel has acknowledged it. Defined here as the
// consumer's minimal seam so the loop can be unit-tested with a fake;
// *neutron.Neutron satisfies it.
type MetadataSource interface {
	Sync(ctx context.Context) (neutron.SyncResult, error)
	Trie() []neutron.TrieEntry
	Commit(result neutron.SyncResult, at time.Time)
}

// Reconciler periodically reconciles the kernel subnet_zone_trie against
// a fresh Neutron snapshot. Construct with [New], then run
// [Reconciler.Run] on a long-lived goroutine.
type Reconciler struct {
	src      MetadataSource
	trie     kernelwriter.MapUpdateDeleter
	interner *metadata.TenantInterner
	seq      *boot.Sequencer
	mx       *Metrics
	interval time.Duration
}

// Options bundles the inputs to [New]. Source, Trie, Interner, and
// Metrics are required; Seq is optional (nil skips the boot barrier,
// used by reconcileOnce unit tests); Interval defaults to
// [defaultInterval] when zero.
type Options struct {
	Source   MetadataSource
	Trie     kernelwriter.MapUpdateDeleter
	Interner *metadata.TenantInterner
	Seq      *boot.Sequencer
	Metrics  *Metrics
	Interval time.Duration
}

// New constructs a Reconciler from opts, applying the default interval
// when Interval is zero.
func New(opts Options) *Reconciler {
	interval := opts.Interval
	if interval == 0 {
		interval = defaultInterval
	}
	return &Reconciler{
		src:      opts.Source,
		trie:     opts.Trie,
		interner: opts.Interner,
		seq:      opts.Seq,
		mx:       opts.Metrics,
		interval: interval,
	}
}

// Run reconciles every interval until ctx is cancelled. It first blocks
// on [boot.PhaseStateRestored] so no kernel write races the boot
// sequence — the cold-start push must have committed the initial trie
// before any delta is computed against it. If the boot aborts (or ctx
// is cancelled) before that phase, Run returns without reconciling.
// There is no immediate first pass: cold-start already populated the
// trie, so the first reconcile fires one interval in.
func (r *Reconciler) Run(ctx context.Context) {
	if r.seq != nil {
		if err := r.seq.Await(ctx, boot.PhaseStateRestored); err != nil {
			slog.Info("reconciler stopping before first pass",
				"component", component, "err", err)
			return
		}
	}
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			r.reconcileOnce(ctx, now)
		}
	}
}

// reconcileOnce runs one full reconcile pass: fetch a fresh snapshot,
// apply the trie delta against the last committed state, and commit on
// success. Each terminal outcome increments cubecos_reconcile_runs_total
// exactly once.
//
// On a Sync failure nothing is touched. On a kernel-apply failure the
// new state is deliberately NOT committed: the retained trie stays the
// "old" side, so the next pass re-diffs against it and retries the
// failed writes (and any deletes [kernelwriter.ApplyTrieDelta] skipped
// after the failure) rather than treating the partial state as done.
func (r *Reconciler) reconcileOnce(ctx context.Context, now time.Time) {
	result, err := r.src.Sync(ctx)
	if err != nil {
		slog.Warn("reconcile sync failed; metadata staleness grows until the next pass succeeds",
			"component", component, "err", err)
		r.mx.RecordRun(resultSyncError)
		return
	}

	delta, err := kernelwriter.ApplyTrieDelta(r.trie, r.src.Trie(), result.Entries, r.interner)
	if err != nil {
		slog.Error("reconcile trie apply failed; not committing — next pass re-diffs and retries",
			"component", component,
			"added", delta.Added, "changed", delta.Changed, "removed", delta.Removed,
			"err", err)
		r.mx.RecordRun(resultApplyError)
		return
	}

	r.src.Commit(result, now)
	r.mx.RecordRun(resultOK)

	if delta != (kernelwriter.TrieDelta{}) {
		slog.Info("reconcile applied trie delta",
			"component", component,
			"added", delta.Added, "changed", delta.Changed, "removed", delta.Removed)
	}
	// Runtime ambiguities resolve to EXTERNAL fallback in the entries
	// already; unlike cold-start (which can abort under strict mode), a
	// running agent applies and logs rather than stopping.
	if n := len(result.Ambiguities); n > 0 {
		slog.Warn("reconcile: static-route ambiguities resolved to EXTERNAL fallback",
			"component", component, "count", n)
	}
}
