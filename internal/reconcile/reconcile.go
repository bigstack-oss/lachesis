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
	src       MetadataSource
	trie      kernelwriter.MapUpdateDeleter
	meta      *metadata.ShardedMetadataMap
	macWriter MacWriter
	interner  *metadata.TenantInterner
	seq       *boot.Sequencer
	mx        *Metrics
	interval  time.Duration
	// kick requests an out-of-band reconcile pass (the Kafka consumer
	// signals it on a Neutron notification). Buffered to one so a burst
	// of events coalesces into a single pending pass; [Reconciler.Run]
	// drains it.
	kick chan struct{}
}

// Options bundles the inputs to [New]. Source, Trie, Interner, and
// Metrics are required. Meta and MacWriter enable the mac_tenant_map
// reconcile; both nil (the trie-only unit tests) skips it. Seq is
// optional (nil skips the boot barrier, used by reconcileOnce unit
// tests); Interval defaults to [defaultInterval] when zero.
type Options struct {
	Source    MetadataSource
	Trie      kernelwriter.MapUpdateDeleter
	Meta      *metadata.ShardedMetadataMap
	MacWriter MacWriter
	Interner  *metadata.TenantInterner
	Seq       *boot.Sequencer
	Metrics   *Metrics
	Interval  time.Duration
}

// New constructs a Reconciler from opts, applying the default interval
// when Interval is zero.
func New(opts Options) *Reconciler {
	interval := opts.Interval
	if interval == 0 {
		interval = defaultInterval
	}
	return &Reconciler{
		src:       opts.Source,
		trie:      opts.Trie,
		meta:      opts.Meta,
		macWriter: opts.MacWriter,
		interner:  opts.Interner,
		seq:       opts.Seq,
		mx:        opts.Metrics,
		interval:  interval,
		kick:      make(chan struct{}, 1),
	}
}

// Kick requests an immediate reconcile pass out of band. The Kafka
// consumer calls it when a Neutron notification shows metadata changed,
// so the trie and mac_tenant_map refresh within one pass instead of
// waiting up to a full interval. It is non-blocking and coalescing — the
// buffered channel holds at most one pending kick, so a burst of events
// costs a single extra pass — and safe to call from any goroutine.
func (r *Reconciler) Kick() {
	select {
	case r.kick <- struct{}{}:
	default: // a pass is already pending; coalesce
	}
}

// Run reconciles on every interval tick and on every [Reconciler.Kick]
// until ctx is cancelled — one applier goroutine for both the periodic
// safety net and the Kafka-driven kicks, so passes never overlap. It
// first blocks on [boot.PhaseStateRestored] so no kernel write races the
// boot sequence — the cold-start push must have committed the initial
// trie before any delta is computed against it. If the boot aborts (or
// ctx is cancelled) before that phase, Run returns without reconciling.
// There is no immediate first pass: cold-start already populated the
// trie, so the first periodic reconcile fires one interval in (a kick
// can run one sooner).
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
		case <-r.kick:
			r.reconcileOnce(ctx, time.Now())
		}
	}
}

// reconcileOnce runs one full reconcile pass: fetch a fresh snapshot,
// apply the trie and mac_tenant_map deltas against current state, and
// commit on success. Orchestration only — each step records its own
// terminal outcome on cubecos_reconcile_runs_total and signals whether
// the pass may continue.
func (r *Reconciler) reconcileOnce(ctx context.Context, now time.Time) {
	result, ok := r.fetch(ctx)
	if !ok {
		return
	}
	delta, ok := r.applyTrie(result)
	if !ok {
		return
	}
	mac := r.reconcileMACs(result.Snapshot.Ports, now)

	r.src.Commit(result, now)
	r.mx.RecordRun(resultOK)
	r.logOutcome(delta, mac, len(result.Ambiguities))
}

// fetch runs one Sync. On failure it records a sync_error and returns
// ok=false, so the rest of the pass is skipped and metadata staleness
// grows until a later pass succeeds.
func (r *Reconciler) fetch(ctx context.Context) (neutron.SyncResult, bool) {
	result, err := r.src.Sync(ctx)
	if err != nil {
		slog.Warn("reconcile sync failed; metadata staleness grows until the next pass succeeds",
			"component", component, "err", err)
		r.mx.RecordRun(resultSyncError)
		return neutron.SyncResult{}, false
	}
	return result, true
}

// applyTrie applies the subnet_zone_trie delta against the last committed
// trie. On a kernel-write failure it records an apply_error and returns
// ok=false so the caller does NOT commit: the retained trie stays the
// "old" side, so the next pass re-diffs against it and retries the failed
// writes (and any deletes [kernelwriter.ApplyTrieDelta] skipped after the
// failure) rather than treating the partial state as done.
func (r *Reconciler) applyTrie(result neutron.SyncResult) (kernelwriter.TrieDelta, bool) {
	delta, err := kernelwriter.ApplyTrieDelta(r.trie, r.src.Trie(), result.Entries, r.interner)
	if err != nil {
		slog.Error("reconcile trie apply failed; not committing — next pass re-diffs and retries",
			"component", component,
			"added", delta.Added, "changed", delta.Changed, "removed", delta.Removed,
			"err", err)
		r.mx.RecordRun(resultApplyError)
		return delta, false
	}
	return delta, true
}

// logOutcome reports a committed pass: trie and MAC deltas log only when
// non-empty, and runtime static-route ambiguities log as a warning —
// unlike cold-start (which can abort under strict mode), a running agent
// applies the EXTERNAL fallback already baked into the entries and
// continues.
func (r *Reconciler) logOutcome(delta kernelwriter.TrieDelta, mac macDelta, ambiguities int) {
	if delta != (kernelwriter.TrieDelta{}) {
		slog.Info("reconcile applied trie delta",
			"component", component,
			"added", delta.Added, "changed", delta.Changed, "removed", delta.Removed)
	}
	if mac != (macDelta{}) {
		slog.Info("reconcile applied mac_tenant_map delta",
			"component", component,
			"inserted", mac.Inserted, "changed", mac.Changed, "ghosted", mac.Ghosted)
	}
	if ambiguities > 0 {
		slog.Warn("reconcile: static-route ambiguities resolved to EXTERNAL fallback",
			"component", component, "count", ambiguities)
	}
}
