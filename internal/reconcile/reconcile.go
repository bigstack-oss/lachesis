// Package reconcile owns the periodic Neutron reconcile: a 5-minute
// safety net that re-fetches the full snapshot and applies only the
// rows that changed, so metadata staleness stays bounded by one
// interval even through a Kafka outage.
//
// It shares [kernelwriter.ApplyTrieDelta] with the Kafka path, so the
// insert-then-delete ordering holds for both.
//
// docs/architecture/trie-construction.md#incremental-updates
package reconcile

import (
	"context"
	"log/slog"
	"time"

	"github.com/bigstack-oss/lachesis/internal/boot"
	"github.com/bigstack-oss/lachesis/internal/bpf"
	"github.com/bigstack-oss/lachesis/internal/kernelwriter"
	"github.com/bigstack-oss/lachesis/internal/metadata"
	"github.com/bigstack-oss/lachesis/internal/neutron"
	"github.com/bigstack-oss/lachesis/internal/state"
	"github.com/bigstack-oss/lachesis/internal/tunables"
)

// MapGauge refreshes a kernel map's current-entry gauge
// (lachesis_bpf_map_current_entries). Cold-start sets it once; the
// incremental path must keep it current or it drifts as the reconcile
// rewrites the trie and mac_tenant_map. Consumer-defined seam;
// *bpf.Metrics satisfies it.
type MapGauge interface {
	SetCurrent(mapName string, value float64)
}

// AmphoraGauge publishes how many Amphora ports the latest pass
// re-attributed to their load balancer's owner. Cold start sets it once,
// so without this seam the gauge would freeze at the boot value — a load
// balancer created later would never move it, and the very failure it
// exists to catch would read healthy. nil skips publishing.
//
// docs/architecture/octavia.md
type AmphoraGauge interface {
	SetAmphoraPorts(n int)
}

// FlowSettler folds flow rows into the settled-bytes accumulator. The
// MAC reconcile calls it just before re-pointing a live MAC, so bytes
// earned under the old attribution settle there instead of re-binding
// wholesale at the next scrape.
//
// docs/architecture/data-structures.md#settled-bytes
type FlowSettler interface {
	Settle(mode state.SettleMode, resolve func(bpf.FlowKey) (tenant, extNet, server string, ok bool)) int
	// PruneServerSettled releases server-settled buckets whose server is
	// no longer in the Nova server list — the server tier's lifecycle
	// rule. The reconciler owns the call: it is the one place a fresh,
	// successful Nova fetch is in hand.
	//
	// Settled bytes: docs/architecture/data-structures.md#settled-bytes
	PruneServerSettled(alive map[string]struct{}) int
	// PruneTenantSettled releases tenant-settled buckets whose project is
	// no longer in the Keystone project list, folding each into the
	// total-settled absorber — the tenant tier's lifecycle rule. Same
	// ownership rationale as PruneServerSettled.
	//
	// Settled bytes: docs/architecture/data-structures.md#settled-bytes
	PruneTenantSettled(alive map[string]struct{}) int
}

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
	src          MetadataSource
	trie         kernelwriter.MapUpdateDeleter
	amphoraIPs   kernelwriter.MapUpdater
	meta         *metadata.ShardedMetadataMap
	macWriter    MacWriter
	routers      *metadata.RouterMACs
	settler      FlowSettler
	tun          *tunables.Store
	interner     *metadata.TenantInterner
	seq          *boot.Sequencer
	mx           *Metrics
	bpfGauge     MapGauge
	amphoraGauge AmphoraGauge
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
	Source MetadataSource
	Trie   kernelwriter.MapUpdateDeleter
	// AmphoraIPs writes the Octavia base-address set
	// (docs/architecture/octavia.md). Optional: nil skips the write, as
	// the trie-only unit tests do.
	AmphoraIPs kernelwriter.MapUpdater
	Meta       *metadata.ShardedMetadataMap
	MacWriter  MacWriter
	// Settler folds a MAC's flow rows to its old tenant before a
	// tenant reassignment replaces the binding. Optional (nil skips
	// the fold — trie-only unit tests); the agent wires its
	// *state.GlobalState.
	Settler  FlowSettler
	Interner *metadata.TenantInterner
	Seq      *boot.Sequencer
	Metrics  *Metrics
	// Routers is the router-interface-MAC → external-network map the
	// pass rebuilds and swaps (per-flow external attribution).
	// Optional (nil skips — trie-only unit tests); the agent wires the
	// store its Resolver reads.
	//
	// Billing tiers: docs/architecture/billing.md
	Routers *metadata.RouterMACs
	// BPFGauge refreshes the kernel map-fill gauges after each pass.
	// Optional (nil skips); the agent wires its bpf metrics bundle.
	BPFGauge MapGauge
	// AmphoraGauge republishes the Amphora re-attribution count each
	// pass. Optional; nil skips it.
	AmphoraGauge AmphoraGauge
	// Tunables supplies the live reconcile interval and ghost grace
	// (hot-reload; the interval applies at the next tick). REQUIRED —
	// operational knobs have exactly one source; unit tests construct
	// a store with the values they exercise.
	Tunables *tunables.Store
}

// New constructs a Reconciler from opts.
func New(opts Options) *Reconciler {
	return &Reconciler{
		src:          opts.Source,
		trie:         opts.Trie,
		amphoraIPs:   opts.AmphoraIPs,
		meta:         opts.Meta,
		macWriter:    opts.MacWriter,
		routers:      opts.Routers,
		settler:      opts.Settler,
		tun:          opts.Tunables,
		interner:     opts.Interner,
		seq:          opts.Seq,
		mx:           opts.Metrics,
		bpfGauge:     opts.BPFGauge,
		amphoraGauge: opts.AmphoraGauge,
		kick:         make(chan struct{}, 1),
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

// Run reconciles on each tick and on each [Reconciler.Kick] until ctx
// is cancelled — one applier goroutine for both, so passes never
// overlap. Blocks on [boot.PhaseStateRestored] first: a delta computed
// before cold-start committed the initial trie would be wrong. No
// immediate first pass; cold start already populated the trie.
func (r *Reconciler) Run(ctx context.Context) {
	if r.seq != nil {
		if err := r.seq.Await(ctx, boot.PhaseStateRestored); err != nil {
			slog.Info("reconciler stopping before first pass",
				"component", component, "err", err)
			return
		}
	}
	cur := r.intervalNow()
	t := time.NewTicker(cur)
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
		if next := r.intervalNow(); next != cur {
			t.Reset(next)
			cur = next
		}
	}
}

// intervalNow returns the live reconcile cadence. A hot change applies
// at the next tick (worst case one old interval of delay).
func (r *Reconciler) intervalNow() time.Duration {
	return r.tun.Get().ReconcileInterval
}

// reconcileOnce runs one full reconcile pass: fetch a fresh snapshot,
// apply the trie and mac_tenant_map deltas against current state, and
// commit on success. Orchestration only — each step records its own
// terminal outcome on lachesis_reconcile_runs_total and signals whether
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
	mac := r.reconcileMACs(&result.Snapshot, now)
	r.reconcileRouterMACs(&result.Snapshot)
	nAmp := r.reconcileAmphoraIPs(&result.Snapshot)

	r.src.Commit(result, now)
	r.mx.RecordRun(resultOK)
	r.pruneServerSettled(result.Snapshot.Servers)
	r.pruneTenantSettled(result.Snapshot.Projects)
	r.refreshMapGauges(len(result.Entries), nAmp)
	r.logOutcome(delta, mac, len(result.Ambiguities))
}

// pruneServerSettled releases buckets for servers gone from the Nova
// list. Skipped when the list is empty: a failed best-effort fetch is
// indistinguishable from a genuinely empty cloud, and pruning on
// missing data would end live servers' series.
func (r *Reconciler) pruneServerSettled(servers []neutron.Server) {
	if r.settler == nil || len(servers) == 0 {
		return
	}
	alive := make(map[string]struct{}, len(servers))
	for _, s := range servers {
		alive[s.ID] = struct{}{}
	}
	if dropped := r.settler.PruneServerSettled(alive); dropped > 0 {
		slog.Info("released server-settled buckets for dead servers",
			"component", component, "dropped", dropped, "servers_alive", len(alive))
	}
}

// pruneTenantSettled releases buckets for projects gone from Keystone,
// folding each into the total-settled absorber so the derived total
// never dips. metadata.UnknownTenantID joins alive explicitly — it is
// not a Keystone project and has none to die with.
func (r *Reconciler) pruneTenantSettled(projects []neutron.Project) {
	if r.settler == nil || len(projects) == 0 {
		return
	}
	alive := make(map[string]struct{}, len(projects)+1)
	for _, p := range projects {
		alive[p.ID] = struct{}{}
	}
	alive[metadata.UnknownTenantID] = struct{}{}
	if dropped := r.settler.PruneTenantSettled(alive); dropped > 0 {
		slog.Info("released tenant-settled buckets for deleted projects into the total absorber",
			"component", component, "dropped", dropped, "projects_alive", len(projects))
	}
}

// refreshMapGauges keeps lachesis_bpf_map_current_entries current after the
// incremental rewrite: cold-start sets it once, so without this the
// subnet_zone_trie and mac_tenant_map fill gauges drift as the reconcile
// changes them. trieRows is the committed trie size; the mac_tenant_map
// count tracks the userspace metadata map (kernel ⊆ userspace, and they
// converge). No-op when no gauge is wired (trie-only unit tests).
func (r *Reconciler) refreshMapGauges(trieRows, amphoraRows int) {
	if r.bpfGauge == nil {
		return
	}
	r.bpfGauge.SetCurrent(bpf.MapSubnetZoneTrie, float64(trieRows))
	if r.meta != nil {
		r.bpfGauge.SetCurrent(bpf.MapMacTenant, float64(r.meta.Len()))
	}
	if r.amphoraIPs != nil {
		r.bpfGauge.SetCurrent(bpf.MapAmphoraBaseIP, float64(amphoraRows))
	}
}

// reconcileAmphoraIPs re-asserts the Octavia base-address set so a load
// balancer created since the last cold start starts zoning its Segment-2
// traffic as infra (docs/architecture/octavia.md). Returns the row count
// for the fill gauge; 0 when no writer is wired.
//
// Insert-only, deliberately. A stale row costs a zone label on a MAC that
// no longer resolves — the flow misses mac_tenant_map first and never
// reaches the Amphora branch — whereas eagerly deleting risks dropping a
// live Amphora's address on a partial snapshot and re-billing Segment 2
// as tenant traffic. The set is small (bounded by load-balancer count)
// and rebuilt whole on the next agent boot.
func (r *Reconciler) reconcileAmphoraIPs(snap *neutron.Snapshot) int {
	if r.amphoraIPs == nil {
		return 0
	}
	n, err := kernelwriter.WriteAmphoraBaseIPs(r.amphoraIPs, neutron.AmphoraBaseIPs(snap), r.interner)
	if err != nil {
		slog.Warn("amphora_base_ip write failed; Segment-2 zoning stale until the next pass",
			"component", component, "err", err)
	}
	return n
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
