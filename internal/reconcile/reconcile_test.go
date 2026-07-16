package reconcile

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/bigstack-oss/lachesis/internal/boot"
	"github.com/bigstack-oss/lachesis/internal/bpf"
	"github.com/bigstack-oss/lachesis/internal/metadata"
	"github.com/bigstack-oss/lachesis/internal/neutron"
	"github.com/bigstack-oss/lachesis/internal/tunables"
)

// fakeMap is a kernelwriter.MapUpdateDeleter that counts operations and,
// when failUpdate is set, fails the first Update so the apply-error path
// can be exercised.
type fakeMap struct {
	updates    int
	deletes    int
	failUpdate bool
}

func (f *fakeMap) Update(k, v any, flags ebpf.MapUpdateFlags) error {
	if f.failUpdate {
		return errors.New("kernel ENOMEM")
	}
	f.updates++
	return nil
}

func (f *fakeMap) Delete(k any) error {
	f.deletes++
	return nil
}

// fakeSrc is a MetadataSource backed by canned values. onCommit, when
// set, fires on each Commit so a Run test can observe a pass without a
// fixed sleep.
type fakeSrc struct {
	syncResult neutron.SyncResult
	syncErr    error
	trie       []neutron.TrieEntry
	commits    int
	onCommit   func()
}

func (f *fakeSrc) Sync(ctx context.Context) (neutron.SyncResult, error) {
	return f.syncResult, f.syncErr
}
func (f *fakeSrc) Trie() []neutron.TrieEntry { return f.trie }
func (f *fakeSrc) Commit(result neutron.SyncResult, at time.Time) {
	f.commits++
	if f.onCommit != nil {
		f.onCommit()
	}
}

func te(tenant, cidr string, zone bpf.ZoneCode) neutron.TrieEntry {
	return neutron.TrieEntry{TenantID: tenant, Prefix: netip.MustParsePrefix(cidr), Zone: zone}
}

// newReconciler builds a Reconciler over the fakes with no boot barrier
// (Seq nil) so reconcileOnce can be driven directly.
func newReconciler(src MetadataSource, trie *fakeMap) (*Reconciler, *Metrics) {
	mx := NewMetrics()
	r := New(Options{
		Source:   src,
		Trie:     trie,
		Interner: metadata.NewTenantInterner(),
		Metrics:  mx,
	})
	return r, mx
}

func runResult(t *testing.T, mx *Metrics, result string) float64 {
	t.Helper()
	return testutil.ToFloat64(mx.runs.WithLabelValues(result))
}

func TestReconcileOnce_AppliesDeltaAndCommits(t *testing.T) {
	src := &fakeSrc{
		trie: nil, // empty committed trie
		syncResult: neutron.SyncResult{Entries: []neutron.TrieEntry{
			te("A", "10.0.0.0/24", bpf.ZoneSameTenant),
			te("", "0.0.0.0/0", bpf.ZoneExternal),
		}},
	}
	fm := &fakeMap{}
	r, mx := newReconciler(src, fm)

	r.reconcileOnce(context.Background(), time.Unix(1000, 0))

	if fm.updates != 2 || fm.deletes != 0 {
		t.Errorf("kernel ops = %d updates / %d deletes, want 2/0", fm.updates, fm.deletes)
	}
	if src.commits != 1 {
		t.Errorf("commits = %d, want 1", src.commits)
	}
	if got := runResult(t, mx, resultOK); got != 1 {
		t.Errorf("result=ok counter = %v, want 1", got)
	}
}

func TestReconcileOnce_SyncErrorSkipsApplyAndCommit(t *testing.T) {
	src := &fakeSrc{syncErr: errors.New("neutron 503")}
	fm := &fakeMap{}
	r, mx := newReconciler(src, fm)

	r.reconcileOnce(context.Background(), time.Unix(1000, 0))

	if fm.updates != 0 || fm.deletes != 0 {
		t.Errorf("kernel touched on sync error: %d updates / %d deletes", fm.updates, fm.deletes)
	}
	if src.commits != 0 {
		t.Errorf("committed on sync error: commits = %d, want 0", src.commits)
	}
	if got := runResult(t, mx, resultSyncError); got != 1 {
		t.Errorf("result=sync_error counter = %v, want 1", got)
	}
}

// TestReconcileOnce_ApplyErrorSkipsCommit locks the retry-safety rule:
// a kernel-apply failure must NOT commit, so the next pass re-diffs
// against the same prior state and retries.
func TestReconcileOnce_ApplyErrorSkipsCommit(t *testing.T) {
	src := &fakeSrc{
		syncResult: neutron.SyncResult{Entries: []neutron.TrieEntry{
			te("A", "10.0.0.0/24", bpf.ZoneSameTenant),
		}},
	}
	fm := &fakeMap{failUpdate: true}
	r, mx := newReconciler(src, fm)

	r.reconcileOnce(context.Background(), time.Unix(1000, 0))

	if src.commits != 0 {
		t.Errorf("committed despite apply error: commits = %d, want 0", src.commits)
	}
	if got := runResult(t, mx, resultApplyError); got != 1 {
		t.Errorf("result=apply_error counter = %v, want 1", got)
	}
}

// TestReconcileOnce_DeltaAgainstOld confirms the new snapshot is diffed
// against the committed trie, not pushed wholesale: a row that vanished
// is deleted.
func TestReconcileOnce_DeltaAgainstOld(t *testing.T) {
	src := &fakeSrc{
		trie:       []neutron.TrieEntry{te("A", "10.9.0.0/24", bpf.ZoneInfra)}, // committed
		syncResult: neutron.SyncResult{Entries: nil},                           // A removed
	}
	fm := &fakeMap{}
	r, _ := newReconciler(src, fm)

	r.reconcileOnce(context.Background(), time.Unix(1000, 0))

	if fm.updates != 0 || fm.deletes != 1 {
		t.Errorf("kernel ops = %d updates / %d deletes, want 0/1 (A removed)", fm.updates, fm.deletes)
	}
	if src.commits != 1 {
		t.Errorf("commits = %d, want 1", src.commits)
	}
}

// TestRun_AwaitsStateRestored proves Run does not reconcile before the
// boot barrier: a sequencer stuck at PhaseInit plus a cancelled ctx
// makes Run return without a single pass.
func TestRun_AwaitsStateRestored(t *testing.T) {
	src := &fakeSrc{}
	fm := &fakeMap{}
	mx := NewMetrics()
	r := New(Options{
		Source:   src,
		Trie:     fm,
		Interner: metadata.NewTenantInterner(),
		Seq:      boot.New(), // PhaseInit; never advanced
		Metrics:  mx,
		Tunables: tunables.New(tunables.Values{ReconcileInterval: time.Millisecond, GhostGrace: 60 * time.Second}),
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Await returns ctx.Err immediately
	r.Run(ctx)

	if src.commits != 0 {
		t.Errorf("reconciled before PhaseStateRestored: commits = %d, want 0", src.commits)
	}
}

// TestKick_TriggersReconcilePass proves a Kick runs a pass out of band:
// with a long interval (so the timer never fires) the only way a commit
// happens is the kick.
func TestKick_TriggersReconcilePass(t *testing.T) {
	committed := make(chan struct{}, 1)
	src := &fakeSrc{
		syncResult: neutron.SyncResult{Entries: []neutron.TrieEntry{
			te("A", "10.0.0.0/24", bpf.ZoneSameTenant),
		}},
		onCommit: func() {
			select {
			case committed <- struct{}{}:
			default:
			}
		},
	}
	r := New(Options{
		Source:   src,
		Trie:     &fakeMap{},
		Interner: metadata.NewTenantInterner(),
		Metrics:  NewMetrics(),
		Tunables: tunables.New(tunables.Values{ReconcileInterval: time.Hour, GhostGrace: 60 * time.Second}), // timer must not fire; only the kick should
	})

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() { r.Run(ctx); close(runDone) }()

	r.Kick()
	select {
	case <-committed:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("kick did not trigger a reconcile pass")
	}
	cancel()
	select {
	case <-runDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit after cancel")
	}
}

// TestKick_NonBlockingWhenPending confirms Kick never blocks, even with a
// full buffer and no draining Run — the coalescing default branch.
func TestKick_NonBlockingWhenPending(t *testing.T) {
	r := New(Options{
		Source: &fakeSrc{}, Trie: &fakeMap{},
		Interner: metadata.NewTenantInterner(), Metrics: NewMetrics(), Tunables: tunables.New(tunables.Values{ReconcileInterval: time.Hour, GhostGrace: 60 * time.Second}),
	})
	done := make(chan struct{})
	go func() {
		r.Kick()
		r.Kick() // buffer already full → must take the default branch
		r.Kick()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Kick blocked when a kick was already pending")
	}
}

// TestRun_ReconcilesOnTick drives the full loop: with the barrier
// satisfied (Seq nil) and a short interval, Run reconciles on the tick
// and exits cleanly on cancel.
func TestRun_ReconcilesOnTick(t *testing.T) {
	committed := make(chan struct{}, 1)
	src := &fakeSrc{
		syncResult: neutron.SyncResult{Entries: []neutron.TrieEntry{
			te("A", "10.0.0.0/24", bpf.ZoneSameTenant),
		}},
		onCommit: func() {
			select {
			case committed <- struct{}{}:
			default:
			}
		},
	}
	fm := &fakeMap{}
	r := New(Options{
		Source:   src,
		Trie:     fm,
		Interner: metadata.NewTenantInterner(),
		Metrics:  NewMetrics(),
		Tunables: tunables.New(tunables.Values{ReconcileInterval: 5 * time.Millisecond, GhostGrace: 60 * time.Second}),
	})

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() { r.Run(ctx); close(runDone) }()

	select {
	case <-committed:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("no reconcile within 2s")
	}
	cancel()
	select {
	case <-runDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit after cancel")
	}
}
