package reconcile

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bigstack-oss/lachesis/internal/bpf"
	"github.com/bigstack-oss/lachesis/internal/metadata"
	"github.com/bigstack-oss/lachesis/internal/neutron"
	"github.com/bigstack-oss/lachesis/internal/tunables"
)

// debounceRig runs a Reconciler whose timer never fires (1h interval),
// so every commit it counts came from a kick.
type debounceRig struct {
	r       *Reconciler
	mx      *Metrics
	commits atomic.Int64
	cancel  context.CancelFunc
	done    chan struct{}
}

func startDebounceRig(t *testing.T, window, maxWait time.Duration) *debounceRig {
	t.Helper()
	rig := &debounceRig{mx: NewMetrics(), done: make(chan struct{})}
	src := &fakeSrc{
		syncResult: neutron.SyncResult{Entries: []neutron.TrieEntry{
			te("A", "10.0.0.0/24", bpf.ZoneSameTenant),
		}},
		onCommit: func() { rig.commits.Add(1) },
	}
	rig.r = New(Options{
		Source:   src,
		Trie:     &fakeMap{},
		Interner: metadata.NewTenantInterner(),
		Metrics:  rig.mx,
		Tunables: tunables.New(tunables.Values{ReconcileInterval: time.Hour, GhostGrace: 60 * time.Second, KickDebounce: window}),
	})
	if maxWait > 0 {
		rig.r.maxWait = maxWait
	}
	ctx, cancel := context.WithCancel(context.Background())
	rig.cancel = cancel
	go func() { rig.r.Run(ctx); close(rig.done) }()
	t.Cleanup(rig.stop)
	return rig
}

func (rig *debounceRig) stop() {
	rig.cancel()
	<-rig.done
}

// waitCommits polls until at least n commits happened or d elapses.
func (rig *debounceRig) waitCommits(n int64, d time.Duration) bool {
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if rig.commits.Load() >= n {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return rig.commits.Load() >= n
}

// TestRun_DebounceFoldsBurstIntoOnePass: kicks arriving closer together
// than the window keep restarting it, so the whole burst costs one pass.
func TestRun_DebounceFoldsBurstIntoOnePass(t *testing.T) {
	rig := startDebounceRig(t, 100*time.Millisecond, 0)
	for range 10 {
		rig.r.Kick()
		time.Sleep(10 * time.Millisecond)
	}
	if !rig.waitCommits(1, 2*time.Second) {
		t.Fatal("burst never reconciled")
	}
	time.Sleep(300 * time.Millisecond) // room for a wrong second pass
	rig.stop()
	if got := rig.commits.Load(); got != 1 {
		t.Errorf("passes = %d, want 1 for one burst", got)
	}
	if got := passCount(t, rig.mx, triggerKick); got != 1 {
		t.Errorf("trigger=kick passes = %d, want 1", got)
	}
}

// TestRun_DebounceSparseKicksEachReconcile: kicks further apart than
// the window each get their own pass — steady-state changes stay prompt.
func TestRun_DebounceSparseKicksEachReconcile(t *testing.T) {
	tests := []struct {
		name   string
		window time.Duration
	}{
		{"debounce off", 0},
		{"debounce on", 50 * time.Millisecond},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rig := startDebounceRig(t, tc.window, 0)
			for i := int64(1); i <= 3; i++ {
				rig.r.Kick()
				if !rig.waitCommits(i, 2*time.Second) {
					t.Fatalf("kick %d did not reconcile", i)
				}
			}
		})
	}
}

// TestRun_DebounceMaxWaitBoundsSteadyStream: a stream of kicks that
// never leaves a quiet window still reconciles every maxWait.
func TestRun_DebounceMaxWaitBoundsSteadyStream(t *testing.T) {
	rig := startDebounceRig(t, 200*time.Millisecond, 300*time.Millisecond)
	start := time.Now()
	var firstAt time.Duration
	for time.Since(start) < time.Second {
		rig.r.Kick()
		if firstAt == 0 && rig.commits.Load() > 0 {
			firstAt = time.Since(start)
		}
		time.Sleep(50 * time.Millisecond)
	}
	rig.stop()
	if firstAt == 0 || firstAt > 700*time.Millisecond {
		t.Errorf("first pass at %v, want within ~maxWait (300ms) of the first kick", firstAt)
	}
	if got := rig.commits.Load(); got < 2 {
		t.Errorf("passes = %d over 1s of kicks, want >= 2 with a 300ms max-wait", got)
	}
}
