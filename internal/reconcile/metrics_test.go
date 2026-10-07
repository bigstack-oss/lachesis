package reconcile

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"

	"github.com/bigstack-oss/lachesis/internal/bpf"
	"github.com/bigstack-oss/lachesis/internal/metadata"
	"github.com/bigstack-oss/lachesis/internal/neutron"
	"github.com/bigstack-oss/lachesis/internal/tunables"
)

// TestKick_CountsQueuedAndCoalesced: with no Run draining the channel,
// the first kick fills it and every later one coalesces.
func TestKick_CountsQueuedAndCoalesced(t *testing.T) {
	tests := []struct {
		name          string
		kicks         int
		wantQueued    int
		wantCoalesced int
	}{
		{"none", 0, 0, 0},
		{"one", 1, 1, 0},
		{"burst", 5, 1, 4},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mx := NewMetrics()
			r := New(Options{Source: &fakeSrc{}, Trie: &fakeMap{}, Interner: metadata.NewTenantInterner(), Metrics: mx})
			for range tc.kicks {
				r.Kick()
			}
			reg := prometheus.NewPedanticRegistry()
			reg.MustRegister(mx.kicks)
			want := `
# HELP lachesis_reconcile_kicks_total Kafka-driven reconcile kicks: queued = started a pass; coalesced = a pass was already pending, so the kick was folded into it.
# TYPE lachesis_reconcile_kicks_total counter
lachesis_reconcile_kicks_total{result="coalesced"} ` + strconv.Itoa(tc.wantCoalesced) + `
lachesis_reconcile_kicks_total{result="queued"} ` + strconv.Itoa(tc.wantQueued) + `
`
			if err := testutil.GatherAndCompare(reg, strings.NewReader(want), "lachesis_reconcile_kicks_total"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestRun_ObservesPassDurationByTrigger: a kick-started pass is timed
// under trigger="kick" and nothing lands under "tick" while the timer
// cannot fire.
func TestRun_ObservesPassDurationByTrigger(t *testing.T) {
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
	mx := NewMetrics()
	r := New(Options{
		Source:   src,
		Trie:     &fakeMap{},
		Interner: metadata.NewTenantInterner(),
		Metrics:  mx,
		Tunables: tunables.New(tunables.Values{ReconcileInterval: time.Hour, GhostGrace: 60 * time.Second}),
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
	case <-runDone: // the pass's observation precedes Run's return
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit after cancel")
	}

	if got := passCount(t, mx, triggerKick); got != 1 {
		t.Errorf("trigger=kick sample count = %d, want 1", got)
	}
	if got := passCount(t, mx, triggerTick); got != 0 {
		t.Errorf("trigger=tick sample count = %d, want 0", got)
	}
}

func passCount(t *testing.T, mx *Metrics, trigger string) uint64 {
	t.Helper()
	var m dto.Metric
	if err := mx.duration.WithLabelValues(trigger).(prometheus.Histogram).Write(&m); err != nil {
		t.Fatal(err)
	}
	return m.GetHistogram().GetSampleCount()
}
