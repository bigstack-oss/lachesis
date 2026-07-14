package unresolved

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/bigstack-oss/lachesis/internal/bpf"
	"github.com/bigstack-oss/lachesis/internal/metadata"
	"github.com/bigstack-oss/lachesis/internal/state"
)

func newClassifier(t *testing.T) (*Classifier, *state.GlobalState, *metadata.ShardedMetadataMap, *Buffer) {
	t.Helper()
	st := state.New()
	meta := metadata.New()
	clk := &fakeClock{t: time.Unix(1000, 0)}
	buf := NewBuffer(Options{State: st, Evictor: &recordingEvictor{}, Metrics: NewMetrics(), TTL: time.Minute, Now: clk.now})
	return NewClassifier(st, meta, buf), st, meta, buf
}

// stateHas reports whether GlobalState holds key with a positive byte total.
func stateHas(st *state.GlobalState, key bpf.FlowKey) bool {
	return stateBytes(st, key) > 0
}

// stateBytes returns the byte total GlobalState holds for key, or 0.
func stateBytes(st *state.GlobalState, key bpf.FlowKey) uint64 {
	for _, e := range st.Snapshot(nil) {
		if e.Key == key {
			return e.Total.Bytes
		}
	}
	return 0
}

// TestClassifier_LateBindingResolvesToTenant exercises the full
// late-binding path: a flow buffered while its MAC is unknown is handed
// to the right tenant on the first drain after the MAC becomes known,
// with no double-count and without resetting the live kernel entry.
func TestClassifier_LateBindingResolvesToTenant(t *testing.T) {
	st := state.New()
	meta := metadata.New()
	mx := NewMetrics()
	ev := &recordingEvictor{}
	clk := &fakeClock{t: time.Unix(1000, 0)}
	buf := NewBuffer(Options{State: st, Evictor: ev, Metrics: mx, TTL: time.Minute, Now: clk.now})
	c := NewClassifier(st, meta, buf)

	key := flowKey(42, bpf.ZoneExternal, bpf.DirectionEgress)

	// Unknown MAC: two readings accumulate in the buffer (cumulative 1500).
	c.Absorb(key, bpf.FlowMetrics{Bytes: 1000, Packets: 5, LastSeenNs: 1})
	c.Absorb(key, bpf.FlowMetrics{Bytes: 1500, Packets: 8, LastSeenNs: 2})
	if buf.Len() != 1 {
		t.Fatalf("buffer len = %d, want 1", buf.Len())
	}
	if stateHas(st, key) {
		t.Fatal("unknown flow leaked into GlobalState before resolve")
	}

	// A reconcile / Kafka event makes the MAC known.
	meta.Insert(metadata.VMMAC(key), &metadata.TenantMeta{ProjectID: "tenant-late"})

	// First drain after the MAC is known: resolve + integrate current reading.
	c.Absorb(key, bpf.FlowMetrics{Bytes: 1800, Packets: 9, LastSeenNs: 3})

	if buf.Len() != 0 {
		t.Errorf("buffer not drained after resolve: len = %d", buf.Len())
	}
	if got := stateBytes(st, key); got != 1800 {
		t.Errorf("resolved total = %d bytes, want 1800 (full cumulative, no double-count)", got)
	}
	if n := testutil.ToFloat64(mx.resolved); n != 1 {
		t.Errorf("lachesis_unresolved_resolved_total = %v, want 1", n)
	}
	if len(ev.deleted) != 0 {
		t.Errorf("resolve reset the kernel entry (%d deletes); a resolved flow must keep counting", len(ev.deleted))
	}

	// Continued counting: a later reading adds only its delta, and the
	// resolved counter does not re-increment.
	c.Absorb(key, bpf.FlowMetrics{Bytes: 2000, Packets: 10, LastSeenNs: 4})
	if got := stateBytes(st, key); got != 2000 {
		t.Errorf("post-resolve total = %d bytes, want 2000", got)
	}
	if n := testutil.ToFloat64(mx.resolved); n != 1 {
		t.Errorf("resolved counter re-incremented = %v, want 1", n)
	}
}

func TestClassifier_KnownToStateUnknownToBuffer(t *testing.T) {
	c, st, meta, buf := newClassifier(t)

	known := flowKey(1, bpf.ZoneSameTenant, bpf.DirectionEgress) // VM MAC = DstMac
	unknown := flowKey(2, bpf.ZoneExternal, bpf.DirectionEgress)
	meta.Insert(metadata.VMMAC(known), &metadata.TenantMeta{ProjectID: "tenant-a"})

	c.Absorb(known, bpf.FlowMetrics{Bytes: 1000, Packets: 5, LastSeenNs: 1})
	c.Absorb(unknown, bpf.FlowMetrics{Bytes: 200, Packets: 2, LastSeenNs: 1})

	if !stateHas(st, known) {
		t.Error("known flow did not reach GlobalState")
	}
	if stateHas(st, unknown) {
		t.Error("unknown flow leaked into GlobalState instead of the buffer")
	}
	if buf.Len() != 1 {
		t.Errorf("buffer len = %d, want 1 (the unknown flow)", buf.Len())
	}
}

// TestClassifier_GhostRoutesToStateNotBuffer pins the ghost-precedence
// invariant (docs/DESIGN.md §3.3): a MAC marked for deletion is still a
// metadata hit until the GC sweeps it, so its dying-tail traffic must
// attribute to the ghosted tenant via GlobalState — never the
// UnresolvedBuffer. The test fails if the classifier's branches are
// inverted (buffer checked before, or instead of, the metadata lookup).
func TestClassifier_GhostRoutesToStateNotBuffer(t *testing.T) {
	c, st, meta, buf := newClassifier(t)

	ghost := flowKey(7, bpf.ZoneSameTenant, bpf.DirectionEgress)
	mac := metadata.VMMAC(ghost)
	meta.Insert(mac, &metadata.TenantMeta{ProjectID: "tenant-dying"})
	if !meta.MarkDelete(mac, time.Now().Add(60*time.Second)) { // ghosted, grace not elapsed
		t.Fatal("MarkDelete did not find the entry")
	}

	c.Absorb(ghost, bpf.FlowMetrics{Bytes: 4242, Packets: 7, LastSeenNs: 1})

	if !stateHas(st, ghost) {
		t.Error("ghosted flow did not reach GlobalState — ghost precedence over the buffer is broken")
	}
	if buf.Len() != 0 {
		t.Errorf("ghosted flow landed in the UnresolvedBuffer (len=%d) — branches inverted", buf.Len())
	}
}
