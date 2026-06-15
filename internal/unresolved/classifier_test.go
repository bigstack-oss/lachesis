package unresolved

import (
	"testing"
	"time"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/metadata"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/state"
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
	for _, e := range st.Snapshot(nil) {
		if e.Key == key && e.Total.Bytes > 0 {
			return true
		}
	}
	return false
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
