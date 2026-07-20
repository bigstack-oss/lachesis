//go:build linux && integration

package agent

import (
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/bigstack-oss/lachesis/internal/bpf"
	"github.com/bigstack-oss/lachesis/internal/config"
)

// These tests prove the #83 zero-loss-recovery contract at the kernel
// boundary: loadCollection pins the counter-bearing maps, reuses a
// compatible pin across a "crash" (collection Close), refuses to adopt a
// wrong-sized stale pin, and honours the strict/unsafe fork when pinning
// is unavailable. They mount a hermetic bpffs so they neither depend on
// nor pollute the host's /sys/fs/bpf.

// mountBPFFS mounts a fresh bpf filesystem at a temp dir and returns a
// pin directory under it. The unmount is registered before t.TempDir's
// own removal cleanup, so it runs first (cleanups are LIFO).
func mountBPFFS(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := unix.Mount("bpf", dir, "bpf", 0, ""); err != nil {
		t.Fatalf("mount bpffs at %s: %v (needs a privileged container)", dir, err)
	}
	t.Cleanup(func() { _ = unix.Unmount(dir, 0) })
	return filepath.Join(dir, "telemetry")
}

// putSentinel writes a one-CPU sentinel counter into the PERCPU_HASH
// telemetry_map under key, and returns the key it used.
func putSentinel(t *testing.T, m *ebpf.Map, bytes uint64) bpf.FlowKey {
	t.Helper()
	key := bpf.FlowKey{
		SrcMac:    [6]uint8{0xaa, 0, 0, 0, 0, 1},
		DstMac:    [6]uint8{0xbb, 0, 0, 0, 0, 2},
		EthProto:  0x0800,
		Direction: bpf.DirectionIngress,
		DstZone:   bpf.ZoneSameTenant,
	}
	n, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatalf("PossibleCPU: %v", err)
	}
	vals := make([]bpf.FlowMetrics, n)
	vals[0] = bpf.FlowMetrics{Bytes: bytes, Packets: 1, LastSeenNs: 1}
	if err := m.Put(&key, vals); err != nil {
		t.Fatalf("put sentinel: %v", err)
	}
	return key
}

// sumBytes reads key from a PERCPU_HASH telemetry_map and sums Bytes
// across all CPUs.
func sumBytes(t *testing.T, m *ebpf.Map, key bpf.FlowKey) uint64 {
	t.Helper()
	var got []bpf.FlowMetrics
	if err := m.Lookup(&key, &got); err != nil {
		t.Fatalf("lookup sentinel: %v", err)
	}
	var total uint64
	for _, v := range got {
		total += v.Bytes
	}
	return total
}

// TestLoadCollection_PinnedMapSurvivesReload is the agent-crash path:
// the counters written before the collection Close are still there when
// a second load reuses the pinned map — the zero-loss guarantee.
func TestLoadCollection_PinnedMapSurvivesReload(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock: %v", err)
	}
	cfg := config.BPFConfig{PinPath: mountBPFFS(t)}

	coll, pinned, err := loadCollection(cfg)
	if err != nil {
		t.Fatalf("first loadCollection: %v", err)
	}
	if !pinned {
		t.Fatalf("first load: pinned=false, want true")
	}
	key := putSentinel(t, coll.Maps[bpf.MapTelemetry], 4242)
	coll.Close() // process "crash": fds released, bpffs pins remain

	coll2, pinned2, err := loadCollection(cfg)
	if err != nil {
		t.Fatalf("second loadCollection: %v", err)
	}
	defer coll2.Close()
	if !pinned2 {
		t.Fatalf("second load: pinned=false, want true (reuse)")
	}
	if got := sumBytes(t, coll2.Maps[bpf.MapTelemetry], key); got != 4242 {
		t.Errorf("counter did not survive reload: got %d bytes, want 4242", got)
	}
}

// TestLoadCollection_RefusesStalePinWrongSizing proves contract 7's
// refuse-to-reuse: a pin whose max_entries no longer matches the build
// is never adopted; it is removed and recreated fresh (self-heal), so
// the reloaded map has the spec sizing and none of the stale data.
func TestLoadCollection_RefusesStalePinWrongSizing(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock: %v", err)
	}
	pinDir := mountBPFFS(t)

	// Hand-pin a telemetry_map with the WRONG max_entries under pinDir,
	// standing in for a pin left by an older build with a different ABI.
	spec, err := bpf.LoadTelemetry()
	if err != nil {
		t.Fatalf("LoadTelemetry: %v", err)
	}
	if err := unix.Mkdir(pinDir, 0o700); err != nil {
		t.Fatalf("mkdir pin dir: %v", err)
	}
	stale := spec.Maps[bpf.MapTelemetry].Copy()
	stale.MaxEntries = bpf.MapTelemetryMaxEntries / 2
	staleMap, err := ebpf.NewMap(stale)
	if err != nil {
		t.Fatalf("new stale map: %v", err)
	}
	if err := staleMap.Pin(filepath.Join(pinDir, bpf.MapTelemetry)); err != nil {
		t.Fatalf("pin stale map: %v", err)
	}
	staleMap.Close()

	// The production loader must refuse the stale pin, self-heal, pin fresh.
	coll, pinned, err := loadCollection(config.BPFConfig{PinPath: pinDir})
	if err != nil {
		t.Fatalf("loadCollection should self-heal past a stale pin, got: %v", err)
	}
	defer coll.Close()
	if !pinned {
		t.Fatalf("pinned=false after self-heal, want true")
	}
	if got := coll.Maps[bpf.MapTelemetry].MaxEntries(); got != bpf.MapTelemetryMaxEntries {
		t.Errorf("reused stale pin: MaxEntries=%d, want fresh spec-sized %d",
			got, bpf.MapTelemetryMaxEntries)
	}
}

// TestLoadCollection_PinningUnavailable exercises the strict/unsafe fork
// via a pin_path on a regular (non-bpf) filesystem, where the pin syscall
// fails: strict mode refuses to boot; the unsafe toggle boots unpinned.
func TestLoadCollection_PinningUnavailable(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock: %v", err)
	}
	// t.TempDir is a regular fs, not bpffs — MkdirAll succeeds but Pin fails.
	pinDir := filepath.Join(t.TempDir(), "telemetry")

	if _, _, err := loadCollection(config.BPFConfig{PinPath: pinDir}); err == nil {
		t.Fatalf("strict mode should refuse to boot when pinning is unavailable")
	}

	coll, pinned, err := loadCollection(config.BPFConfig{
		PinPath:                 pinDir,
		UnsafeAllowUnpinnedMaps: true,
	})
	if err != nil {
		t.Fatalf("unsafe fallback should boot unpinned: %v", err)
	}
	defer coll.Close()
	if pinned {
		t.Fatalf("pinned=true in the unpinned fallback, want false")
	}
}
