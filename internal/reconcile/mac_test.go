package reconcile

import (
	"net"
	"testing"
	"time"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/metadata"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/neutron"
)

// fakeMacWriter records the kernel mac_tenant_map upserts the reconcile
// worker issues.
type fakeMacWriter struct {
	updates map[uint64]uint32
}

func (f *fakeMacWriter) Update(mac uint64, tenantID uint32) error {
	if f.updates == nil {
		f.updates = make(map[uint64]uint32)
	}
	f.updates[mac] = tenantID
	return nil
}

// mac parses a MAC string into the uint64 key the metadata map uses,
// matching bpf.MACKey / desiredMACs.
func mac(t *testing.T, s string) uint64 {
	t.Helper()
	hw, err := net.ParseMAC(s)
	if err != nil {
		t.Fatalf("ParseMAC(%q): %v", s, err)
	}
	var key [6]uint8
	copy(key[:], hw)
	return bpf.MACKey(key)
}

func vmPort(macStr, projectID string) neutron.Port {
	return neutron.Port{MACAddress: macStr, ProjectID: projectID, DeviceOwner: "compute:nova"}
}

func newMacReconciler(meta *metadata.ShardedMetadataMap, mw MacWriter) *Reconciler {
	return New(Options{
		Meta:      meta,
		MacWriter: mw,
		Interner:  metadata.NewTenantInterner(),
		Metrics:   NewMetrics(),
	})
}

func TestDesiredMACs_AdmitsOnlyVMPorts(t *testing.T) {
	ports := []neutron.Port{
		vmPort("aa:bb:cc:00:00:01", "proj-a"),
		{MACAddress: "aa:bb:cc:00:00:02", ProjectID: "proj-b", DeviceOwner: "network:router_interface"}, // infra
		{MACAddress: "", ProjectID: "proj-c", DeviceOwner: "compute:nova"},                              // no MAC
		{MACAddress: "aa:bb:cc:00:00:04", ProjectID: "", DeviceOwner: "compute:nova"},                   // no project
		{MACAddress: "not-a-mac", ProjectID: "proj-e", DeviceOwner: "compute:nova"},                     // bad MAC
	}
	got := desiredMACs(ports)
	if len(got) != 1 {
		t.Fatalf("desiredMACs admitted %d, want 1: %v", len(got), got)
	}
	if got[mac(t, "aa:bb:cc:00:00:01")] != "proj-a" {
		t.Errorf("admitted VM port maps to %q, want proj-a", got[mac(t, "aa:bb:cc:00:00:01")])
	}
}

// TestReconcileMACs_LearnsNewGhostsGone is the core diff: a new port is
// learned (userspace + kernel), a vanished port is ghosted (MarkDelete,
// not deleted, kernel untouched), and an unchanged port is left alone.
func TestReconcileMACs_LearnsNewGhostsGone(t *testing.T) {
	meta := metadata.New()
	keep := mac(t, "aa:00:00:00:00:01")
	gone := mac(t, "aa:00:00:00:00:02")
	meta.Insert(keep, &metadata.TenantMeta{ProjectID: "proj-keep"})
	meta.Insert(gone, &metadata.TenantMeta{ProjectID: "proj-gone"})

	mw := &fakeMacWriter{}
	r := newMacReconciler(meta, mw)
	now := time.Unix(2000, 0)

	d := r.reconcileMACs([]neutron.Port{
		vmPort("aa:00:00:00:00:01", "proj-keep"), // unchanged
		vmPort("aa:00:00:00:00:03", "proj-new"),  // new
	}, now)

	if d != (macDelta{Inserted: 1, Ghosted: 1}) {
		t.Fatalf("macDelta = %+v, want {Inserted:1 Ghosted:1}", d)
	}
	// New MAC learned in userspace + kernel.
	newMac := mac(t, "aa:00:00:00:00:03")
	if cur, ok := meta.Lookup(newMac); !ok || cur.ProjectID != "proj-new" {
		t.Errorf("new MAC not inserted in userspace: %v %v", cur, ok)
	}
	if _, ok := mw.updates[newMac]; !ok {
		t.Error("new MAC not written to the kernel mac_tenant_map")
	}
	// Gone MAC ghosted, not deleted; kernel not touched for it.
	cur, ok := meta.Lookup(gone)
	if !ok || cur.DeleteAt.IsZero() {
		t.Error("gone MAC should be ghosted (present with DeleteAt set), not deleted")
	}
	if !cur.DeleteAt.Equal(now.Add(metadata.GhostGrace)) {
		t.Errorf("ghost DeleteAt = %v, want now+GhostGrace", cur.DeleteAt)
	}
	if _, ok := mw.updates[gone]; ok {
		t.Error("gone MAC must not be written to the kernel (ghost = userspace-only)")
	}
	// Unchanged MAC not re-written.
	if _, ok := mw.updates[keep]; ok {
		t.Error("unchanged MAC was re-written to the kernel")
	}
}

// TestReconcileMACs_ChangedAndResurrected covers a tenant reassignment
// and a ghost coming back within its grace.
func TestReconcileMACs_ChangedAndResurrected(t *testing.T) {
	meta := metadata.New()
	changed := mac(t, "bb:00:00:00:00:01")
	ghost := mac(t, "bb:00:00:00:00:02")
	meta.Insert(changed, &metadata.TenantMeta{ProjectID: "old"})
	meta.Insert(ghost, &metadata.TenantMeta{ProjectID: "proj-z"})
	meta.MarkDelete(ghost, time.Unix(1000, 0)) // ghosted

	mw := &fakeMacWriter{}
	r := newMacReconciler(meta, mw)

	d := r.reconcileMACs([]neutron.Port{
		vmPort("bb:00:00:00:00:01", "new"),    // tenant reassigned
		vmPort("bb:00:00:00:00:02", "proj-z"), // ghost resurrected
	}, time.Unix(2000, 0))

	if d != (macDelta{Changed: 2}) {
		t.Fatalf("macDelta = %+v, want {Changed:2}", d)
	}
	if cur, _ := meta.Lookup(changed); cur.ProjectID != "new" {
		t.Errorf("changed MAC project = %q, want new", cur.ProjectID)
	}
	if cur, _ := meta.Lookup(ghost); !cur.DeleteAt.IsZero() {
		t.Error("resurrected MAC still ghosted (DeleteAt not cleared)")
	}
	if _, ok := mw.updates[changed]; !ok {
		t.Error("changed MAC not re-written to the kernel")
	}
}

// TestReconcileMACs_TenantChangeIsPointerReplace hardens Implementation
// Contract #3 for the reconcile path: a tenant reassignment must replace
// the *TenantMeta pointer, never mutate a stored one in place. Two MACs
// share one pointer (the contract permits this), and a hot-path reader
// holds it; reassigning one MAC must leave the held pointer — and the
// other MAC — untouched. (The static-lint detection lands in Sprint 9;
// this is the behavioral guard.)
func TestReconcileMACs_TenantChangeIsPointerReplace(t *testing.T) {
	meta := metadata.New()
	m1 := mac(t, "dd:00:00:00:00:01")
	m2 := mac(t, "dd:00:00:00:00:02")
	shared := &metadata.TenantMeta{ProjectID: "old"}
	meta.Insert(m1, shared)
	meta.Insert(m2, shared) // one VM, two ports → one shared pointer (DESIGN §3.2)

	captured, _ := meta.Lookup(m1) // a scrape holding the pointer

	r := newMacReconciler(meta, &fakeMacWriter{})
	r.reconcileMACs([]neutron.Port{
		vmPort("dd:00:00:00:00:01", "new"), // m1 reassigned
		vmPort("dd:00:00:00:00:02", "old"), // m2 unchanged
	}, time.Unix(2000, 0))

	if captured.ProjectID != "old" {
		t.Fatalf("reconcile mutated a shared TenantMeta in place: ProjectID=%q (Contract #3 violated)", captured.ProjectID)
	}
	n1, _ := meta.Lookup(m1)
	if n1 == captured {
		t.Fatal("reconcile reused the prior pointer for the reassigned MAC; want pointer-replace")
	}
	if n1.ProjectID != "new" {
		t.Errorf("reassigned m1 ProjectID = %q, want new", n1.ProjectID)
	}
	if n2, _ := meta.Lookup(m2); n2.ProjectID != "old" {
		t.Errorf("unchanged m2 ProjectID = %q, want old", n2.ProjectID)
	}
}

// TestReconcileMACs_NilSkips confirms the MAC reconcile is optional: a
// reconciler with no metadata map / kernel writer (trie-only tests) does
// nothing rather than panicking.
func TestReconcileMACs_NilSkips(t *testing.T) {
	r := New(Options{Interner: metadata.NewTenantInterner(), Metrics: NewMetrics()})
	if d := r.reconcileMACs([]neutron.Port{vmPort("cc:00:00:00:00:01", "p")}, time.Unix(2000, 0)); d != (macDelta{}) {
		t.Errorf("nil MAC reconcile returned %+v, want zero", d)
	}
}
