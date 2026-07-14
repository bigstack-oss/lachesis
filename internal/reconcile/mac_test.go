package reconcile

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/bigstack-oss/lachesis/internal/bpf"
	"github.com/bigstack-oss/lachesis/internal/metadata"
	"github.com/bigstack-oss/lachesis/internal/neutron"
	"github.com/bigstack-oss/lachesis/internal/state"
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

// TestReconcileMACs_TenantChangeSettlesOldTenant locks the tenant-change
// half of the settled-bytes fold (docs/DESIGN.md §3.5): re-pointing a
// live MAC at a new tenant first settles the MAC's accumulated flows
// under the OLD tenant, and — because the port's kernel counters keep
// running — the rows survive with their delta watermark intact, so the
// next drain credits only post-fold bytes (which late-bind to the new
// tenant). Without the fold the whole history would re-attribute.
func TestReconcileMACs_TenantChangeSettlesOldTenant(t *testing.T) {
	meta := metadata.New()
	macStr := "cc:00:00:00:00:01"
	m := mac(t, macStr)
	meta.Insert(m, &metadata.TenantMeta{ProjectID: "proj-old"})

	var vmMAC [6]uint8
	hw, _ := net.ParseMAC(macStr)
	copy(vmMAC[:], hw)
	key := bpf.FlowKey{SrcMac: vmMAC, DstMac: [6]uint8{0xee, 0, 0, 0, 0, 9},
		EthProto: 0x0800, Direction: bpf.DirectionIngress, DstZone: bpf.ZoneSameTenant}

	st := state.New()
	st.ApplyDelta(key, bpf.FlowMetrics{Bytes: 100, Packets: 4, LastSeenNs: 1})

	r := New(Options{
		Meta:      meta,
		MacWriter: &fakeMacWriter{},
		Settler:   st,
		Interner:  metadata.NewTenantInterner(),
		Metrics:   NewMetrics(),
	})
	d := r.reconcileMACs([]neutron.Port{vmPort(macStr, "proj-new")}, time.Unix(2000, 0))
	if d != (macDelta{Changed: 1}) {
		t.Fatalf("macDelta = %+v, want {Changed:1}", d)
	}

	flows, settled := st.SnapshotWithSettled(nil, nil)
	wantKey := state.SettledKey{Tenant: "proj-old", Zone: bpf.ZoneSameTenant, Dir: bpf.DirectionIngress}
	if len(settled) != 1 || settled[0].Key != wantKey || settled[0].Bytes != 100 {
		t.Fatalf("settled = %+v, want 100 bytes under %+v", settled, wantKey)
	}
	// The row survives (SettleRebase), zeroed: the kernel counters are
	// still live, so eviction would make the next drain re-count the
	// full kernel cumulative as first sight.
	if len(flows) != 1 || flows[0].Key != key || flows[0].Total.Bytes != 0 {
		t.Fatalf("flows = %+v, want the row kept with Total zeroed", flows)
	}
	// Next drain: kernel cumulative moved 100→130; only the 30 new
	// bytes may accrue (and will late-bind to proj-new at scrape).
	st.ApplyDelta(key, bpf.FlowMetrics{Bytes: 130, Packets: 5, LastSeenNs: 2})
	flows, settled = st.SnapshotWithSettled(nil, nil)
	if flows[0].Total.Bytes != 30 {
		t.Errorf("post-fold delta = %d bytes, want 30 (old cumulative must not replay)", flows[0].Total.Bytes)
	}
	if settled[0].Bytes != 100 {
		t.Errorf("settled bytes = %d, want 100 (unchanged by later drains)", settled[0].Bytes)
	}
}

// TestReconcileMACs_ResurrectedSameTenantDoesNotSettle: a ghost coming
// back within its grace under the SAME tenant keeps its history in
// place — nothing to re-attribute, so nothing folds.
func TestReconcileMACs_ResurrectedSameTenantDoesNotSettle(t *testing.T) {
	meta := metadata.New()
	macStr := "cc:00:00:00:00:02"
	m := mac(t, macStr)
	meta.Insert(m, &metadata.TenantMeta{ProjectID: "proj-z"})
	meta.MarkDelete(m, time.Unix(1000, 0))

	var vmMAC [6]uint8
	hw, _ := net.ParseMAC(macStr)
	copy(vmMAC[:], hw)
	st := state.New()
	st.ApplyDelta(bpf.FlowKey{SrcMac: vmMAC, EthProto: 0x0800,
		Direction: bpf.DirectionIngress, DstZone: bpf.ZoneSameTenant},
		bpf.FlowMetrics{Bytes: 100, Packets: 1, LastSeenNs: 1})

	r := New(Options{
		Meta:      meta,
		MacWriter: &fakeMacWriter{},
		Settler:   st,
		Interner:  metadata.NewTenantInterner(),
		Metrics:   NewMetrics(),
	})
	r.reconcileMACs([]neutron.Port{vmPort(macStr, "proj-z")}, time.Unix(2000, 0))

	flows, settled := st.SnapshotWithSettled(nil, nil)
	if len(settled) != 0 {
		t.Errorf("settled = %+v, want none (same tenant resurrected)", settled)
	}
	if len(flows) != 1 || flows[0].Total.Bytes != 100 {
		t.Errorf("flows = %+v, want the history untouched", flows)
	}
}

// fakeGauge records the last value set for each kernel map.
type fakeGauge struct{ vals map[string]float64 }

func (f *fakeGauge) SetCurrent(name string, v float64) {
	if f.vals == nil {
		f.vals = map[string]float64{}
	}
	f.vals[name] = v
}

// TestReconcileOnce_RefreshesMapGauges locks the fix for the gauge gap:
// a reconcile pass refreshes lachesis_bpf_map_current_entries for both the
// subnet_zone_trie (committed rows) and mac_tenant_map (metadata count),
// so the fill gauges don't stay stuck at the cold-start value.
func TestReconcileOnce_RefreshesMapGauges(t *testing.T) {
	meta := metadata.New()
	src := &fakeSrc{syncResult: neutron.SyncResult{
		Entries: []neutron.TrieEntry{
			te("A", "10.0.0.0/24", bpf.ZoneSameTenant),
			te("", "0.0.0.0/0", bpf.ZoneExternal),
		},
		Snapshot: neutron.Snapshot{Ports: []neutron.Port{vmPort("aa:00:00:00:00:01", "proj-a")}},
	}}
	fg := &fakeGauge{}
	r := New(Options{
		Source: src, Trie: &fakeMap{}, Meta: meta, MacWriter: &fakeMacWriter{},
		Interner: metadata.NewTenantInterner(), Metrics: NewMetrics(), BPFGauge: fg,
	})

	r.reconcileOnce(context.Background(), time.Unix(1000, 0))

	if got := fg.vals[bpf.MapSubnetZoneTrie]; got != 2 {
		t.Errorf("subnet_zone_trie gauge = %v, want 2 (committed rows)", got)
	}
	if got := fg.vals[bpf.MapMacTenant]; got != 1 {
		t.Errorf("mac_tenant_map gauge = %v, want 1 (the learned MAC)", got)
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
