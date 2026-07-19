package kernelwriter

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/bigstack-oss/lachesis/internal/bpf"
	"github.com/bigstack-oss/lachesis/internal/metadata"
	"github.com/bigstack-oss/lachesis/internal/neutron"
)

// fakeMap is a [MapUpdateDeleter] that records every update and delete.
// failAt, when non-empty, makes the N-th update (1-indexed) return that
// error so tests can exercise the partial-failure path; failDeleteAt
// does the same for deletes. ops is the interleaved operation log the
// delta tests use to assert the docs/architecture/trie-construction.md#incremental-updates upsert-before-delete ordering.
type fakeMap struct {
	updates      []update
	deletes      []any
	ops          []fakeOp
	failAt       map[int]error
	failDeleteAt map[int]error
	calls        int
	deleteCalls  int
}

type update struct {
	key   any
	value any
	flags ebpf.MapUpdateFlags
}

// fakeOp records the kind ("update"/"delete") of each map mutation in
// call order, so a test can verify no delete precedes any update.
type fakeOp struct {
	kind string
	key  any
}

func (f *fakeMap) Update(k, v any, flags ebpf.MapUpdateFlags) error {
	f.calls++
	if err, ok := f.failAt[f.calls]; ok {
		return err
	}
	// Copy through pointer-deref so the recorded value isn't aliased
	// to the caller's stack-allocated locals.
	rec := update{flags: flags}
	switch kk := k.(type) {
	case *uint64:
		rec.key = *kk
	case *bpf.LpmKey:
		rec.key = *kk
	default:
		rec.key = k
	}
	switch vv := v.(type) {
	case *uint32:
		rec.value = *vv
	case *uint8:
		rec.value = *vv
	default:
		rec.value = v
	}
	f.updates = append(f.updates, rec)
	f.ops = append(f.ops, fakeOp{kind: "update", key: rec.key})
	return nil
}

// Delete records the key (deref'd for LpmKey so it isn't aliased) and
// honours failDeleteAt for the partial-failure path.
func (f *fakeMap) Delete(k any) error {
	f.deleteCalls++
	if err, ok := f.failDeleteAt[f.deleteCalls]; ok {
		return err
	}
	key := k
	if kk, ok := k.(*bpf.LpmKey); ok {
		key = *kk
	}
	f.deletes = append(f.deletes, key)
	f.ops = append(f.ops, fakeOp{kind: "delete", key: key})
	return nil
}

func TestWriteMacTenantMap_HappyPath(t *testing.T) {
	snap := metadata.New()
	interner := metadata.NewTenantInterner()
	snap.Insert(0x010203040506, &metadata.TenantMeta{ProjectID: "proj-A"})
	snap.Insert(0x0a0b0c0d0e0f, &metadata.TenantMeta{ProjectID: "proj-B"})
	snap.Insert(0x111213141516, &metadata.TenantMeta{ProjectID: "proj-A"}) // 2nd MAC same project

	fm := &fakeMap{}
	n, err := WriteMacTenantMap(fm, snap, interner)
	if err != nil {
		t.Fatalf("WriteMacTenantMap: %v", err)
	}
	if n != 3 {
		t.Fatalf("wrote %d, want 3", n)
	}
	// proj-A → 1, proj-B → 2.
	if id, _ := interner.Lookup("proj-A"); id != 1 {
		t.Errorf("proj-A interned id = %d, want 1", id)
	}
	if id, _ := interner.Lookup("proj-B"); id != 2 {
		t.Errorf("proj-B interned id = %d, want 2", id)
	}
	if len(fm.updates) != 3 {
		t.Fatalf("recorded %d updates, want 3", len(fm.updates))
	}
	// Both proj-A MACs must point at the same u32 tenant_id.
	seenA := 0
	for _, u := range fm.updates {
		if u.value.(uint32) == 1 {
			seenA++
		}
	}
	if seenA != 2 {
		t.Errorf("MACs mapped to tenant 1 = %d, want 2 (both proj-A MACs)", seenA)
	}
}

func TestWriteMacTenantMap_SkipsEmptyProjectID(t *testing.T) {
	snap := metadata.New()
	interner := metadata.NewTenantInterner()
	snap.Insert(0xAA, &metadata.TenantMeta{ProjectID: "proj-A"})
	snap.Insert(0xBB, &metadata.TenantMeta{ProjectID: ""}) // skipped

	fm := &fakeMap{}
	n, err := WriteMacTenantMap(fm, snap, interner)
	if err != nil {
		t.Fatalf("WriteMacTenantMap: %v", err)
	}
	if n != 1 {
		t.Errorf("wrote %d, want 1 (empty ProjectID skipped)", n)
	}
}

func TestWriteMacTenantMap_PartialFailureReturnsFirstError(t *testing.T) {
	snap := metadata.New()
	interner := metadata.NewTenantInterner()
	for i := uint64(1); i <= 4; i++ {
		snap.Insert(i, &metadata.TenantMeta{ProjectID: "p"})
	}
	wantErr := errors.New("map full")
	fm := &fakeMap{failAt: map[int]error{2: wantErr}}

	n, err := WriteMacTenantMap(fm, snap, interner)
	if err == nil {
		t.Fatal("expected error from failing update")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("want wrapped %v, got %v", wantErr, err)
	}
	if n != 3 {
		t.Errorf("wrote %d, want 3 (one of 4 failed)", n)
	}
}

func TestWriteMacTenantMap_NilArgs(t *testing.T) {
	if _, err := WriteMacTenantMap(nil, metadata.New(), metadata.NewTenantInterner()); err == nil {
		t.Error("nil macMap should error")
	}
	if _, err := WriteMacTenantMap(&fakeMap{}, nil, metadata.NewTenantInterner()); err == nil {
		t.Error("nil snap should error")
	}
	if _, err := WriteMacTenantMap(&fakeMap{}, metadata.New(), nil); err == nil {
		t.Error("nil interner should error")
	}
}

func TestWriteSubnetZoneTrie_HappyPath(t *testing.T) {
	entries := []neutron.TrieEntry{
		{TenantID: "proj-A", Prefix: netip.MustParsePrefix("0.0.0.0/0"), Zone: bpf.ZoneExternal},
		{TenantID: "proj-A", Prefix: netip.MustParsePrefix("10.0.0.0/24"), Zone: bpf.ZoneSameTenant},
		{TenantID: "proj-A", Prefix: netip.MustParsePrefix("169.254.169.254/32"), Zone: bpf.ZoneInfra},
		{TenantID: "proj-B", Prefix: netip.MustParsePrefix("0.0.0.0/0"), Zone: bpf.ZoneExternal},
	}
	interner := metadata.NewTenantInterner()
	fm := &fakeMap{}
	n, err := WriteSubnetZoneTrie(fm, entries, interner)
	if err != nil {
		t.Fatalf("WriteSubnetZoneTrie: %v", err)
	}
	if n != 4 {
		t.Fatalf("wrote %d, want 4", n)
	}

	// proj-A → 1, proj-B → 2 (monotonic interner assignment in walk order).
	idA, _ := interner.Lookup("proj-A")
	idB, _ := interner.Lookup("proj-B")
	if idA != 1 || idB != 2 {
		t.Fatalf("interner allocation surprise: A=%d, B=%d", idA, idB)
	}

	// LpmKey roundtrip: 10.0.0.0/24 entry must have prefixlen 56 and
	// tenant_id 1.
	for _, u := range fm.updates {
		k := u.key.(bpf.LpmKey)
		if k.Prefixlen == 56 && k.TenantId != idA {
			t.Errorf("/24 entry tenant_id = %d, want %d", k.TenantId, idA)
		}
	}
}

func TestWriteSubnetZoneTrie_EmptyTenantWritesAsSentinel(t *testing.T) {
	// Empty TenantID is the valid sentinel for a global row
	// (catchall / SHARED / INFRA / metadata). The interner maps
	// "" → metadata.TenantIDUnset = 0, which the C-side lookup_zone
	// uses as the fallback key on first-lookup miss. Verify the
	// writer accepts the row and lands it at tenant_id=0 in the
	// trie map.
	fm := &fakeMap{}
	entries := []neutron.TrieEntry{
		{TenantID: "p", Prefix: netip.MustParsePrefix("10.0.0.0/24"), Zone: bpf.ZoneSameTenant},
		{TenantID: "", Prefix: netip.MustParsePrefix("0.0.0.0/0"), Zone: bpf.ZoneExternal},
		{TenantID: "p", Prefix: netip.MustParsePrefix("192.0.2.0/24"), Zone: bpf.ZoneOtherTenant},
	}
	n, err := WriteSubnetZoneTrie(fm, entries, metadata.NewTenantInterner())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 3 {
		t.Errorf("written = %d, want 3 (sentinel row writes alongside per-tenant rows)", n)
	}
	if len(fm.updates) != 3 {
		t.Fatalf("fakeMap.updates len = %d, want 3", len(fm.updates))
	}
	// The catchall row must have landed at tenant_id=0 (sentinel).
	var sawSentinel bool
	for _, u := range fm.updates {
		k := u.key.(bpf.LpmKey)
		if k.Prefixlen == bpf.LpmKeyTenantBits && k.TenantId == metadata.TenantIDUnset {
			sawSentinel = true
		}
	}
	if !sawSentinel {
		t.Errorf("catchall row did not land at tenant_id=0; updates=%+v", fm.updates)
	}
}

func TestWriteSubnetZoneTrie_PartialFailureReturnsFirstError(t *testing.T) {
	entries := []neutron.TrieEntry{
		{TenantID: "p", Prefix: netip.MustParsePrefix("0.0.0.0/0"), Zone: bpf.ZoneExternal},
		{TenantID: "p", Prefix: netip.MustParsePrefix("10.0.0.0/24"), Zone: bpf.ZoneSameTenant},
		{TenantID: "p", Prefix: netip.MustParsePrefix("192.0.2.0/24"), Zone: bpf.ZoneOtherTenant},
	}
	wantErr := errors.New("EINVAL")
	fm := &fakeMap{failAt: map[int]error{2: wantErr}}
	interner := metadata.NewTenantInterner()
	n, err := WriteSubnetZoneTrie(fm, entries, interner)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("want wrapped %v, got %v", wantErr, err)
	}
	if n != 2 {
		t.Errorf("wrote %d, want 2 (one of 3 failed)", n)
	}
}

func TestWriteSubnetZoneTrie_NilArgs(t *testing.T) {
	if _, err := WriteSubnetZoneTrie(nil, nil, metadata.NewTenantInterner()); err == nil {
		t.Error("nil trieMap should error")
	}
	if _, err := WriteSubnetZoneTrie(&fakeMap{}, nil, nil); err == nil {
		t.Error("nil interner should error")
	}
}
