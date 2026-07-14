package kernelwriter

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/bigstack-oss/lachesis/internal/bpf"
	"github.com/bigstack-oss/lachesis/internal/metadata"
	"github.com/bigstack-oss/lachesis/internal/neutron"
)

// te builds a TrieEntry; cidr is parsed with MustParsePrefix so a
// malformed test fixture fails loudly at setup.
func te(tenant, cidr string, zone bpf.ZoneCode) neutron.TrieEntry {
	return neutron.TrieEntry{
		TenantID: tenant,
		Prefix:   netip.MustParsePrefix(cidr),
		Zone:     zone,
	}
}

// internAll pre-interns the tenants of every entry, mimicking a real
// run where the "old" trie was written by a prior pass that already
// interned its tenants. ApplyTrieDelta resolves old rows via Lookup, so
// without this their u32 is unknown and they cannot be deleted.
func internAll(in *metadata.TenantInterner, entries ...neutron.TrieEntry) {
	for _, e := range entries {
		in.Intern(e.TenantID)
	}
}

func TestApplyTrieDelta_AddChangeRemoveSkip(t *testing.T) {
	interner := metadata.NewTenantInterner()
	old := []neutron.TrieEntry{
		te("A", "10.0.0.0/24", bpf.ZoneExternal),   // unchanged → skipped
		te("B", "10.1.0.0/16", bpf.ZoneSameTenant), // zone changes → upsert
		te("X", "10.9.0.0/24", bpf.ZoneInfra),      // gone → delete
	}
	internAll(interner, old...)

	newE := []neutron.TrieEntry{
		te("A", "10.0.0.0/24", bpf.ZoneExternal), // identical
		te("B", "10.1.0.0/16", bpf.ZoneInfra),    // changed zone
		te("C", "10.2.0.0/8", bpf.ZoneShared),    // brand new
	}

	fm := &fakeMap{}
	delta, err := ApplyTrieDelta(fm, old, newE, interner)
	if err != nil {
		t.Fatalf("ApplyTrieDelta: %v", err)
	}
	if delta != (TrieDelta{Added: 1, Changed: 1, Removed: 1}) {
		t.Fatalf("delta = %+v, want {Added:1 Changed:1 Removed:1}", delta)
	}
	// Two upserts (B changed, C added) — A is identical and must not be
	// rewritten.
	if len(fm.updates) != 2 {
		t.Errorf("updates = %d, want 2 (B changed, C added; A skipped)", len(fm.updates))
	}
	if len(fm.deletes) != 1 {
		t.Errorf("deletes = %d, want 1 (X)", len(fm.deletes))
	}
	// The deleted key must be X's row, not anyone else's.
	xTid, _ := interner.Lookup("X")
	wantDel := bpf.LpmKeyForPrefix(xTid, netip.MustParsePrefix("10.9.0.0/24"))
	if got := fm.deletes[0]; got != any(wantDel) {
		t.Errorf("deleted key = %v, want X row %v", got, wantDel)
	}
}

// TestApplyTrieDelta_UpsertBeforeDelete locks the docs/DESIGN.md §5.7
// ordering contract: every upsert must precede every delete. A
// regression that interleaves or reverses them fails here.
func TestApplyTrieDelta_UpsertBeforeDelete(t *testing.T) {
	interner := metadata.NewTenantInterner()
	// Many old rows that all disappear, many new rows that all appear —
	// so a wrong ordering is overwhelmingly likely to interleave.
	var old, newE []neutron.TrieEntry
	for i := 0; i < 8; i++ {
		old = append(old, te("old", netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i), 0, 0}), 16).String(), bpf.ZoneInfra))
		newE = append(newE, te("new", netip.PrefixFrom(netip.AddrFrom4([4]byte{172, 16, byte(i), 0}), 24).String(), bpf.ZoneExternal))
	}
	internAll(interner, old...)

	fm := &fakeMap{}
	if _, err := ApplyTrieDelta(fm, old, newE, interner); err != nil {
		t.Fatalf("ApplyTrieDelta: %v", err)
	}
	if len(fm.updates) != 8 || len(fm.deletes) != 8 {
		t.Fatalf("got %d updates / %d deletes, want 8/8", len(fm.updates), len(fm.deletes))
	}
	lastUpdate, firstDelete := -1, len(fm.ops)
	for i, op := range fm.ops {
		switch op.kind {
		case "update":
			lastUpdate = i
		case "delete":
			if i < firstDelete {
				firstDelete = i
			}
		}
	}
	if lastUpdate > firstDelete {
		t.Errorf("a delete at op[%d] preceded an upsert at op[%d]: §5.7 ordering violated", firstDelete, lastUpdate)
	}
}

func TestApplyTrieDelta_NoChange(t *testing.T) {
	interner := metadata.NewTenantInterner()
	entries := []neutron.TrieEntry{
		te("A", "10.0.0.0/24", bpf.ZoneExternal),
		te("", "0.0.0.0/0", bpf.ZoneExternal), // sentinel catchall
	}
	internAll(interner, entries...)

	fm := &fakeMap{}
	delta, err := ApplyTrieDelta(fm, entries, entries, interner)
	if err != nil {
		t.Fatalf("ApplyTrieDelta: %v", err)
	}
	if delta != (TrieDelta{}) {
		t.Errorf("delta = %+v, want zero", delta)
	}
	if len(fm.updates) != 0 || len(fm.deletes) != 0 {
		t.Errorf("identical snapshots wrote %d updates / %d deletes, want 0/0", len(fm.updates), len(fm.deletes))
	}
}

// TestApplyTrieDelta_UpsertFailureSkipsDeletes proves the safety rule:
// if any upsert fails, the delete phase is skipped so a stale row is
// never removed while its replacement is missing.
func TestApplyTrieDelta_UpsertFailureSkipsDeletes(t *testing.T) {
	interner := metadata.NewTenantInterner()
	old := []neutron.TrieEntry{te("X", "10.9.0.0/24", bpf.ZoneInfra)} // would be deleted
	internAll(interner, old...)
	newE := []neutron.TrieEntry{te("C", "10.2.0.0/8", bpf.ZoneShared)} // would be added

	boom := errors.New("kernel ENOMEM")
	fm := &fakeMap{failAt: map[int]error{1: boom}} // first (only) upsert fails

	delta, err := ApplyTrieDelta(fm, old, newE, interner)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}
	if delta.Removed != 0 {
		t.Errorf("Removed = %d, want 0 — deletes must be skipped after an upsert failure", delta.Removed)
	}
	if len(fm.deletes) != 0 {
		t.Errorf("performed %d deletes after an upsert failure; want 0", len(fm.deletes))
	}
}

func TestApplyTrieDelta_SentinelTenantRow(t *testing.T) {
	interner := metadata.NewTenantInterner()
	// Sentinel rows (TenantID="") intern to tenant_id 0. A changed
	// sentinel zone must upsert at the tenant_id=0 key.
	old := []neutron.TrieEntry{te("", "169.254.169.254/32", bpf.ZoneInfra)}
	internAll(interner, old...)
	newE := []neutron.TrieEntry{te("", "169.254.169.254/32", bpf.ZoneExternal)} // zone flip

	fm := &fakeMap{}
	delta, err := ApplyTrieDelta(fm, old, newE, interner)
	if err != nil {
		t.Fatalf("ApplyTrieDelta: %v", err)
	}
	if delta != (TrieDelta{Changed: 1}) {
		t.Fatalf("delta = %+v, want {Changed:1}", delta)
	}
	wantKey := bpf.LpmKeyForPrefix(metadata.TenantIDUnset, netip.MustParsePrefix("169.254.169.254/32"))
	if got := fm.updates[0].key; got != any(wantKey) {
		t.Errorf("upsert key = %v, want sentinel tenant_id=0 row %v", got, wantKey)
	}
}
