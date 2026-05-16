package metadata

import (
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestLookupMiss(t *testing.T) {
	m := New()
	if v, ok := m.Lookup(0xdeadbeef); ok || v != nil {
		t.Fatalf("Lookup on empty map = (%v, %v), want (nil, false)", v, ok)
	}
	if got := m.Len(); got != 0 {
		t.Fatalf("Len = %d, want 0", got)
	}
}

func TestInsertLookup(t *testing.T) {
	m := New()
	want := &TenantMeta{ProjectID: "proj-A", IsAmphora: true}
	m.Insert(0x010203040506, want)

	got, ok := m.Lookup(0x010203040506)
	if !ok {
		t.Fatal("Lookup after Insert reports missing")
	}
	if got != want {
		t.Fatalf("Lookup returned %p, want the inserted pointer %p", got, want)
	}
	if got.ProjectID != "proj-A" || !got.IsAmphora {
		t.Fatalf("Lookup fields = %+v, want ProjectID=proj-A IsAmphora=true", got)
	}
}

func TestInsertOverwriteReplacesPointer(t *testing.T) {
	m := New()
	first := &TenantMeta{ProjectID: "proj-A"}
	m.Insert(0x42, first)

	second := &TenantMeta{ProjectID: "proj-B"}
	m.Insert(0x42, second)

	got, _ := m.Lookup(0x42)
	if got != second {
		t.Fatalf("Lookup returned %p, want overwriting pointer %p", got, second)
	}
}

func TestSharedPointerAcrossMACs(t *testing.T) {
	// A VM with two ports (two MACs) shares one TenantMeta pointer.
	m := New()
	shared := &TenantMeta{ProjectID: "proj-multi"}
	m.Insert(0xAABBCC000001, shared)
	m.Insert(0xAABBCC000002, shared)

	a, _ := m.Lookup(0xAABBCC000001)
	b, _ := m.Lookup(0xAABBCC000002)
	if a != shared || b != shared {
		t.Fatalf("identity broken: a=%p b=%p shared=%p", a, b, shared)
	}
}

// TestMarkDeletePointerReplaceInvariant is the load-bearing test:
// MarkDelete must NEVER mutate the prior TenantMeta in place. A
// concurrent reader holding the prior pointer should still see the
// original (zero) DeleteAt.
func TestMarkDeletePointerReplaceInvariant(t *testing.T) {
	m := New()
	original := &TenantMeta{ProjectID: "proj-A"}
	m.Insert(0x99, original)

	captured, _ := m.Lookup(0x99) // simulates a scrape holding the pointer
	if captured != original {
		t.Fatalf("Lookup did not return the inserted pointer")
	}

	deadline := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if !m.MarkDelete(0x99, deadline) {
		t.Fatal("MarkDelete on present entry returned false")
	}

	if !captured.DeleteAt.IsZero() {
		t.Fatalf("captured pointer was mutated in place: DeleteAt=%v", captured.DeleteAt)
	}
	if !original.DeleteAt.IsZero() {
		t.Fatalf("original pointer was mutated in place: DeleteAt=%v", original.DeleteAt)
	}

	updated, ok := m.Lookup(0x99)
	if !ok {
		t.Fatal("Lookup after MarkDelete reports missing")
	}
	if updated == original {
		t.Fatal("MarkDelete reused the original pointer; want pointer-replace")
	}
	if !updated.DeleteAt.Equal(deadline) {
		t.Fatalf("updated.DeleteAt = %v, want %v", updated.DeleteAt, deadline)
	}
	if updated.ProjectID != original.ProjectID {
		t.Fatalf("updated.ProjectID = %q, want %q (immutable fields must carry through)",
			updated.ProjectID, original.ProjectID)
	}
}

func TestMarkDeleteMissingMAC(t *testing.T) {
	m := New()
	if m.MarkDelete(0x123, time.Now()) {
		t.Fatal("MarkDelete on absent MAC returned true")
	}
	if _, ok := m.Lookup(0x123); ok {
		t.Fatal("MarkDelete on absent MAC unexpectedly inserted an entry")
	}
}

func TestDelete(t *testing.T) {
	m := New()
	m.Insert(0xAA, &TenantMeta{ProjectID: "proj-A"})
	m.Delete(0xAA)
	if _, ok := m.Lookup(0xAA); ok {
		t.Fatal("Lookup after Delete still finds the entry")
	}
	m.Delete(0xBB) // no-op on missing must not panic
}

func TestRange_VisitsEveryEntry(t *testing.T) {
	m := New()
	want := map[uint64]string{}
	for i := uint64(0); i < 200; i++ {
		proj := "proj-" + strconv.FormatUint(i, 10)
		m.Insert(i, &TenantMeta{ProjectID: proj})
		want[i] = proj
	}
	got := map[uint64]string{}
	m.Range(func(mac uint64, meta *TenantMeta) bool {
		got[mac] = meta.ProjectID
		return true
	})
	if len(got) != len(want) {
		t.Fatalf("Range visited %d entries, want %d", len(got), len(want))
	}
	for mac, proj := range want {
		if got[mac] != proj {
			t.Errorf("Range mac=%d project = %q, want %q", mac, got[mac], proj)
		}
	}
}

func TestRange_EarlyStop(t *testing.T) {
	m := New()
	for i := uint64(0); i < 100; i++ {
		m.Insert(i, &TenantMeta{ProjectID: "p"})
	}
	visited := 0
	m.Range(func(uint64, *TenantMeta) bool {
		visited++
		return visited < 5
	})
	if visited != 5 {
		t.Fatalf("Range visited %d entries, want 5 (early stop)", visited)
	}
}

func TestLenAcrossShards(t *testing.T) {
	m := New()
	// MACs chosen to land in different shards (low bits differ).
	for i := uint64(0); i < 200; i++ {
		m.Insert(i, &TenantMeta{ProjectID: "p"})
	}
	if got := m.Len(); got != 200 {
		t.Fatalf("Len = %d, want 200", got)
	}
}

// TestConcurrentInsertLookup hammers the map from many goroutines.
// Intended to be run with `-race`. Asserts that all readers see a
// stable, never-mutated TenantMeta even while writers update entries.
func TestConcurrentInsertLookup(t *testing.T) {
	m := New()
	const macs = 256
	for i := uint64(0); i < macs; i++ {
		m.Insert(i, &TenantMeta{ProjectID: "initial"})
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Writers: each goroutine repeatedly replaces a few MACs'
	// pointers. Pointer-replace, never in-place mutation.
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(seed uint64) {
			defer wg.Done()
			for i := uint64(0); ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				mac := (seed*17 + i) & (macs - 1)
				m.Insert(mac, &TenantMeta{ProjectID: "updated"})
			}
		}(uint64(w))
	}

	// Readers: capture a pointer, then re-read its fields several
	// times. If a writer mutates in place, the race detector or a
	// field comparison would catch the tear.
	for r := 0; r < 8; r++ {
		wg.Add(1)
		go func(seed uint64) {
			defer wg.Done()
			for i := uint64(0); ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				mac := (seed*23 + i) & (macs - 1)
				if v, ok := m.Lookup(mac); ok {
					projectID := v.ProjectID
					if projectID != "initial" && projectID != "updated" {
						t.Errorf("torn read: ProjectID=%q", projectID)
						return
					}
				}
			}
		}(uint64(r))
	}

	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
}
