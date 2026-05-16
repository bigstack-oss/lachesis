package metadata

import (
	"strconv"
	"sync"
	"testing"
)

func TestTenantInterner_Empty(t *testing.T) {
	i := NewTenantInterner()
	if i.Len() != 0 {
		t.Fatalf("fresh interner Len = %d, want 0", i.Len())
	}
	if got := i.Intern(""); got != TenantIDUnset {
		t.Fatalf("Intern(\"\") = %d, want TenantIDUnset (%d)", got, TenantIDUnset)
	}
	if i.Len() != 0 {
		t.Fatalf("empty Intern() must not allocate; Len = %d", i.Len())
	}
}

func TestTenantInterner_MonotonicStartingAtOne(t *testing.T) {
	i := NewTenantInterner()
	a := i.Intern("proj-A")
	b := i.Intern("proj-B")
	c := i.Intern("proj-C")
	if a != 1 || b != 2 || c != 3 {
		t.Errorf("expected 1/2/3, got %d/%d/%d", a, b, c)
	}
}

func TestTenantInterner_StableForSameProjectID(t *testing.T) {
	i := NewTenantInterner()
	first := i.Intern("proj-X")
	for k := 0; k < 100; k++ {
		if got := i.Intern("proj-X"); got != first {
			t.Fatalf("iter %d: got %d, want %d (stable)", k, got, first)
		}
	}
	if i.Len() != 1 {
		t.Errorf("Len = %d, want 1", i.Len())
	}
}

func TestTenantInterner_LookupReverseRoundTrip(t *testing.T) {
	i := NewTenantInterner()
	id := i.Intern("proj-X")

	if gotID, ok := i.Lookup("proj-X"); !ok || gotID != id {
		t.Errorf("Lookup(proj-X) = (%d, %v), want (%d, true)", gotID, ok, id)
	}
	if gotID, ok := i.Lookup("proj-unknown"); ok || gotID != TenantIDUnset {
		t.Errorf("Lookup(unknown) = (%d, %v), want (%d, false)", gotID, ok, TenantIDUnset)
	}
	if gotID, ok := i.Lookup(""); ok || gotID != TenantIDUnset {
		t.Errorf("Lookup(\"\") = (%d, %v), want (%d, false)", gotID, ok, TenantIDUnset)
	}

	if gotProj, ok := i.Reverse(id); !ok || gotProj != "proj-X" {
		t.Errorf("Reverse(%d) = (%q, %v), want (proj-X, true)", id, gotProj, ok)
	}
	if gotProj, ok := i.Reverse(TenantIDUnset); ok || gotProj != "" {
		t.Errorf("Reverse(TenantIDUnset) = (%q, %v), want (\"\", false)", gotProj, ok)
	}
	if gotProj, ok := i.Reverse(9999); ok || gotProj != "" {
		t.Errorf("Reverse(9999) = (%q, %v), want (\"\", false)", gotProj, ok)
	}
}

// TestTenantInterner_ConcurrentInternStable hammers Intern from many
// goroutines with overlapping ProjectIDs; the resulting forward map
// must contain exactly one ID per distinct ProjectID and the
// reverse map must round-trip. Intended to run under -race.
func TestTenantInterner_ConcurrentInternStable(t *testing.T) {
	i := NewTenantInterner()
	const projects = 32
	const goroutines = 16
	const iters = 200

	var wg sync.WaitGroup
	results := make([][]uint32, goroutines)
	for g := 0; g < goroutines; g++ {
		results[g] = make([]uint32, projects)
		wg.Add(1)
		go func(gi int) {
			defer wg.Done()
			for n := 0; n < iters; n++ {
				for p := 0; p < projects; p++ {
					id := i.Intern("proj-" + strconv.Itoa(p))
					results[gi][p] = id
				}
			}
		}(g)
	}
	wg.Wait()

	if i.Len() != projects {
		t.Fatalf("Len = %d, want %d", i.Len(), projects)
	}
	for p := 0; p < projects; p++ {
		want := results[0][p]
		for g := 1; g < goroutines; g++ {
			if results[g][p] != want {
				t.Errorf("goroutine %d observed proj-%d id %d, goroutine 0 saw %d",
					g, p, results[g][p], want)
			}
		}
		if proj, ok := i.Reverse(want); !ok || proj != "proj-"+strconv.Itoa(p) {
			t.Errorf("Reverse(%d) = (%q, %v); want (proj-%d, true)", want, proj, ok, p)
		}
	}
}
