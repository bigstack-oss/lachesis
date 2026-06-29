package scenarios

import "testing"

var validZones = map[string]bool{
	"same_tenant": true, "other_tenant": true, "external": true,
	"shared": true, "infra": true, "miss": true,
}

// TestAll_BuildAndInvariants exercises every registered scenario: the
// DSL builder must produce a snapshot without panicking, names must be
// unique, and every Expect must name a valid zone and a tx/rx
// direction (the real metric vocabulary).
func TestAll_BuildAndInvariants(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range All() {
		if s.Name == "" {
			t.Error("scenario with empty name")
		}
		if seen[s.Name] {
			t.Errorf("duplicate scenario name %q", s.Name)
		}
		seen[s.Name] = true

		if s.Builder == nil {
			t.Fatalf("%s: nil builder", s.Name)
		}
		snap := s.Builder.Build() // must not panic
		if len(snap.Networks) == 0 {
			t.Errorf("%s: topology has no networks", s.Name)
		}
		if len(s.Flows) == 0 {
			t.Errorf("%s: no flows declared", s.Name)
		}
		if len(s.Expect) == 0 {
			t.Errorf("%s: no expectations declared", s.Name)
		}
		for _, e := range s.Expect {
			if !validZones[e.Zone] {
				t.Errorf("%s: invalid zone %q", s.Name, e.Zone)
			}
			if e.Direction != "tx" && e.Direction != "rx" {
				t.Errorf("%s: invalid direction %q (want tx|rx)", s.Name, e.Direction)
			}
			if e.MinBytes <= 0 {
				t.Errorf("%s: non-positive MinBytes %d", s.Name, e.MinBytes)
			}
		}
	}
}

func TestGet(t *testing.T) {
	if _, err := Get("twovms-same-tenant"); err != nil {
		t.Errorf("Get(known): %v", err)
	}
	if _, err := Get("does-not-exist"); err == nil {
		t.Error("Get(unknown): want error, got nil")
	}
}

// TestAll_CoversFiveZones asserts the registry covers each billing
// zone exactly as the feature requires.
func TestAll_CoversFiveZones(t *testing.T) {
	want := []string{"same_tenant", "infra", "external", "shared", "other_tenant"}
	covered := map[string]bool{}
	for _, s := range All() {
		for _, e := range s.Expect {
			covered[e.Zone] = true
		}
	}
	for _, z := range want {
		if !covered[z] {
			t.Errorf("no scenario covers zone %q", z)
		}
	}
}
