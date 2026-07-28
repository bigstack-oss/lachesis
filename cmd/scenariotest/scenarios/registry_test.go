package scenarios

import (
	"strings"
	"testing"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/steps"
)

var validZones = map[string]bool{
	"same_tenant": true, "other_tenant": true, "external": true,
	"shared": true, "infra": true, "miss": true, "multicast": true,
}

// TestAll_BuildAndInvariants exercises every registered scenario: the
// DSL builder must produce a snapshot without panicking, names must be
// unique, and every expectation — top-level or embedded in an
// AssertStep — must name a valid zone and a tx/rx direction (the real
// metric vocabulary). A scenario declares either the classic
// Flows+Expect pair or a step script that drives and asserts.
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

		flows, expects := s.Flows, s.Expect
		asserts := len(expects) > 0
		for _, st := range s.Steps {
			switch st := st.(type) {
			case steps.DriveStep:
				flows = append(flows, st.Flows...)
			case steps.IngressFlowStep:
				// Harness-side sender: a flow for coverage purposes.
				flows = append(flows, scenariotest.Flow{Bytes: st.Bytes})
			case steps.AssertStep:
				expects = append(expects, st.Expect...)
			}
			// Any assert-* step (ZoneGrowthStep, MonotoneStep, AssertAnomalyStep,
			// …) makes a scenario's assertions live in its steps rather than
			// its Expect list; recognise them by their Kind() prefix so this
			// invariant doesn't have to enumerate the growing vocabulary.
			if strings.HasPrefix(st.Kind(), "assert") {
				asserts = true
			}
		}
		if len(flows) == 0 {
			t.Errorf("%s: no flows declared (top-level or in steps)", s.Name)
		}
		if !asserts {
			t.Errorf("%s: no assertions declared (top-level Expect or an assert-* step)", s.Name)
		}
		for _, e := range expects {
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

func TestLiveMigrationContinuity_Invariants(t *testing.T) {
	sc, err := Get("live-migration-continuity")
	if err != nil {
		t.Fatal(err)
	}
	if n := scenariotest.RequiredNodes(sc); n != 2 {
		t.Fatalf("RequiredNodes = %d, want 2", n)
	}
	migrates := 0
	for _, st := range sc.Steps {
		if st.Kind() == "migrate" {
			migrates++
		}
	}
	if migrates != 1 {
		t.Errorf("want exactly one migrate step, got %d", migrates)
	}
}

func TestCrossHostSameTenant_SkipsOnSingleNode(t *testing.T) {
	sc, err := Get("cross-host-same-tenant")
	if err != nil {
		t.Fatal(err)
	}
	if n := scenariotest.RequiredNodes(sc); n != 2 {
		t.Fatalf("RequiredNodes = %d, want 2", n)
	}
	for _, e := range sc.Expect {
		if e.Node == "" {
			t.Errorf("expectation %+v must target a node — the collective sum can't tell the taps apart", e)
		}
	}
}
