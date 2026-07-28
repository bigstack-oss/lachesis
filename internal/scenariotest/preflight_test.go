package scenariotest

import (
	"context"
	"testing"
)

func checkByName(r PreflightReport, name string) (Check, bool) {
	for _, c := range r.Checks {
		if c.Name == name {
			return c, true
		}
	}
	return Check{}, false
}

func TestPreflight_AllGood(t *testing.T) {
	env := &fakeEnv{baseAttached: 1}
	cloud := newFakeCloud(env)
	r := Preflight(context.Background(), testConfig(), sameTenantScenario(), cloud, &fakeMetrics{env: env})
	if !r.OK {
		t.Fatalf("expected READY, report: %+v", r.Checks)
	}
	for _, c := range r.Checks {
		if !c.OK {
			t.Errorf("check %q failed unexpectedly: %s", c.Name, c.Detail)
		}
	}
}

func TestPreflight_MissingFlavor(t *testing.T) {
	env := &fakeEnv{baseAttached: 1}
	cloud := newFakeCloud(env)
	cloud.findErrs["flavor"] = context.DeadlineExceeded // any error
	r := Preflight(context.Background(), testConfig(), sameTenantScenario(), cloud, &fakeMetrics{env: env})
	if r.OK {
		t.Fatal("expected NOT READY when flavor missing")
	}
	if c, ok := checkByName(r, "flavor"); !ok || c.OK {
		t.Errorf("flavor check should have failed, got %+v", c)
	}
}

func TestPreflight_PlacementUnknownHost(t *testing.T) {
	env := &fakeEnv{baseAttached: 1}
	cloud := newFakeCloud(env)
	cloud.hyps = []string{"compute-0"}
	sc := sameTenantScenario()
	sc.Placement = Placement{"vm-a": "nonexistent-host"}
	r := Preflight(context.Background(), testConfig(), sc, cloud, &fakeMetrics{env: env})
	if c, ok := checkByName(r, "placement"); !ok || c.OK {
		t.Errorf("placement check should have failed for unknown host, got %+v", c)
	}
	if r.OK {
		t.Error("report should be NOT READY")
	}
}

func TestPreflight_PlacementSlotResolves(t *testing.T) {
	env := &fakeEnv{baseAttached: 1}
	cloud := newFakeCloud(env)
	cloud.hyps = []string{"compute-0"}
	sc := sameTenantScenario()
	sc.Placement = Placement{"vm-a": "node:0"} // testConfig's only agent is compute-0
	r := Preflight(context.Background(), testConfig(), sc, cloud, &fakeMetrics{env: env})
	if c, ok := checkByName(r, "placement"); !ok || !c.OK {
		t.Errorf("placement check should pass for a resolvable slot, got %+v", c)
	}
}

func TestPreflight_SlotBeyondAgentsSkips(t *testing.T) {
	env := &fakeEnv{baseAttached: 1}
	cloud := newFakeCloud(env)
	sc := sameTenantScenario()
	sc.Placement = Placement{"vm-b": "node:1"} // testConfig lists one agent
	r := Preflight(context.Background(), testConfig(), sc, cloud, &fakeMetrics{env: env})
	if r.Skip == "" {
		t.Fatalf("expected a skip reason, report: %+v", r)
	}
	if !r.OK {
		t.Error("a skip is not a failure")
	}
	if len(r.Checks) != 0 {
		t.Errorf("no checks should run when skipped, got %d", len(r.Checks))
	}
}

func TestPreflight_MalformedSlotFailsPlacement(t *testing.T) {
	// A malformed slot is a scenario defect, not a too-small cluster:
	// it must FAIL the placement check, never SKIP — even when a valid
	// slot beside it would qualify the scenario for a skip (masking the
	// defect until a big-enough cluster finally ran it).
	for name, p := range map[string]Placement{
		"malformed alone":            {"vm-a": "node:one"},
		"malformed beside skip-size": {"vm-a": "node:5", "vm-b": "node:one"},
	} {
		t.Run(name, func(t *testing.T) {
			env := &fakeEnv{baseAttached: 1}
			cloud := newFakeCloud(env)
			sc := sameTenantScenario()
			sc.Placement = p
			r := Preflight(context.Background(), testConfig(), sc, cloud, &fakeMetrics{env: env})
			if r.Skip != "" {
				t.Errorf("malformed slot must not skip, got reason %q", r.Skip)
			}
			if c, ok := checkByName(r, "placement"); !ok || c.OK {
				t.Errorf("placement check should fail for a malformed slot, got %+v", c)
			}
			if r.OK {
				t.Error("report should be NOT READY")
			}
		})
	}
}

func TestPreflight_AgentMissingMetric(t *testing.T) {
	env := &fakeEnv{baseAttached: 1}
	cloud := newFakeCloud(env)
	r := Preflight(context.Background(), testConfig(), sameTenantScenario(), cloud, halfMetrics{})
	if c, ok := checkByName(r, "agent:compute-0"); !ok || c.OK {
		t.Errorf("agent check should fail when a required metric is absent, got %+v", c)
	}
}

// halfMetrics reports bytes present but the attach gauge absent.
type halfMetrics struct{ instantMACs }

func (halfMetrics) Scrape(context.Context, string) (ScrapeResult, error) {
	return ScrapeResult{Present: map[string]bool{MetricBytesTotal: true, MetricAttachedInterfaces: false}}, nil
}
