package preflight

import (
	"context"
	"testing"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/fake"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

func checkByName(r Report, name string) (Check, bool) {
	for _, c := range r.Checks {
		if c.Name == name {
			return c, true
		}
	}
	return Check{}, false
}

func TestPreflight_AllGood(t *testing.T) {
	env := &fake.Env{BaseAttached: 1}
	cloud := fake.NewCloud(env)
	r := Run(context.Background(), fake.Config(), fake.SameTenantScenario(), cloud, &fake.Metrics{Env: env})
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
	env := &fake.Env{BaseAttached: 1}
	cloud := fake.NewCloud(env)
	cloud.FindErrs["flavor"] = context.DeadlineExceeded // any error
	r := Run(context.Background(), fake.Config(), fake.SameTenantScenario(), cloud, &fake.Metrics{Env: env})
	if r.OK {
		t.Fatal("expected NOT READY when flavor missing")
	}
	if c, ok := checkByName(r, "flavor"); !ok || c.OK {
		t.Errorf("flavor check should have failed, got %+v", c)
	}
}

func TestPreflight_PlacementUnknownHost(t *testing.T) {
	env := &fake.Env{BaseAttached: 1}
	cloud := fake.NewCloud(env)
	cloud.Hyps = []string{"compute-0"}
	sc := fake.SameTenantScenario()
	sc.Placement = scenariotest.Placement{"vm-a": "nonexistent-host"}
	r := Run(context.Background(), fake.Config(), sc, cloud, &fake.Metrics{Env: env})
	if c, ok := checkByName(r, "placement"); !ok || c.OK {
		t.Errorf("placement check should have failed for unknown host, got %+v", c)
	}
	if r.OK {
		t.Error("report should be NOT READY")
	}
}

func TestPreflight_PlacementSlotResolves(t *testing.T) {
	env := &fake.Env{BaseAttached: 1}
	cloud := fake.NewCloud(env)
	cloud.Hyps = []string{"compute-0"}
	sc := fake.SameTenantScenario()
	sc.Placement = scenariotest.Placement{"vm-a": "node:0"} // fake.Config's only agent is compute-0
	r := Run(context.Background(), fake.Config(), sc, cloud, &fake.Metrics{Env: env})
	if c, ok := checkByName(r, "placement"); !ok || !c.OK {
		t.Errorf("placement check should pass for a resolvable slot, got %+v", c)
	}
}

func TestPreflight_SlotBeyondAgentsSkips(t *testing.T) {
	env := &fake.Env{BaseAttached: 1}
	cloud := fake.NewCloud(env)
	sc := fake.SameTenantScenario()
	sc.Placement = scenariotest.Placement{"vm-b": "node:1"} // fake.Config lists one agent
	r := Run(context.Background(), fake.Config(), sc, cloud, &fake.Metrics{Env: env})
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
	for name, p := range map[string]scenariotest.Placement{
		"malformed alone":            {"vm-a": "node:one"},
		"malformed beside skip-size": {"vm-a": "node:5", "vm-b": "node:one"},
	} {
		t.Run(name, func(t *testing.T) {
			env := &fake.Env{BaseAttached: 1}
			cloud := fake.NewCloud(env)
			sc := fake.SameTenantScenario()
			sc.Placement = p
			r := Run(context.Background(), fake.Config(), sc, cloud, &fake.Metrics{Env: env})
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
	env := &fake.Env{BaseAttached: 1}
	cloud := fake.NewCloud(env)
	r := Run(context.Background(), fake.Config(), fake.SameTenantScenario(), cloud, halfMetrics{})
	if c, ok := checkByName(r, "agent:compute-0"); !ok || c.OK {
		t.Errorf("agent check should fail when a required metric is absent, got %+v", c)
	}
}

// halfMetrics reports bytes present but the attach gauge absent.
type halfMetrics struct{ fake.InstantMACs }

func (halfMetrics) Scrape(context.Context, string) (scenariotest.ScrapeResult, error) {
	return scenariotest.ScrapeResult{Present: map[string]bool{scenariotest.MetricBytesTotal: true, scenariotest.MetricAttachedInterfaces: false}}, nil
}

// lbScenario declares a minimal load-balancer topology at the given
// topology, for the optional-prerequisite tests below.
func lbScenario(topology scenario.LBTopology) *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.1.0/24", "10.0.1.1").
		VM("vm-a", "T1", "10.0.1.5").
		LoadBalancer("lb1", "T1", "service", "10.0.1.50", topology).
		Member("sub-T1", "10.0.1.5", 80).
		Done()
	return &scenariotest.Scenario{Name: "lb", Desc: "lb", Builder: b}
}

// TestPreflight_LBFlavorCheckedOnlyWhenNeeded pins the one OPTIONAL
// prerequisite. A scenario with no ACTIVE_STANDBY load balancer must not
// probe Octavia at all, so every existing scenario keeps working on a
// cluster with no load balancing; one that declares it gets a real
// check; and an unstaged flavor SKIPS rather than fails.
func TestPreflight_LBFlavorCheckedOnlyWhenNeeded(t *testing.T) {
	t.Run("standalone never probes octavia", func(t *testing.T) {
		env := &fake.Env{BaseAttached: 1}
		cloud := fake.NewCloud(env)
		cloud.LBFlavorID = "lbflv-1"
		cfg := fake.Config()
		cfg.Prerequisites.LBFlavorName = "lachesis-ha"
		r := Run(context.Background(), cfg, lbScenario(scenario.Standalone), cloud, &fake.Metrics{Env: env})
		if _, ok := checkByName(r, "lb_flavor"); ok {
			t.Error("lb_flavor probed for a scenario declaring no ACTIVE_STANDBY load balancer")
		}
	})

	t.Run("active-standby resolves the flavor", func(t *testing.T) {
		env := &fake.Env{BaseAttached: 1}
		cloud := fake.NewCloud(env)
		cloud.LBFlavorID = "lbflv-1"
		cfg := fake.Config()
		cfg.Prerequisites.LBFlavorName = "lachesis-ha"
		r := Run(context.Background(), cfg, lbScenario(scenario.ActiveStandby), cloud, &fake.Metrics{Env: env})
		c, ok := checkByName(r, "lb_flavor")
		if !ok {
			t.Fatal("lb_flavor not probed for an ACTIVE_STANDBY scenario")
		}
		if !c.OK {
			t.Errorf("lb_flavor check failed: %s", c.Detail)
		}
	})

	t.Run("configured but unresolvable flavor fails", func(t *testing.T) {
		env := &fake.Env{BaseAttached: 1}
		cloud := fake.NewCloud(env)
		cloud.LBFlavorID = "" // name staged, no such flavor
		cfg := fake.Config()
		cfg.Prerequisites.LBFlavorName = "lachesis-ha"
		r := Run(context.Background(), cfg, lbScenario(scenario.ActiveStandby), cloud, &fake.Metrics{Env: env})
		if r.OK {
			t.Error("report OK despite an unresolvable lb flavor")
		}
	})

	t.Run("unstaged flavor skips rather than fails", func(t *testing.T) {
		env := &fake.Env{BaseAttached: 1}
		cloud := fake.NewCloud(env)
		cfg := fake.Config()
		cfg.Prerequisites.LBFlavorName = ""
		r := Run(context.Background(), cfg, lbScenario(scenario.ActiveStandby), cloud, &fake.Metrics{Env: env})
		if r.Skip == "" {
			t.Error("want SKIPPED when no lb flavor is staged")
		}
		if !r.OK {
			t.Error("a skip is not a failure")
		}
	})
}
