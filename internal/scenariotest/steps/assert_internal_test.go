package steps

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/fake"
)

func TestSteps_MaxGhosts(t *testing.T) {
	_, nm, senv := nicFixture(t)
	ctx := context.Background()

	nm.ghosts = 3 // a pre-existing ghost on the (shared) agent
	if err := (CaptureStep{}).Run(ctx, senv); err != nil {
		t.Fatal(err)
	}
	// No NEW ghost marked → delta 0 → passes a zero budget, even though
	// the absolute count is non-zero (delta-from-capture, not absolute).
	if err := (MaxGhostsStep{Note: "migration marks no ghost"}).Run(ctx, senv); err != nil {
		t.Fatal(err)
	}
	if !senv.Report.OK {
		t.Fatalf("no new ghost must pass despite a non-zero baseline: %+v", senv.Report.Rows)
	}
	// A newly-marked ghost (e.g. a wrongful migration ghost) fails.
	nm.ghosts = 4
	if err := (MaxGhostsStep{Note: "wrongful ghost"}).Run(ctx, senv); err != nil {
		t.Fatal(err)
	}
	if senv.Report.OK {
		t.Error("a newly-marked ghost must fail the report")
	}
}

// sweepMetrics models a SHARED agent: the global settled counter rises
// on every scrape (other tenants' folds), while the target MAC leaves
// the metadata map only after macGoneAfterLookups lookups.
type sweepMetrics struct {
	settledStart        float64
	macGoneAfterLookups int
	lookups             int
	scrapes             int
}

func (m *sweepMetrics) Scrape(context.Context, string) (scenariotest.ScrapeResult, error) {
	m.scrapes++
	return scenariotest.ScrapeResult{
		Present:      map[string]bool{scenariotest.MetricSettledFlows: true, scenariotest.MetricBytesTotal: true, scenariotest.MetricAttachedInterfaces: true},
		SettledFlows: m.settledStart + float64(m.scrapes), // always rising
	}, nil
}

func (m *sweepMetrics) LookupMAC(_ context.Context, _, _ string) (scenariotest.MACLookup, error) {
	m.lookups++
	if m.lookups >= m.macGoneAfterLookups {
		return scenariotest.MACLookup{Found: false}, nil
	}
	return scenariotest.MACLookup{Found: true, TenantID: "t"}, nil
}

func (m *sweepMetrics) LookupFlows(context.Context, string, string) ([]scenariotest.FlowRow, error) {
	return nil, nil
}

func sweepEnv(t *testing.T, m scenariotest.MetricsSource) *scenariotest.StepEnv {
	t.Helper()
	env := &scenariotest.StepEnv{
		Config:   fake.Config(), // one agent
		State:    &scenariotest.RunState{RunID: "r"},
		Metrics:  m,
		Log:      slog.New(slog.DiscardHandler),
		Report:   &scenariotest.AssertReport{OK: true},
		Captured: scenariotest.Capture{SettledFlows: 10},
	}
	env.RecordMAC("nic", "fa:16:3e:00:00:aa")
	return env
}

// The fix (lachesis#240): ForMACOf waits for the MAC to leave metadata,
// returning as soon as it does — regardless of the rising global counter.
func TestSteps_AwaitSweep_ForMACReturnsWhenGone(t *testing.T) {
	m := &sweepMetrics{settledStart: 10, macGoneAfterLookups: 1}
	if err := (AwaitSweepStep{ForMACOf: "nic", Timeout: time.Second}).Run(context.Background(), sweepEnv(t, m)); err != nil {
		t.Fatalf("await-sweep: %v", err)
	}
	if m.lookups != 1 {
		t.Errorf("lookups = %d, want 1 (MAC gone on first poll)", m.lookups)
	}
}

// The bug it fixes: a rising global settled counter must NOT satisfy a
// ForMACOf wait — while the MAC is still in metadata the step keeps
// waiting and ultimately times out on the MAC, never on the counter.
func TestSteps_AwaitSweep_ForMACIgnoresGlobalSettled(t *testing.T) {
	m := &sweepMetrics{settledStart: 10, macGoneAfterLookups: 1_000_000} // never gone
	err := (AwaitSweepStep{ForMACOf: "nic", Timeout: 60 * time.Millisecond}).Run(context.Background(), sweepEnv(t, m))
	if err == nil || !strings.Contains(err.Error(), "still in metadata") {
		t.Fatalf("want a MAC-still-in-metadata timeout (not a global-settled pass), got %v", err)
	}
}

// Fallback (no ForMACOf) keeps the legacy global-settled behavior.
func TestSteps_AwaitSweep_GlobalFallback(t *testing.T) {
	m := &sweepMetrics{settledStart: 10, macGoneAfterLookups: 1}
	if err := (AwaitSweepStep{Timeout: time.Second}).Run(context.Background(), sweepEnv(t, m)); err != nil {
		t.Fatalf("await-sweep global fallback: %v", err)
	}
	if m.lookups != 0 {
		t.Errorf("global fallback must not call LookupMAC, got %d lookups", m.lookups)
	}
}

// twoAgentCfg returns a config with two agents, for all-agents semantics.
func twoAgentCfg() scenariotest.Config {
	cfg := fake.Config()
	cfg.Cluster.Agents = []scenariotest.AgentConfig{
		{Host: "compute-0", MetricsURL: "http://compute-0:9100/metrics"},
		{Host: "compute-1", MetricsURL: "http://compute-1:9100/metrics"},
	}
	return cfg
}

// perAgentSweep answers LookupMAC per agent URL, and errors when errAll
// is set — for the all-agents and transient-tolerance tests.
type perAgentSweep struct {
	foundOn map[string]bool // metrics URL → MAC still resolves there
	errAll  bool
}

func (m *perAgentSweep) Scrape(context.Context, string) (scenariotest.ScrapeResult, error) {
	return scenariotest.ScrapeResult{Present: map[string]bool{scenariotest.MetricBytesTotal: true, scenariotest.MetricAttachedInterfaces: true}}, nil
}

func (m *perAgentSweep) LookupMAC(_ context.Context, url, _ string) (scenariotest.MACLookup, error) {
	if m.errAll {
		return scenariotest.MACLookup{}, fmt.Errorf("boom: %s unreachable", url)
	}
	return scenariotest.MACLookup{Found: m.foundOn[url]}, nil
}

func (m *perAgentSweep) LookupFlows(context.Context, string, string) ([]scenariotest.FlowRow, error) {
	return nil, nil
}

// Happy path with a real Found→gone transition (fast: shrunk poll interval).
func TestSteps_AwaitSweep_ForMACTransition(t *testing.T) {
	defer func(d time.Duration) { sweepPollInterval = d }(sweepPollInterval)
	sweepPollInterval = 2 * time.Millisecond

	m := &sweepMetrics{settledStart: 10, macGoneAfterLookups: 3} // Found twice, then gone
	env := sweepEnv(t, m)
	if err := (AwaitSweepStep{ForMACOf: "nic", Timeout: time.Second}).Run(context.Background(), env); err != nil {
		t.Fatalf("await-sweep: %v", err)
	}
	if m.lookups < 3 {
		t.Errorf("expected to poll until the MAC folded (>=3 lookups), got %d", m.lookups)
	}
}

// All-agents semantics: while the MAC still resolves on ANY agent the
// wait must not return — it times out here because compute-1 keeps it.
func TestSteps_AwaitSweep_WaitsForAllAgents(t *testing.T) {
	m := &perAgentSweep{foundOn: map[string]bool{
		"http://compute-0:9100/metrics": false, // swept here
		"http://compute-1:9100/metrics": true,  // still present here
	}}
	env := &scenariotest.StepEnv{
		Config: twoAgentCfg(), State: &scenariotest.RunState{RunID: "r"}, Metrics: m,
		Log: slog.New(slog.DiscardHandler), Report: &scenariotest.AssertReport{OK: true},
	}
	env.RecordMAC("nic", "fa:16:3e:00:00:aa")
	err := (AwaitSweepStep{ForMACOf: "nic", Timeout: 60 * time.Millisecond}).Run(context.Background(), env)
	if err == nil || !strings.Contains(err.Error(), "still in metadata") {
		t.Fatalf("must keep waiting while any agent still has the MAC; got %v", err)
	}
}

// Transient lookup errors must not abort the wait: it keeps polling and
// surfaces the last error on timeout, rather than returning immediately.
func TestSteps_AwaitSweep_ToleratesTransientErrors(t *testing.T) {
	m := &perAgentSweep{errAll: true}
	env := sweepEnv(t, m)
	start := time.Now()
	err := (AwaitSweepStep{ForMACOf: "nic", Timeout: 60 * time.Millisecond}).Run(context.Background(), env)
	if err == nil || !strings.Contains(err.Error(), "last lookup error") {
		t.Fatalf("want a timeout carrying the last lookup error (not an immediate abort), got %v", err)
	}
	if time.Since(start) < 40*time.Millisecond {
		t.Errorf("returned too fast (%s) — it aborted on the first error instead of waiting", time.Since(start))
	}
}

// resolvedMetrics reports a fixed unresolved-resolved total, for ResolvedGrewStep.
type resolvedMetrics struct{ resolved float64 }

func (m resolvedMetrics) Scrape(context.Context, string) (scenariotest.ScrapeResult, error) {
	return scenariotest.ScrapeResult{
		Present:            map[string]bool{scenariotest.MetricUnresolvedResolved: true, scenariotest.MetricBytesTotal: true, scenariotest.MetricAttachedInterfaces: true},
		UnresolvedResolved: m.resolved,
	}, nil
}

func (resolvedMetrics) LookupMAC(context.Context, string, string) (scenariotest.MACLookup, error) {
	return scenariotest.MACLookup{}, nil
}

func (resolvedMetrics) LookupFlows(context.Context, string, string) ([]scenariotest.FlowRow, error) {
	return nil, nil
}

func TestResolvedGrewStep(t *testing.T) {
	// Timing isn't under test: shrink the poll so the timeout (fail) cases
	// resolve in milliseconds.
	defer func(d time.Duration) { sweepPollInterval = d }(sweepPollInterval)
	sweepPollInterval = time.Millisecond

	cases := []struct {
		name          string
		base, current float64
		min           int64
		wantPass      bool
	}{
		{"late-bind fired (grew past floor)", 3, 12, 1, true},
		{"exactly at floor", 3, 4, 1, true},
		{"none resolved — fails", 3, 3, 1, false},
		{"grew but short of floor", 3, 5, 5, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := &scenariotest.StepEnv{
				Config:   fake.Config(),
				State:    &scenariotest.RunState{},
				Metrics:  resolvedMetrics{resolved: tc.current},
				Log:      slog.New(slog.DiscardHandler),
				Report:   &scenariotest.AssertReport{OK: true},
				Captured: scenariotest.Capture{Resolved: tc.base},
			}
			step := ResolvedGrewStep{Min: tc.min, Timeout: 10 * time.Millisecond}
			if err := step.Run(context.Background(), env); err != nil {
				t.Fatalf("Run: %v", err)
			}
			row := env.Report.Rows[len(env.Report.Rows)-1]
			if row.Pass != tc.wantPass {
				t.Errorf("Pass = %v, want %v (delta %.0f, min %d)", row.Pass, tc.wantPass, row.Delta, tc.min)
			}
		})
	}
}

// evictionMetrics reports a fixed pressure-relief eviction total, for
// EvictionsGrewStep.
type evictionMetrics struct{ evictions float64 }

func (m evictionMetrics) Scrape(context.Context, string) (scenariotest.ScrapeResult, error) {
	return scenariotest.ScrapeResult{
		Present:                 map[string]bool{scenariotest.MetricGCEvictions: true, scenariotest.MetricBytesTotal: true, scenariotest.MetricAttachedInterfaces: true},
		PressureReliefEvictions: m.evictions,
	}, nil
}

func (evictionMetrics) LookupMAC(context.Context, string, string) (scenariotest.MACLookup, error) {
	return scenariotest.MACLookup{}, nil
}

func (evictionMetrics) LookupFlows(context.Context, string, string) ([]scenariotest.FlowRow, error) {
	return nil, nil
}

func TestEvictionsGrewStep(t *testing.T) {
	// Timing isn't under test: shrink the poll so the timeout (fail) cases
	// resolve in milliseconds.
	defer func(d time.Duration) { sweepPollInterval = d }(sweepPollInterval)
	sweepPollInterval = time.Millisecond

	cases := []struct {
		name          string
		base, current float64
		min           int64
		wantPass      bool
	}{
		{"relief ran (grew past floor)", 2000, 5858, 1, true},
		{"exactly at floor", 2000, 2001, 1, true},
		{"never tripped the watermark — fails", 2000, 2000, 1, false},
		{"grew but short of floor", 2000, 2500, 1000, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := &scenariotest.StepEnv{
				Config:   fake.Config(),
				State:    &scenariotest.RunState{},
				Metrics:  evictionMetrics{evictions: tc.current},
				Log:      slog.New(slog.DiscardHandler),
				Report:   &scenariotest.AssertReport{OK: true},
				Captured: scenariotest.Capture{Evictions: tc.base},
			}
			step := EvictionsGrewStep{Min: tc.min, Timeout: 10 * time.Millisecond}
			if err := step.Run(context.Background(), env); err != nil {
				t.Fatalf("Run: %v", err)
			}
			row := env.Report.Rows[len(env.Report.Rows)-1]
			if row.Pass != tc.wantPass {
				t.Errorf("Pass = %v, want %v (delta %.0f, min %d)", row.Pass, tc.wantPass, row.Delta, tc.min)
			}
		})
	}
}

// TestEpochStep pins the assertion semantics: Changed=false demands
// the captured epoch back exactly (and nonzero — an absent gauge must
// not pass as "unchanged"); Changed=true demands a strictly later one.
func TestEpochStep(t *testing.T) {
	cases := []struct {
		name     string
		captured float64
		current  float64
		changed  bool
		wantPass bool
	}{
		{"carried epoch passes unchanged", 1000, 1000, false, true},
		{"new epoch fails unchanged", 1000, 2000, false, false},
		{"zero gauge fails unchanged", 0, 0, false, false},
		{"later epoch passes changed", 1000, 2000, true, true},
		{"same epoch fails changed", 1000, 1000, true, false},
		{"earlier epoch fails changed", 2000, 1000, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := fake.Config()
			host := cfg.Cluster.Agents[0].Host
			env := &scenariotest.StepEnv{
				Config:   cfg,
				Log:      slog.New(slog.DiscardHandler),
				Report:   &scenariotest.AssertReport{OK: true},
				Metrics:  &epochMetrics{epoch: tc.current},
				Captured: scenariotest.Capture{Epochs: map[string]float64{host: tc.captured}},
			}
			if err := (EpochStep{Changed: tc.changed}).Run(context.Background(), env); err != nil {
				t.Fatalf("Run: %v", err)
			}
			rows := env.Report.Rows
			if len(rows) != 1 {
				t.Fatalf("rows = %d, want 1", len(rows))
			}
			if rows[0].Pass != tc.wantPass {
				t.Fatalf("pass = %v, want %v (baseline %v current %v)", rows[0].Pass, tc.wantPass, tc.captured, tc.current)
			}
		})
	}
}

// epochMetrics is a scenariotest.MetricsSource stub returning a fixed epoch gauge.
type epochMetrics struct{ epoch float64 }

func (m *epochMetrics) Scrape(context.Context, string) (scenariotest.ScrapeResult, error) {
	return scenariotest.ScrapeResult{CountersResetEpoch: m.epoch}, nil
}

func (m *epochMetrics) LookupMAC(context.Context, string, string) (scenariotest.MACLookup, error) {
	return scenariotest.MACLookup{}, nil
}

func (m *epochMetrics) LookupFlows(context.Context, string, string) ([]scenariotest.FlowRow, error) {
	return nil, nil
}
