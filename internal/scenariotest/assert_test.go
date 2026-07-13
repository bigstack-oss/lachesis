package scenariotest

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// assertState builds the run-state drive would have left: resolved
// project, attach record, and a captured baseline.
func assertState() *RunState {
	rs := NewRunState("run1", "same", "scenariotest")
	rs.Projects = map[string]ProjectRef{"T1": {Name: "scenariotest-T1", ID: "uuid-t1", Created: true}}
	rs.Attach = AttachRecord{Target: 7}
	rs.Baseline = []BytesSample{
		{TenantID: "uuid-t1", Zone: "same_tenant", Direction: "tx", Value: 100},
		{TenantID: "uuid-t1", Zone: "same_tenant", Direction: "rx", Value: 200},
	}
	return rs
}

func assertScenario() *Scenario {
	sc := sameTenantScenario()
	sc.Expect = []Expect{
		{TenantID: "T1", Zone: "same_tenant", Direction: "tx", MinBytes: 1 << 20},
		{TenantID: "T1", Zone: "same_tenant", Direction: "rx", MinBytes: 1 << 20},
	}
	return sc
}

func runAssertFixture(t *testing.T, sc *Scenario, rs *RunState, m MetricsSource, timeout time.Duration) (AssertReport, string, error) {
	t.Helper()
	reportPath := t.TempDir() + "/report.json"
	rep, err := Assert(context.Background(), AssertOptions{
		Config:        testConfig(),
		Scenario:      sc,
		State:         rs,
		ReportPath:    reportPath,
		Metrics:       m,
		Log:           io.Discard,
		SettleTimeout: timeout,
	})
	return rep, reportPath, err
}

func TestAssert_Pass(t *testing.T) {
	m := driveMetrics{attached: 7, bytes: []BytesSample{
		{TenantID: "uuid-t1", Zone: "same_tenant", Direction: "tx", Value: 100 + 2<<20},
		{TenantID: "uuid-t1", Zone: "same_tenant", Direction: "rx", Value: 200 + 2<<20},
	}}
	rep, path, err := runAssertFixture(t, assertScenario(), assertState(), m, time.Second)
	if err != nil {
		t.Fatalf("Assert: %v", err)
	}
	if !rep.OK {
		t.Fatalf("want OK report, got %+v", rep)
	}
	for _, row := range rep.Rows {
		if !row.Pass || row.Delta != float64(2<<20) || row.TenantID != "uuid-t1" {
			t.Errorf("row wrong: %+v", row)
		}
	}
	// The report persisted and round-trips.
	saved := mustLoadReport(t, path)
	if !saved.OK || len(saved.Rows) != 2 {
		t.Errorf("persisted report wrong: %+v", saved)
	}
}

func TestAssert_FailBelowMin(t *testing.T) {
	m := driveMetrics{attached: 7, bytes: []BytesSample{
		{TenantID: "uuid-t1", Zone: "same_tenant", Direction: "tx", Value: 100 + 512},
		{TenantID: "uuid-t1", Zone: "same_tenant", Direction: "rx", Value: 200 + 2<<20},
	}}
	rep, path, err := runAssertFixture(t, assertScenario(), assertState(), m, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("Assert: %v", err)
	}
	if rep.OK {
		t.Fatal("want failed report")
	}
	if rep.Rows[0].Pass || !rep.Rows[1].Pass {
		t.Errorf("row verdicts wrong: %+v", rep.Rows)
	}
	// Failed reports persist too — the evidence must survive.
	if saved := mustLoadReport(t, path); saved.OK {
		t.Error("persisted report should record the failure")
	}
}

func TestAssert_NegativeDeltaFlagsBaseline(t *testing.T) {
	// Counter dropped below baseline (ghost GC evicted a prior run's
	// flows after the baseline was captured).
	m := driveMetrics{attached: 7, bytes: []BytesSample{
		{TenantID: "uuid-t1", Zone: "same_tenant", Direction: "tx", Value: 10},
		{TenantID: "uuid-t1", Zone: "same_tenant", Direction: "rx", Value: 200 + 2<<20},
	}}
	rep, _, err := runAssertFixture(t, assertScenario(), assertState(), m, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("Assert: %v", err)
	}
	if rep.OK {
		t.Fatal("want failed report")
	}
	if !strings.Contains(rep.Rows[0].Note, "re-run drive") {
		t.Errorf("negative delta must carry the re-drive note, got %+v", rep.Rows[0])
	}
}

// settleMetrics reports counters that cross the threshold on the
// second scrape round, proving the poll-until-settle loop.
type settleMetrics struct{ calls *int }

func (m settleMetrics) Scrape(context.Context, string) (ScrapeResult, error) {
	*m.calls++
	v := 100.0
	if *m.calls > 1 {
		v = 100 + float64(2<<20)
	}
	return ScrapeResult{Bytes: []BytesSample{
		{TenantID: "uuid-t1", Zone: "same_tenant", Direction: "tx", Value: v},
		{TenantID: "uuid-t1", Zone: "same_tenant", Direction: "rx", Value: 200 + float64(2<<20)},
	}}, nil
}

func TestAssert_SettlesOnLaterScrape(t *testing.T) {
	calls := 0
	rep, _, err := runAssertFixture(t, assertScenario(), assertState(), settleMetrics{&calls}, 30*time.Second)
	if err != nil {
		t.Fatalf("Assert: %v", err)
	}
	if !rep.OK {
		t.Fatalf("want OK after settle, got %+v", rep)
	}
	if calls < 2 {
		t.Errorf("expected at least 2 scrape rounds, got %d", calls)
	}
}

func TestAssert_NoBaselineErrors(t *testing.T) {
	rs := assertState()
	rs.Baseline = nil
	_, _, err := runAssertFixture(t, assertScenario(), rs, driveMetrics{}, time.Second)
	if err == nil || !strings.Contains(err.Error(), "drive first") {
		t.Fatalf("want no-baseline error, got %v", err)
	}
}

func TestAssert_UnknownTenantErrors(t *testing.T) {
	sc := assertScenario()
	sc.Expect = []Expect{{TenantID: "T9", Zone: "same_tenant", Direction: "tx", MinBytes: 1}}
	_, _, err := runAssertFixture(t, sc, assertState(), driveMetrics{}, time.Second)
	if err == nil || !strings.Contains(err.Error(), "no such project") {
		t.Fatalf("want unknown-tenant error, got %v", err)
	}
}

func TestAssert_MultiAgentTuplesSum(t *testing.T) {
	// Two agents each expose half the driven bytes for the same
	// tuple; the evaluation must sum them.
	cfg := testConfig()
	cfg.Cluster.Agents = append(cfg.Cluster.Agents, AgentConfig{Host: "compute-1", MetricsURL: "http://compute-1:9100/metrics"})
	rs := assertState()
	rs.Baseline = []BytesSample{ // baseline also captured across both agents
		{TenantID: "uuid-t1", Zone: "same_tenant", Direction: "tx", Value: 50},
		{TenantID: "uuid-t1", Zone: "same_tenant", Direction: "tx", Value: 50},
	}
	sc := assertScenario()
	sc.Expect = sc.Expect[:1]               // tx only
	m := driveMetrics{bytes: []BytesSample{ // per agent scrape: half the traffic each
		{TenantID: "uuid-t1", Zone: "same_tenant", Direction: "tx", Value: 50 + 1<<19},
	}}
	reportPath := t.TempDir() + "/report.json"
	rep, err := Assert(context.Background(), AssertOptions{
		Config: cfg, Scenario: sc, State: rs, ReportPath: reportPath,
		Metrics: m, Log: io.Discard, SettleTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Sum over 2 agents: current = 2×(50+512Ki), baseline = 100 → delta = 1 MiB.
	if !rep.OK || rep.Rows[0].Delta != float64(1<<20) {
		t.Fatalf("multi-agent sum wrong: %+v", rep.Rows[0])
	}
}

func TestDefaultReportPath(t *testing.T) {
	if got := DefaultReportPath(".scenariotest/x-abc.json"); got != ".scenariotest/x-abc-report.json" {
		t.Errorf("DefaultReportPath = %q", got)
	}
}

func mustLoadReport(t *testing.T, path string) AssertReport {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	var r AssertReport
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("parse report: %v", err)
	}
	return r
}
