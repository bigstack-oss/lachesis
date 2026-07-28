package assert

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/fake"
)

// assertState builds the run-state drive would have left: resolved
// project, attach record, and a captured baseline.
func assertState() *scenariotest.RunState {
	rs := scenariotest.NewRunState("run1", "same", "scenariotest")
	rs.Projects = map[string]scenariotest.ProjectRef{"T1": {Name: "scenariotest-T1", ID: "uuid-t1", Created: true}}
	rs.Attach = scenariotest.AttachRecord{Target: 7}
	rs.Baseline = []scenariotest.BytesSample{
		{TenantID: "uuid-t1", Zone: "same_tenant", Direction: "tx", Value: 100},
		{TenantID: "uuid-t1", Zone: "same_tenant", Direction: "rx", Value: 200},
	}
	return rs
}

func assertScenario() *scenariotest.Scenario {
	sc := fake.SameTenantScenario()
	sc.Expect = []scenariotest.Expect{
		{TenantID: "T1", Zone: "same_tenant", Direction: "tx", MinBytes: 1 << 20},
		{TenantID: "T1", Zone: "same_tenant", Direction: "rx", MinBytes: 1 << 20},
	}
	return sc
}

func runAssertFixture(t *testing.T, sc *scenariotest.Scenario, rs *scenariotest.RunState, m scenariotest.MetricsSource, timeout time.Duration) (scenariotest.AssertReport, string, error) {
	t.Helper()
	reportPath := t.TempDir() + "/report.json"
	rep, err := Run(context.Background(), Options{
		Config:           fake.Config(),
		Scenario:         sc,
		State:            rs,
		ReportPath:       reportPath,
		Metrics:          m,
		Log:              slog.New(slog.DiscardHandler),
		StabilizeTimeout: timeout,
	})
	return rep, reportPath, err
}

func TestAssert_Pass(t *testing.T) {
	m := fake.HealthyMetrics{Attached: 7, Bytes: []scenariotest.BytesSample{
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
	m := fake.HealthyMetrics{Attached: 7, Bytes: []scenariotest.BytesSample{
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
	m := fake.HealthyMetrics{Attached: 7, Bytes: []scenariotest.BytesSample{
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

// stabilizeMetrics reports counters that cross the threshold on the
// second scrape round, proving the poll-until-stabilize loop.
type stabilizeMetrics struct {
	fake.InstantMACs
	Calls *int
}

func (m stabilizeMetrics) Scrape(context.Context, string) (scenariotest.ScrapeResult, error) {
	*m.Calls++
	v := 100.0
	if *m.Calls > 1 {
		v = 100 + float64(2<<20)
	}
	return scenariotest.ScrapeResult{Bytes: []scenariotest.BytesSample{
		{TenantID: "uuid-t1", Zone: "same_tenant", Direction: "tx", Value: v},
		{TenantID: "uuid-t1", Zone: "same_tenant", Direction: "rx", Value: 200 + float64(2<<20)},
	}}, nil
}

func TestAssert_StabilizesOnLaterScrape(t *testing.T) {
	calls := 0
	rep, _, err := runAssertFixture(t, assertScenario(), assertState(), stabilizeMetrics{Calls: &calls}, 30*time.Second)
	if err != nil {
		t.Fatalf("Assert: %v", err)
	}
	if !rep.OK {
		t.Fatalf("want OK after stabilizing, got %+v", rep)
	}
	if calls < 2 {
		t.Errorf("expected at least 2 scrape rounds, got %d", calls)
	}
}

func TestAssert_NoBaselineErrors(t *testing.T) {
	rs := assertState()
	rs.Baseline = nil
	_, _, err := runAssertFixture(t, assertScenario(), rs, fake.HealthyMetrics{}, time.Second)
	if err == nil || !strings.Contains(err.Error(), "drive first") {
		t.Fatalf("want no-baseline error, got %v", err)
	}
}

func TestAssert_UnknownTenantErrors(t *testing.T) {
	sc := assertScenario()
	sc.Expect = []scenariotest.Expect{{TenantID: "T9", Zone: "same_tenant", Direction: "tx", MinBytes: 1}}
	_, _, err := runAssertFixture(t, sc, assertState(), fake.HealthyMetrics{}, time.Second)
	if err == nil || !strings.Contains(err.Error(), "no such project") {
		t.Fatalf("want unknown-tenant error, got %v", err)
	}
}

func TestAssert_MultiAgentTuplesSum(t *testing.T) {
	// Two agents each expose half the driven bytes for the same
	// tuple; the evaluation must sum them.
	cfg := fake.Config()
	cfg.Cluster.Agents = append(cfg.Cluster.Agents, scenariotest.AgentConfig{Host: "compute-1", MetricsURL: "http://compute-1:9100/metrics"})
	rs := assertState()
	rs.Baseline = []scenariotest.BytesSample{ // baseline also captured across both agents
		{TenantID: "uuid-t1", Zone: "same_tenant", Direction: "tx", Value: 50},
		{TenantID: "uuid-t1", Zone: "same_tenant", Direction: "tx", Value: 50},
	}
	sc := assertScenario()
	sc.Expect = sc.Expect[:1]                                   // tx only
	m := fake.HealthyMetrics{Bytes: []scenariotest.BytesSample{ // per agent scrape: half the traffic each
		{TenantID: "uuid-t1", Zone: "same_tenant", Direction: "tx", Value: 50 + 1<<19},
	}}
	reportPath := t.TempDir() + "/report.json"
	rep, err := Run(context.Background(), Options{
		Config: cfg, Scenario: sc, State: rs, ReportPath: reportPath,
		Metrics: m, Log: slog.New(slog.DiscardHandler), StabilizeTimeout: time.Second,
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
	if got := scenariotest.DefaultReportPath(".scenariotest/x-abc.json"); got != ".scenariotest/x-abc-report.json" {
		t.Errorf("DefaultReportPath = %q", got)
	}
}

func mustLoadReport(t *testing.T, path string) scenariotest.AssertReport {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	var r scenariotest.AssertReport
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("parse report: %v", err)
	}
	return r
}

// extAssertState is assertState plus external-labeled baseline series
// and a per-server baseline for the created vm-a.
func extAssertState() *scenariotest.RunState {
	rs := assertState()
	rs.Baseline = []scenariotest.BytesSample{
		{TenantID: "uuid-t1", Zone: "external", ExternalNetwork: "ext", Direction: "tx", Value: 1000},
		{TenantID: "uuid-t1", Zone: "external", ExternalNetwork: "none", Direction: "tx", Value: 500},
	}
	rs.BaselineServers = []scenariotest.ServerSample{
		{ServerID: "srv-a", TenantID: "uuid-t1", Zone: "external", ExternalNetwork: "ext", Direction: "tx", Value: 800},
	}
	rs.Servers = []scenariotest.ResourceRef{{DSLID: "vm-a", ID: "srv-a", ProjectID: "uuid-t1"}}
	return rs
}

// TestAssert_ExternalNetworkFilter: an expectation pinning
// ExternalNetwork must count only that label's series — growth on the
// "none" bucket cannot satisfy it — and the DSL marker id ("net-ext")
// resolves to the config's provider network name ("ext"), mirroring
// realize's binding.
func TestAssert_ExternalNetworkFilter(t *testing.T) {
	sc := fake.SameTenantScenario()
	sc.Expect = []scenariotest.Expect{
		{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 1 << 20, ExternalNetwork: "net-ext"},
	}
	// Only the "none" bucket grew: the pinned expectation must FAIL.
	m := fake.HealthyMetrics{Attached: 7, Bytes: []scenariotest.BytesSample{
		{TenantID: "uuid-t1", Zone: "external", ExternalNetwork: "ext", Direction: "tx", Value: 1000},
		{TenantID: "uuid-t1", Zone: "external", ExternalNetwork: "none", Direction: "tx", Value: 500 + 2<<20},
	}}
	rep, _, err := runAssertFixture(t, sc, extAssertState(), m, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("Assert: %v", err)
	}
	if rep.OK {
		t.Fatal("growth on external_network=none must not satisfy an ext-pinned expectation")
	}
	if rep.Rows[0].ExternalNetwork != "ext" {
		t.Errorf("DSL marker not resolved: row ext = %q, want %q", rep.Rows[0].ExternalNetwork, "ext")
	}

	// Now the pinned bucket grows: PASS.
	m = fake.HealthyMetrics{Attached: 7, Bytes: []scenariotest.BytesSample{
		{TenantID: "uuid-t1", Zone: "external", ExternalNetwork: "ext", Direction: "tx", Value: 1000 + 2<<20},
		{TenantID: "uuid-t1", Zone: "external", ExternalNetwork: "none", Direction: "tx", Value: 500},
	}}
	rep, _, err = runAssertFixture(t, sc, extAssertState(), m, time.Second)
	if err != nil {
		t.Fatalf("Assert: %v", err)
	}
	if !rep.OK || rep.Rows[0].Delta != float64(2<<20) {
		t.Errorf("ext-pinned expectation should pass on its own bucket: %+v", rep.Rows[0])
	}
}

// TestAssert_VMTargetsServerFamily: an expectation with a VM target
// lower-bounds lachesis_server_bytes_total for the run's created
// server, resolved from the run-state.
func TestAssert_VMTargetsServerFamily(t *testing.T) {
	sc := fake.SameTenantScenario()
	sc.Expect = []scenariotest.Expect{
		{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 1 << 20, ExternalNetwork: "net-ext", VM: "vm-a"},
	}
	m := fake.HealthyMetrics{Attached: 7,
		Bytes: []scenariotest.BytesSample{
			{TenantID: "uuid-t1", Zone: "external", ExternalNetwork: "ext", Direction: "tx", Value: 1000 + 2<<20},
		},
		Servers: []scenariotest.ServerSample{
			{ServerID: "srv-a", TenantID: "uuid-t1", Zone: "external", ExternalNetwork: "ext", Direction: "tx", Value: 800 + 2<<20},
			{ServerID: "srv-other", TenantID: "uuid-t1", Zone: "external", ExternalNetwork: "ext", Direction: "tx", Value: 9e9},
		}}
	rep, _, err := runAssertFixture(t, sc, extAssertState(), m, time.Second)
	if err != nil {
		t.Fatalf("Assert: %v", err)
	}
	row := rep.Rows[0]
	if !rep.OK || row.ServerID != "srv-a" || row.Delta != float64(2<<20) {
		t.Errorf("VM-targeted row wrong (must diff srv-a only, ignoring srv-other): %+v", row)
	}
}

// TestAssert_VMExpectRefusesPreFamilyAgent: a VM-targeted expectation
// against an agent exposing no per-server family is an evaluation
// error — not a silent zero-delta failure.
func TestAssert_VMExpectRefusesPreFamilyAgent(t *testing.T) {
	sc := fake.SameTenantScenario()
	sc.Expect = []scenariotest.Expect{
		{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 1, VM: "vm-a"},
	}
	m := fake.HealthyMetrics{Attached: 7, Bytes: []scenariotest.BytesSample{
		{TenantID: "uuid-t1", Zone: "external", ExternalNetwork: "ext", Direction: "tx", Value: 1e9},
	}}
	_, _, err := runAssertFixture(t, sc, extAssertState(), m, 50*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "per-server") {
		t.Fatalf("want per-server-family refusal error, got %v", err)
	}
}

// TestResolveExternalNetwork pins the three resolution tiers: a
// CreateExternalNets marker resolves to its run-mangled created name
// (the label the agent really emits — NOT the provider network), a
// provider-bound external marker resolves to the config's provider
// network, and everything else (empty, "none", literals) passes
// through.
func TestResolveExternalNetwork(t *testing.T) {
	sc := fake.ExtPathTopology() // declares net-ext (provider) + net-ext2 (created)
	cfg := fake.Config()
	rs := scenariotest.NewRunState("run1", sc.Name, cfg.Naming.Prefix)

	cases := []struct{ in, want string }{
		{"", ""},
		{"none", "none"},
		{"net-ext", "ext"}, // provider-bound marker
		{"net-ext2", "scenariotest-run1-net-ext2"}, // created marker → mangled name
		{"public-9", "public-9"},                   // literal, not a marker
	}
	for _, tc := range cases {
		if got := resolveExternalNetwork(sc, cfg, rs, tc.in); got != tc.want {
			t.Errorf("resolveExternalNetwork(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// twoAgentNodeFixture: compute-0 carries the driven 1 MiB, compute-1
// stays flat — the divergence only a node-targeted expectation can see.
func twoAgentNodeFixture() (scenariotest.Config, *scenariotest.RunState, scenariotest.MetricsSource) {
	cfg := fake.Config()
	cfg.Cluster.Agents = append(cfg.Cluster.Agents, scenariotest.AgentConfig{Host: "compute-1", MetricsURL: "http://compute-1:9100/metrics"})
	rs := assertState()
	rs.Baseline = []scenariotest.BytesSample{
		{TenantID: "uuid-t1", Zone: "same_tenant", Direction: "tx", Value: 50, Node: "compute-0"},
		{TenantID: "uuid-t1", Zone: "same_tenant", Direction: "tx", Value: 50, Node: "compute-1"},
	}
	m := fake.PerNode{ByURL: map[string]scenariotest.ScrapeResult{
		cfg.Cluster.Agents[0].MetricsURL: {
			Present: map[string]bool{scenariotest.MetricBytesTotal: true},
			Bytes:   []scenariotest.BytesSample{{TenantID: "uuid-t1", Zone: "same_tenant", Direction: "tx", Value: 50 + 1<<20}},
		},
		cfg.Cluster.Agents[1].MetricsURL: {
			Present: map[string]bool{scenariotest.MetricBytesTotal: true},
			Bytes:   []scenariotest.BytesSample{{TenantID: "uuid-t1", Zone: "same_tenant", Direction: "tx", Value: 50}},
		},
	}}
	return cfg, rs, m
}

func TestAssert_NodeTargetSplitsAgents(t *testing.T) {
	cfg, rs, m := twoAgentNodeFixture()
	sc := assertScenario()
	sc.Expect = []scenariotest.Expect{
		// The driving node's tap carries the delta...
		{TenantID: "T1", Zone: "same_tenant", Direction: "tx", Node: "node:0", MinBytes: 1 << 20},
		// ...the flat node's does not — a literal host target resolves too.
		{TenantID: "T1", Zone: "same_tenant", Direction: "tx", Node: "compute-1", MinBytes: 1},
	}
	rep, err := Run(context.Background(), Options{
		Config: cfg, Scenario: sc, State: rs, ReportPath: t.TempDir() + "/report.json",
		// Short: the failing row makes the stabilize loop exhaust the
		// timeout by design; there is nothing to wait for.
		Metrics: m, Log: slog.New(slog.DiscardHandler), StabilizeTimeout: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatal("flat node's expectation should fail the report")
	}
	if r := rep.Rows[0]; !r.Pass || r.Node != "compute-0" || r.Delta != float64(1<<20) {
		t.Errorf("node:0 row wrong: %+v", r)
	}
	if r := rep.Rows[1]; r.Pass || r.Node != "compute-1" || r.Delta != 0 {
		t.Errorf("compute-1 row wrong: %+v", r)
	}
}

func TestAssert_CollectiveUnchangedByNodes(t *testing.T) {
	// The same divergent cluster, asserted without a node target: the
	// cluster-wide sum sees the delta exactly as before per-node capture.
	cfg, rs, m := twoAgentNodeFixture()
	sc := assertScenario()
	sc.Expect = []scenariotest.Expect{{TenantID: "T1", Zone: "same_tenant", Direction: "tx", MinBytes: 1 << 20}}
	rep, err := Run(context.Background(), Options{
		Config: cfg, Scenario: sc, State: rs, ReportPath: t.TempDir() + "/report.json",
		Metrics: m, Log: slog.New(slog.DiscardHandler), StabilizeTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK || rep.Rows[0].Node != "" {
		t.Fatalf("collective row wrong: %+v", rep.Rows[0])
	}
}

func TestAssert_NodeTargetErrors(t *testing.T) {
	cfg, rs, m := twoAgentNodeFixture()
	for name, tc := range map[string]struct {
		node    string
		rs      *scenariotest.RunState
		wantErr string
	}{
		"unknown literal host": {node: "compute-9", rs: rs, wantErr: "not a configured agent host"},
		"slot beyond agents":   {node: "node:5", rs: rs, wantErr: "config lists 2 agent(s)"},
		"malformed slot":       {node: "node:one", rs: rs, wantErr: "want node:<index>"},
		"baseline has no node": {node: "node:0", rs: assertState(), wantErr: "re-run drive"},
	} {
		t.Run(name, func(t *testing.T) {
			sc := assertScenario()
			sc.Expect = []scenariotest.Expect{{TenantID: "T1", Zone: "same_tenant", Direction: "tx", Node: tc.node, MinBytes: 1}}
			_, err := Run(context.Background(), Options{
				Config: cfg, Scenario: sc, State: tc.rs, ReportPath: t.TempDir() + "/report.json",
				Metrics: m, Log: slog.New(slog.DiscardHandler), StabilizeTimeout: time.Second,
			})
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestAssert_NodeWithVMTarget(t *testing.T) {
	// Node combines with the per-server family: only the target node's
	// server series count.
	cfg, rs, _ := twoAgentNodeFixture()
	rs.Servers = []scenariotest.ResourceRef{{DSLID: "vm-a", ID: "srv-1"}}
	rs.BaselineServers = []scenariotest.ServerSample{
		{ServerID: "srv-1", TenantID: "uuid-t1", Zone: "same_tenant", Direction: "tx", Value: 10, Node: "compute-0"},
		{ServerID: "srv-1", TenantID: "uuid-t1", Zone: "same_tenant", Direction: "tx", Value: 10, Node: "compute-1"},
	}
	m := fake.PerNode{ByURL: map[string]scenariotest.ScrapeResult{
		cfg.Cluster.Agents[0].MetricsURL: {
			Present: map[string]bool{scenariotest.MetricBytesTotal: true, scenariotest.MetricServerBytesTotal: true},
			Bytes:   []scenariotest.BytesSample{{TenantID: "uuid-t1", Zone: "same_tenant", Direction: "tx", Value: 50 + 1<<20}},
			Servers: []scenariotest.ServerSample{{ServerID: "srv-1", TenantID: "uuid-t1", Zone: "same_tenant", Direction: "tx", Value: 10 + 1<<20}},
		},
		cfg.Cluster.Agents[1].MetricsURL: {
			Present: map[string]bool{scenariotest.MetricBytesTotal: true, scenariotest.MetricServerBytesTotal: true},
			Bytes:   []scenariotest.BytesSample{{TenantID: "uuid-t1", Zone: "same_tenant", Direction: "tx", Value: 50}},
			Servers: []scenariotest.ServerSample{{ServerID: "srv-1", TenantID: "uuid-t1", Zone: "same_tenant", Direction: "tx", Value: 10}},
		},
	}}
	sc := assertScenario()
	sc.Expect = []scenariotest.Expect{{TenantID: "T1", Zone: "same_tenant", Direction: "tx", VM: "vm-a", Node: "node:0", MinBytes: 1 << 20}}
	rep, err := Run(context.Background(), Options{
		Config: cfg, Scenario: sc, State: rs, ReportPath: t.TempDir() + "/report.json",
		Metrics: m, Log: slog.New(slog.DiscardHandler), StabilizeTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	r := rep.Rows[0]
	if !r.Pass || r.Node != "compute-0" || r.ServerID != "srv-1" || r.Delta != float64(1<<20) {
		t.Fatalf("node+VM row wrong: %+v", r)
	}
}
