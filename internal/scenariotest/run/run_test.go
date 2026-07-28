package run

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/fake"
)

// runScenario is the two-VM fixture with a drivable flow and an
// assertable expectation.
func runScenario() *scenariotest.Scenario {
	sc := fake.SameTenantScenario()
	sc.Flows = []scenariotest.Flow{{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP}}
	sc.Expect = []scenariotest.Expect{{TenantID: "T1", Zone: "same_tenant", Direction: "tx", MinBytes: 1 << 20}}
	return sc
}

// runMetrics serves the whole composed loop: the attach gauge follows
// the fake env (gate + recheck), and the bytes counter climbs by 2 MiB
// per scrape so assert's first delta after drive's baseline passes.
type runMetrics struct {
	fake.InstantMACs
	Env *fake.Env
	val float64
}

func (m *runMetrics) Scrape(context.Context, string) (scenariotest.ScrapeResult, error) {
	m.val += float64(2 << 20)
	return scenariotest.ScrapeResult{
		Present:            map[string]bool{scenariotest.MetricBytesTotal: true, scenariotest.MetricAttachedInterfaces: true},
		AttachedInterfaces: m.Env.BaseAttached + float64(m.Env.Booted),
		AttachFailures:     m.Env.Failures,
		Bytes: []scenariotest.BytesSample{
			{TenantID: "uuid-t1", Zone: "same_tenant", Direction: "tx", Value: m.val},
		},
	}, nil
}

// baseRunOptions is the canonical fixture: fake env/cloud with the T1
// project pre-seeded (so the tenant UUID is stable and the metrics
// fake can label its series), climbing metrics, and a temp state
// path. Tests mutate the returned options (Keep, State, Exec, …).
func baseRunOptions(t *testing.T) (*fake.Cloud, Options) {
	t.Helper()
	env := &fake.Env{BaseAttached: 5}
	cloud := fake.NewCloud(env)
	cloud.PreProjects["scenariotest-T1"] = "uuid-t1"
	statePath := t.TempDir() + "/state.json"
	return cloud, Options{
		Config:     fake.Config(),
		Scenario:   runScenario(),
		RunID:      "run1",
		StatePath:  statePath,
		ReportPath: scenariotest.DefaultReportPath(statePath),
		Cloud:      cloud,
		Metrics:    &runMetrics{Env: env},
		Exec:       &fake.Exec{},
		Log:        slog.New(slog.DiscardHandler),
		SinkDelay:  -1,
	}
}

func runFixture(t *testing.T, keep bool, exec scenariotest.VMExec) (*fake.Cloud, scenariotest.AssertReport, string, error) {
	t.Helper()
	cloud, opts := baseRunOptions(t)
	opts.Keep = keep
	opts.Exec = exec
	rep, err := Run(context.Background(), opts)
	return cloud, rep, opts.StatePath, err
}

func TestRun_FullLoop(t *testing.T) {
	cloud, rep, statePath, err := runFixture(t, false, &fake.Exec{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !rep.OK {
		t.Fatalf("report should pass: %+v", rep)
	}
	// The loop ended with teardown: resources deleted, TornDown set.
	if len(cloud.DownOps) == 0 {
		t.Fatal("down did not run")
	}
	saved, err := scenariotest.LoadRunState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !saved.TornDown {
		t.Error("run-state not marked TornDown")
	}
	// The report file survives the teardown.
	if r := mustLoadReport(t, scenariotest.DefaultReportPath(statePath)); !r.OK {
		t.Errorf("persisted report should pass: %+v", r)
	}
}

func TestRun_SkipsWhenClusterTooSmall(t *testing.T) {
	cloud, opts := baseRunOptions(t)
	opts.Scenario.Placement = scenariotest.Placement{"vm-a": "node:1"} // fake.Config lists one agent
	_, err := Run(context.Background(), opts)
	var skip *scenariotest.SkipError
	if !errors.As(err, &skip) {
		t.Fatalf("want SkipError, got %v", err)
	}
	if skip.Reason == "" {
		t.Error("skip reason must name why")
	}
	// A skip creates nothing and tears down nothing.
	if len(cloud.Servers) != 0 || len(cloud.DownOps) != 0 {
		t.Errorf("skip must not touch the cluster: %d servers, %d down ops", len(cloud.Servers), len(cloud.DownOps))
	}
	if _, err := scenariotest.LoadRunState(opts.StatePath); err == nil {
		t.Error("no run-state file should be written for a skipped run")
	}
}

func TestRun_KeepSkipsDown(t *testing.T) {
	cloud, rep, _, err := runFixture(t, true, &fake.Exec{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !rep.OK {
		t.Fatalf("report should pass: %+v", rep)
	}
	if len(cloud.DownOps) != 0 {
		t.Errorf("keep must skip teardown, got %v", cloud.DownOps)
	}
}

func TestRun_ResumeSkipsRealize(t *testing.T) {
	cloud, opts := baseRunOptions(t)
	first := opts
	first.Keep = true
	if _, err := Run(context.Background(), first); err != nil {
		t.Fatalf("first run: %v", err)
	}
	rs, err := scenariotest.LoadRunState(opts.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	serversBefore := len(cloud.Servers)

	second := opts
	second.State = rs
	rep, err := Run(context.Background(), second)
	if err != nil {
		t.Fatalf("resume run: %v", err)
	}
	if !rep.OK {
		t.Fatalf("resume report should pass: %+v", rep)
	}
	if len(cloud.Servers) != serversBefore {
		t.Errorf("resume must not realize: %d new server(s) created", len(cloud.Servers)-serversBefore)
	}
	if len(cloud.DownOps) == 0 {
		t.Error("resume without Keep must tear down")
	}
}

func TestRun_ResumeRefusesTornDown(t *testing.T) {
	_, opts := baseRunOptions(t)
	rs := scenariotest.NewRunState("run1", opts.Scenario.Name, "scenariotest")
	rs.TornDown = true
	opts.State = rs
	_, err := Run(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "already torn down") {
		t.Fatalf("want already-torn-down error, got %v", err)
	}
}

// blindMetrics scrapes fine but exposes none of the required families
// — a stand-in for a stopped or ancient agent on the resume path.
type blindMetrics struct{ fake.InstantMACs }

func (blindMetrics) Scrape(context.Context, string) (scenariotest.ScrapeResult, error) {
	return scenariotest.ScrapeResult{Present: map[string]bool{}}, nil
}

func TestRun_ResumeStillChecksAgents(t *testing.T) {
	cloud, opts := baseRunOptions(t)
	first := opts
	first.Keep = true
	if _, err := Run(context.Background(), first); err != nil {
		t.Fatalf("first run: %v", err)
	}
	rs, err := scenariotest.LoadRunState(opts.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	teardownsBefore := len(cloud.DownOps)

	second := opts
	second.State = rs
	second.Metrics = blindMetrics{}
	_, err = Run(context.Background(), second)
	if err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("resume against a blind agent must fail the slimmed preflight, got %v", err)
	}
	if len(cloud.DownOps) != teardownsBefore {
		t.Errorf("a failed resume preflight must not tear the kept topology down: %v", cloud.DownOps[teardownsBefore:])
	}
}

// cancelExec cancels the run context the moment drive starts pushing
// traffic — simulating an operator interrupt mid-
type cancelExec struct{ cancel context.CancelFunc }

func (e cancelExec) Run(ctx context.Context, _, cmd string) (string, error) {
	if strings.Contains(cmd, "dd if=/dev/zero") {
		e.cancel()
		return "", context.Canceled
	}
	return "", nil
}

// interruptFixture is the base fixture with a run context the exec
// cancels mid-drive, plus an optional HardStop.
func interruptFixture(t *testing.T, hardStop context.Context) (*fake.Cloud, error) {
	t.Helper()
	cloud, opts := baseRunOptions(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opts.Exec = cancelExec{cancel: cancel}
	opts.HardStop = hardStop
	_, err := Run(ctx, opts)
	return cloud, err
}

func TestRun_InterruptStillTearsDown(t *testing.T) {
	cloud, err := interruptFixture(t, nil)
	if err == nil {
		t.Fatal("interrupted run must return an error")
	}
	// The run context is cancelled, but teardown detached from it and
	// must have deleted everything anyway.
	if len(cloud.DownOps) == 0 {
		t.Fatal("teardown did not run after interrupt")
	}
}

func TestRun_HardStopAbortsTeardown(t *testing.T) {
	hard, hardCancel := context.WithCancel(context.Background())
	hardCancel() // second interrupt already fired
	cloud, err := interruptFixture(t, hard)
	if err == nil {
		t.Fatal("interrupted run must return an error")
	}
	if len(cloud.DownOps) != 0 {
		t.Errorf("hard stop must abort teardown, got %v", cloud.DownOps)
	}
}

func TestRun_DriveFailureStillTearsDown(t *testing.T) {
	cloud, _, _, err := runFixture(t, false, &fake.Exec{Fail: "dd if=/dev/zero"})
	if err == nil || !strings.Contains(err.Error(), "run: drive") {
		t.Fatalf("want drive error, got %v", err)
	}
	if len(cloud.DownOps) == 0 {
		t.Error("teardown must run even after a drive failure")
	}
}

// mustLoadReport reads a persisted assert report.
func mustLoadReport(t *testing.T, path string) scenariotest.AssertReport {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	var rep scenariotest.AssertReport
	if err := json.Unmarshal(body, &rep); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	return rep
}
