package scenariotest

import (
	"context"
	"log/slog"
	"strings"
	"testing"
)

// runScenario is the two-VM fixture with a drivable flow and an
// assertable expectation.
func runScenario() *Scenario {
	sc := sameTenantScenario()
	sc.Flows = []Flow{{From: "vm-a", To: VMTarget("vm-b"), Bytes: 1 << 20, Proto: TCP}}
	sc.Expect = []Expect{{TenantID: "T1", Zone: "same_tenant", Direction: "tx", MinBytes: 1 << 20}}
	return sc
}

// runMetrics serves the whole composed loop: the attach gauge follows
// the fake env (gate + recheck), and the bytes counter climbs by 2 MiB
// per scrape so assert's first delta after drive's baseline passes.
type runMetrics struct {
	instantMACs
	env *fakeEnv
	val float64
}

func (m *runMetrics) Scrape(context.Context, string) (ScrapeResult, error) {
	m.val += float64(2 << 20)
	return ScrapeResult{
		Present:            map[string]bool{metricBytesTotal: true, metricAttachedInterfaces: true},
		AttachedInterfaces: m.env.baseAttached + float64(m.env.booted),
		AttachFailures:     m.env.failures,
		Bytes: []BytesSample{
			{TenantID: "uuid-t1", Zone: "same_tenant", Direction: "tx", Value: m.val},
		},
	}, nil
}

func runFixture(t *testing.T, keep bool, exec VMExec) (*fakeCloud, AssertReport, string, error) {
	t.Helper()
	env := &fakeEnv{baseAttached: 5}
	cloud := newFakeCloud(env)
	// Pre-seed the project so the tenant UUID is stable and the
	// metrics fake can label its series accordingly.
	cloud.preProjects["scenariotest-T1"] = "uuid-t1"
	dir := t.TempDir()
	statePath := dir + "/state.json"
	rep, err := Run(context.Background(), RunOptions{
		Config:     testConfig(),
		Scenario:   runScenario(),
		RunID:      "run1",
		StatePath:  statePath,
		ReportPath: DefaultReportPath(statePath),
		Cloud:      cloud,
		Metrics:    &runMetrics{env: env},
		Exec:       exec,
		Log:        slog.New(slog.DiscardHandler),
		Keep:       keep,
		SinkDelay:  -1,
	})
	return cloud, rep, statePath, err
}

func TestRun_FullLoop(t *testing.T) {
	cloud, rep, statePath, err := runFixture(t, false, &fakeExec{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !rep.OK {
		t.Fatalf("report should pass: %+v", rep)
	}
	// The loop ended with teardown: resources deleted, TornDown set.
	if len(cloud.downOps) == 0 {
		t.Fatal("down did not run")
	}
	saved, err := LoadRunState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !saved.TornDown {
		t.Error("run-state not marked TornDown")
	}
	// The report file survives the teardown.
	if r := mustLoadReport(t, DefaultReportPath(statePath)); !r.OK {
		t.Errorf("persisted report should pass: %+v", r)
	}
}

func TestRun_KeepSkipsDown(t *testing.T) {
	cloud, rep, _, err := runFixture(t, true, &fakeExec{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !rep.OK {
		t.Fatalf("report should pass: %+v", rep)
	}
	if len(cloud.downOps) != 0 {
		t.Errorf("keep must skip teardown, got %v", cloud.downOps)
	}
}

// cancelExec cancels the run context the moment drive starts pushing
// traffic — simulating an operator interrupt mid-run.
type cancelExec struct{ cancel context.CancelFunc }

func (e cancelExec) Run(ctx context.Context, _, cmd string) (string, error) {
	if strings.Contains(cmd, "dd if=/dev/zero") {
		e.cancel()
		return "", context.Canceled
	}
	return "", nil
}

// interruptFixture is runFixture with a cancellable run context and an
// optional HardStop.
func interruptFixture(t *testing.T, hardStop context.Context) (*fakeCloud, error) {
	t.Helper()
	env := &fakeEnv{baseAttached: 5}
	cloud := newFakeCloud(env)
	cloud.preProjects["scenariotest-T1"] = "uuid-t1"
	statePath := t.TempDir() + "/state.json"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := Run(ctx, RunOptions{
		Config:     testConfig(),
		Scenario:   runScenario(),
		RunID:      "run1",
		StatePath:  statePath,
		ReportPath: DefaultReportPath(statePath),
		Cloud:      cloud,
		Metrics:    &runMetrics{env: env},
		Exec:       cancelExec{cancel: cancel},
		Log:        slog.New(slog.DiscardHandler),
		HardStop:   hardStop,
		SinkDelay:  -1,
	})
	return cloud, err
}

func TestRun_InterruptStillTearsDown(t *testing.T) {
	cloud, err := interruptFixture(t, nil)
	if err == nil {
		t.Fatal("interrupted run must return an error")
	}
	// The run context is cancelled, but teardown detached from it and
	// must have deleted everything anyway.
	if len(cloud.downOps) == 0 {
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
	if len(cloud.downOps) != 0 {
		t.Errorf("hard stop must abort teardown, got %v", cloud.downOps)
	}
}

func TestRun_DriveFailureStillTearsDown(t *testing.T) {
	cloud, _, _, err := runFixture(t, false, &fakeExec{fail: "dd if=/dev/zero"})
	if err == nil || !strings.Contains(err.Error(), "run: drive") {
		t.Fatalf("want drive error, got %v", err)
	}
	if len(cloud.downOps) == 0 {
		t.Error("teardown must run even after a drive failure")
	}
}
