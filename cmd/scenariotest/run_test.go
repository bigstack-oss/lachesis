package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bigstack-oss/lachesis/cmd/scenariotest/scenarios"
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
)

// execRoot runs the real command tree with args and returns the error
// Execute surfaced, with cobra's own printing silenced.
func execRoot(args ...string) error {
	root := newRoot()
	root.SetArgs(args)
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	return root.Execute()
}

func TestRunArgValidation(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		wantMsg string
	}{
		{"all with names", []string{"run", "--all", "vm-to-internet"}, "--all takes no scenario names"},
		{"no names no all", []string{"run"}, "missing scenario name"},
		{"state with multiple", []string{"run", "--state", "s.json", "vm-to-internet", "mac-reuse"}, "single files"},
		{"report with multiple", []string{"run", "--report", "r.json", "vm-to-internet", "mac-reuse"}, "single files"},
		{"unknown name", []string{"run", "no-such-scenario"}, "no-such-scenario"},
		{"skip without all", []string{"run", "--skip", "mac-reuse", "vm-to-internet"}, "--skip only applies with --all"},
		{"skip unknown name", []string{"run", "--all", "--skip", "no-such-scenario"}, "no-such-scenario"},
		{"skip everything", []string{"run", "--all", "--skip", "twovms-same-tenant,vm-to-gateway,vm-to-internet,cross-tenant-shared,cross-tenant-routed,mac-reuse,multi-external-path"}, "left no scenarios"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := execRoot(c.args...)
			if err == nil {
				t.Fatalf("execRoot(%v) = nil error", c.args)
			}
			if !strings.Contains(err.Error(), c.wantMsg) {
				t.Errorf("error %q does not contain %q", err, c.wantMsg)
			}
			if c.name != "unknown name" { // a bare unknown scenario is a runtime error (exit 1); the rest, including --skip typos, are usage (exit 2)
				var uerr usageError
				if !errors.As(err, &uerr) {
					t.Errorf("error %T is not a usageError (must exit 2)", err)
				}
			}
		})
	}
}

func TestResolveResume(t *testing.T) {
	sc, err := scenarios.Get("twovms-same-tenant")
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.DiscardHandler)
	dir := t.TempDir()
	save := func(name, scenario string, torn bool) string {
		rs := scenariotest.NewRunState("abc123", scenario, "p")
		rs.TornDown = torn
		path := dir + "/" + name
		if err := rs.Save(path); err != nil {
			t.Fatal(err)
		}
		return path
	}

	if rs, err := resolveResume("", sc, log); rs != nil || err != nil {
		t.Errorf("empty path: got %v, %v; want fresh", rs, err)
	}
	if rs, err := resolveResume(dir+"/missing.json", sc, log); rs != nil || err != nil {
		t.Errorf("missing file: got %v, %v; want fresh", rs, err)
	}
	if rs, err := resolveResume(save("live.json", sc.Name, false), sc, log); err != nil || rs == nil || rs.RunID != "abc123" {
		t.Errorf("live file: got %v, %v; want resume of abc123", rs, err)
	}
	if rs, err := resolveResume(save("torn.json", sc.Name, true), sc, log); rs != nil || err != nil {
		t.Errorf("torn-down file: got %v, %v; want fresh overwrite", rs, err)
	}
	if _, err := resolveResume(save("wrong.json", "other-scenario", false), sc, log); err == nil {
		t.Error("wrong-scenario file must error, not silently overwrite")
	}
	// A directory at the path fails with a non-ENOENT error: that must
	// surface, never silently fall through to a fresh run.
	if _, err := resolveResume(dir, sc, log); err == nil {
		t.Error("unreadable state path must error, not start a fresh run")
	}
}

func TestRenderSuite(t *testing.T) {
	r := summarize([]suiteScenario{
		{Scenario: "twovms-same-tenant", OK: true, DurationSeconds: 222.4, Report: ".scenariotest/a-report.json"},
		{Scenario: "vm-to-internet", OK: false, DurationSeconds: 130, Report: ".scenariotest/b-report.json"},
		{Scenario: "mac-reuse", OK: false, Error: "run: preflight not ready", DurationSeconds: 3.2},
		{Scenario: "cross-host-same-tenant", Skipped: "needs 2 node(s) (placement slots); config lists 1 agent(s)"},
	}, false)
	var b strings.Builder
	renderSuite(&b, r)
	out := b.String()
	for _, want := range []string{"SUITE 4 scenario(s)", "twovms-same-tenant", "3m42s", "FAIL (error)",
		".scenariotest/b-report.json", "FAIL", "skip (needs 2 node(s)", "1 passed · 2 failed · 1 skipped"} {
		if !strings.Contains(out, want) {
			t.Errorf("renderSuite output missing %q:\n%s", want, out)
		}
	}
	if strings.Count(out, "pass ") != 1 {
		t.Errorf("want exactly one pass row:\n%s", out)
	}
}

func TestSummarize(t *testing.T) {
	rows := []suiteScenario{
		{Scenario: "a", OK: true},
		{Scenario: "b"},
		{Scenario: "c", Skipped: "needs 2 node(s)"},
	}
	r := summarize(rows, false)
	if r.Pass != 1 || r.Fail != 1 || r.Skipped != 1 {
		t.Errorf("counts = %d/%d/%d, want 1/1/1", r.Pass, r.Fail, r.Skipped)
	}
	if r.OK {
		t.Error("a failed row must fail the suite")
	}

	// Skips alone never fail the suite...
	r = summarize([]suiteScenario{{Scenario: "a", OK: true}, {Scenario: "c", Skipped: "too small"}}, false)
	if !r.OK {
		t.Error("skips must not fail the suite by default")
	}
	// ...unless --no-skip tightens them.
	r = summarize([]suiteScenario{{Scenario: "a", OK: true}, {Scenario: "c", Skipped: "too small"}}, true)
	if r.OK {
		t.Error("--no-skip must turn skips into failures")
	}
}

func TestTwoStageContexts(t *testing.T) {
	sig := make(chan os.Signal, 2)
	var released atomic.Bool
	runCtx, hardCtx, stop := twoStageContexts(context.Background(), sig, func() { released.Store(true) }, slog.New(slog.DiscardHandler))
	defer stop()

	if runCtx.Err() != nil || hardCtx.Err() != nil {
		t.Fatal("contexts must start live")
	}
	sig <- os.Interrupt
	<-runCtx.Done()
	if hardCtx.Err() != nil {
		t.Fatal("first interrupt must not cancel the hard-stop context")
	}
	sig <- os.Interrupt
	<-hardCtx.Done()
	waitFor(t, released.Load)
}

// waitFor polls cond briefly — the release side effect happens on the
// handler goroutine after hardCtx is cancelled.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for range 100 {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not reached")
}

func TestEmitSuiteJSON(t *testing.T) {
	r := suiteReport{OK: true, Scenarios: []suiteScenario{
		{Scenario: "vm-to-gateway", OK: true, DurationSeconds: 36.2, State: "s.json", Report: "r.json"},
	}}
	var b strings.Builder
	if err := emitSuite(&b, "json", r); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"ok": true`, `"scenario": "vm-to-gateway"`, `"duration_seconds": 36.2`, `"state": "s.json"`, `"report": "r.json"`} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("suite JSON missing %s:\n%s", want, b.String())
		}
	}
	if strings.Contains(b.String(), `"error"`) {
		t.Errorf("empty error must be omitted:\n%s", b.String())
	}
}
