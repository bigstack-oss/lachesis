package main

import (
	"errors"
	"io"
	"strings"
	"testing"
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

func TestRenderSuite(t *testing.T) {
	r := suiteReport{
		OK: false,
		Scenarios: []suiteScenario{
			{Scenario: "twovms-same-tenant", OK: true, DurationSeconds: 222.4, Report: ".scenariotest/a-report.json"},
			{Scenario: "vm-to-internet", OK: false, DurationSeconds: 130, Report: ".scenariotest/b-report.json"},
			{Scenario: "mac-reuse", OK: false, Error: "run: preflight not ready", DurationSeconds: 3.2},
		},
	}
	var b strings.Builder
	renderSuite(&b, r)
	out := b.String()
	for _, want := range []string{"SUITE 3 scenario(s)", "twovms-same-tenant", "3m42s", "FAIL (error)", ".scenariotest/b-report.json", "FAIL"} {
		if !strings.Contains(out, want) {
			t.Errorf("renderSuite output missing %q:\n%s", want, out)
		}
	}
	if strings.Count(out, "pass") != 1 {
		t.Errorf("want exactly one pass row:\n%s", out)
	}
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
