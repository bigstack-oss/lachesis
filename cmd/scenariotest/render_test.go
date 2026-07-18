package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
)

// Rendering runs without a TTY here, so lipgloss degrades to plain
// text — these tests pin the piped/CI shape of the human output.

func TestRenderPreflight(t *testing.T) {
	r := scenariotest.PreflightReport{
		Scenario: "vm-to-internet",
		OK:       false,
		Checks: []scenariotest.Check{
			{Name: "credentials", OK: true, Detail: "authenticated"},
			{Name: "agent /metrics", OK: false, Detail: "connection refused"},
		},
	}
	var b strings.Builder
	renderPreflight(&b, r)
	out := b.String()
	for _, want := range []string{"PREFLIGHT vm-to-internet", "CHECK", "credentials", "ok", "FAIL", "connection refused", "NOT READY"} {
		if !strings.Contains(out, want) {
			t.Errorf("renderPreflight output missing %q:\n%s", want, out)
		}
	}
}

func TestRenderPreflightSkipped(t *testing.T) {
	r := scenariotest.PreflightReport{
		Scenario: "cross-host-same-tenant",
		OK:       true,
		Skip:     "needs 2 node(s) (placement slots); config lists 1 agent(s)",
	}
	var b strings.Builder
	renderPreflight(&b, r)
	out := b.String()
	for _, want := range []string{"PREFLIGHT cross-host-same-tenant", "SKIPPED", "needs 2 node(s)"} {
		if !strings.Contains(out, want) {
			t.Errorf("renderPreflight output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "CHECK") {
		t.Errorf("skipped report must not render the check table:\n%s", out)
	}
}

func TestRenderAssert(t *testing.T) {
	r := scenariotest.AssertReport{
		Scenario: "vm-to-internet",
		RunID:    "abc123",
		OK:       true,
		Rows: []scenariotest.AssertRow{
			{Tenant: "tenant-a", Zone: "external", Direction: "tx", Baseline: 100, Current: 1100, Delta: 1000, MinBytes: 900, Pass: true},
			{Tenant: "tenant-a", Zone: "external", ExternalNetwork: "public", VM: "vm1", Direction: "tx", Delta: 500, MinBytes: 400, Pass: true, Note: "per-server"},
		},
	}
	var b strings.Builder
	renderAssert(&b, r)
	out := b.String()
	for _, want := range []string{"ASSERT vm-to-internet (run abc123)", "TENANT", "tenant-a", "public", "vm1", "pass (per-server)", "PASS", "1.1 KiB", "900 B"} {
		if !strings.Contains(out, want) {
			t.Errorf("renderAssert output missing %q:\n%s", want, out)
		}
	}
}

func TestHumanBytes(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{0, "0 B"},
		{1023, "1023 B"},
		{1024, "1.0 KiB"},
		{36990, "36.1 KiB"},
		{1048576, "1.0 MiB"},
		{1112223, "1.1 MiB"},
		{10.5 * 1024 * 1024 * 1024, "10.5 GiB"},
		{-2048, "-2.0 KiB"},
	}
	for _, c := range cases {
		if got := humanBytes(c.in); got != c.want {
			t.Errorf("humanBytes(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestEmitBadFormat(t *testing.T) {
	var b strings.Builder
	err := emitAssert(&b, "yaml", scenariotest.AssertReport{})
	if err == nil {
		t.Fatal("emitAssert(yaml) = nil error, want usage error")
	}
	if !strings.Contains(err.Error(), "bad output format") {
		t.Errorf("error %q does not name the bad format", err)
	}
	var uerr usageError
	if !errors.As(err, &uerr) {
		t.Errorf("error %T is not a usageError (must exit 2)", err)
	}
}
