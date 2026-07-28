package steps

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/fake"
)

// stdinExecFake is a fake.Exec that also accepts stdin streams,
// recording how many bytes each command drained.
type stdinExecFake struct {
	fake.Exec
	stdinBytes []int64
}

func (e *stdinExecFake) RunWithStdin(ctx context.Context, addr, command string, stdin io.Reader) (string, error) {
	n, err := io.Copy(io.Discard, stdin)
	if err != nil {
		return "", err
	}
	e.stdinBytes = append(e.stdinBytes, n)
	return e.Run(ctx, addr, command)
}

func ingressEnv(t *testing.T, exec scenariotest.VMExec) *scenariotest.StepEnv {
	t.Helper()
	sc := fake.SameTenantScenario()
	return &scenariotest.StepEnv{
		Config:    fake.Config(),
		Scenario:  sc,
		State:     driveState(),
		StatePath: t.TempDir() + "/state.json",
		Metrics:   fake.HealthyMetrics{Attached: 7, Bytes: []scenariotest.BytesSample{{TenantID: "u1", Zone: "external", Direction: "rx", Value: 7}}},
		Exec:      exec,
		Log:       slog.New(slog.DiscardHandler),
		SinkDelay: -1,
		Report:    &scenariotest.AssertReport{OK: true},
	}
}

func TestIngressFlowStep_StreamsBudgetToFIP(t *testing.T) {
	exec := &stdinExecFake{}
	env := ingressEnv(t, exec)

	err := IngressFlowStep{To: "vm-b", Bytes: 3 << 20}.Run(context.Background(), env)
	if err != nil {
		t.Fatalf("IngressFlowStep: %v", err)
	}
	if len(exec.stdinBytes) != 1 || exec.stdinBytes[0] != 3<<20 {
		t.Fatalf("streamed bytes = %v, want one stream of %d", exec.stdinBytes, 3<<20)
	}
	last := exec.Calls[len(exec.Calls)-1]
	if last.Addr != "203.0.113.11" {
		t.Errorf("stream dialed %s, want vm-b's FIP 203.0.113.11", last.Addr)
	}
	if !strings.Contains(last.Command, "cat > /dev/null") {
		t.Errorf("stream command = %q, want a cat sink", last.Command)
	}
	// The step captures drive's baseline so a following AssertStep can diff.
	if len(env.State.Baseline) != 1 || env.State.Baseline[0].Value != 7 {
		t.Errorf("baseline not captured: %+v", env.State.Baseline)
	}
}

func TestIngressFlowStep_RequiresStdinExec(t *testing.T) {
	env := ingressEnv(t, &fake.Exec{})
	err := IngressFlowStep{To: "vm-b", Bytes: 1}.Run(context.Background(), env)
	if err == nil || !strings.Contains(err.Error(), "stdin") {
		t.Fatalf("want stdin-transport error, got %v", err)
	}
}

func TestIngressFlowStep_MissingFIP(t *testing.T) {
	exec := &stdinExecFake{}
	env := ingressEnv(t, exec)
	env.State.FIPs = nil
	env.State.Ports = nil // and no MACs to gate on
	err := IngressFlowStep{To: "vm-b", Bytes: 1}.Run(context.Background(), env)
	if err == nil || !strings.Contains(err.Error(), "no SSH FIP") {
		t.Fatalf("want missing-FIP error, got %v", err)
	}
}

// driveState builds the run-state `up` would have left for the
// two-VM same-tenant fixture: FIPs for both VMs and a green attach
// record.
func driveState() *scenariotest.RunState {
	rs := scenariotest.NewRunState("run1", "same", "scenariotest")
	rs.FIPs = []scenariotest.FIPRef{
		{VMID: "vm-a", ID: "fip-1", Address: "203.0.113.10", ProjectID: "p1"},
		{VMID: "vm-b", ID: "fip-2", Address: "203.0.113.11", ProjectID: "p1"},
	}
	rs.Attach = scenariotest.AttachRecord{Target: 7, Failures: 0}
	return rs
}
