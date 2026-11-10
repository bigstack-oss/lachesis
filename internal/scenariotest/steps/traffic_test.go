package steps

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

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

// TestDriveStep_DuringForwardsNestedNeeds: a drive with nested During
// steps declares their host and metric needs, so the run's skip and
// refusal checks see a restart nested inside a drive.
func TestDriveStep_DuringForwardsNestedNeeds(t *testing.T) {
	plain := DriveStep{}
	if plain.HostNeeds() != (scenariotest.HostNeeds{}) || len(plain.RequiredMetrics()) != 0 {
		t.Errorf("a drive without During declared needs: %+v %v", plain.HostNeeds(), plain.RequiredMetrics())
	}
	s := DriveStep{During: []scenariotest.Step{RestartAgentStep{RemoveWAL: true}}}
	if got := s.HostNeeds(); !got.AgentSSH || !got.WALPath {
		t.Errorf("HostNeeds = %+v, want the nested restart's AgentSSH and WALPath", got)
	}
	if got := s.RequiredMetrics(); !slices.Contains(got, scenariotest.MetricAttachedInterfaces) {
		t.Errorf("RequiredMetrics = %v, want the nested restart's readiness families", got)
	}
}

// recordStep records that it ran, and can fail.
type recordStep struct {
	ran  *bool
	fail bool
}

func (recordStep) Kind() string { return "record" }

func (r recordStep) Run(context.Context, *scenariotest.StepEnv) error {
	*r.ran = true
	if r.fail {
		return errors.New("probe failed")
	}
	return nil
}

// TestDriveStep_During runs the nested steps with the step's env and
// names the failing one in the error.
func TestDriveStep_During(t *testing.T) {
	for _, fail := range []bool{false, true} {
		ran := false
		s := DriveStep{
			Flows:  []scenariotest.Flow{{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP}},
			During: []scenariotest.Step{recordStep{ran: &ran, fail: fail}},
		}
		err := s.Run(context.Background(), ingressEnv(t, &syncExec{}))
		if !ran {
			t.Errorf("fail=%v: During step never ran", fail)
		}
		switch {
		case fail && (err == nil || !strings.Contains(err.Error(), "during flows: record")):
			t.Errorf("err = %v, want the During step named", err)
		case !fail && err != nil:
			t.Errorf("drive: %v", err)
		}
	}
}

// syncExec is a [fake.Exec] safe for the flow and During goroutines,
// whose stream lasts long enough for During to start.
type syncExec struct {
	mu sync.Mutex
	fake.Exec
}

func (e *syncExec) Run(ctx context.Context, addr, command string) (string, error) {
	if strings.Contains(command, "| nc ") {
		select {
		case <-time.After(50 * time.Millisecond):
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.Exec.Run(ctx, addr, command)
}
