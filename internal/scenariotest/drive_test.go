package scenariotest

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
)

// fakeExec records every (addr, command) pair. Commands matching a
// failSubstring return an error.
type fakeExec struct {
	calls []execCall
	fail  string
}

type execCall struct{ addr, command string }

func (f *fakeExec) Run(_ context.Context, addr, command string) (string, error) {
	f.calls = append(f.calls, execCall{addr, command})
	if f.fail != "" && strings.Contains(command, f.fail) {
		return "", fmt.Errorf("injected failure for %q", command)
	}
	return "", nil
}

// driveState builds the run-state `up` would have left for the
// two-VM same-tenant fixture: FIPs for both VMs and a green attach
// record.
func driveState() *RunState {
	rs := NewRunState("run1", "same", "scenariotest")
	rs.FIPs = []FIPRef{
		{VMID: "vm-a", ID: "fip-1", Address: "203.0.113.10", ProjectID: "p1"},
		{VMID: "vm-b", ID: "fip-2", Address: "203.0.113.11", ProjectID: "p1"},
	}
	rs.Attach = AttachRecord{Target: 7, Failures: 0}
	return rs
}

// driveMetrics reports a healthy cluster consistent with driveState's
// attach record.
type driveMetrics struct {
	attached float64
	failures float64
	bytes    []BytesSample
	servers  []ServerSample
}

func (m driveMetrics) Scrape(context.Context, string) (ScrapeResult, error) {
	return ScrapeResult{
		Present:            map[string]bool{metricBytesTotal: true, metricAttachedInterfaces: true},
		AttachedInterfaces: m.attached,
		AttachFailures:     m.failures,
		Bytes:              m.bytes,
		Servers:            m.servers,
	}, nil
}

func driveFixture(t *testing.T, sc *Scenario, rs *RunState, exec VMExec, m MetricsSource) (string, error) {
	t.Helper()
	statePath := t.TempDir() + "/state.json"
	err := Drive(context.Background(), DriveOptions{
		Config:    testConfig(),
		Scenario:  sc,
		State:     rs,
		StatePath: statePath,
		Metrics:   m,
		Exec:      exec,
		Log:       io.Discard,
		SinkDelay: -1, // skip the sink-bind pause in tests
	})
	return statePath, err
}

func TestDrive_VMTargetFlow(t *testing.T) {
	sc := sameTenantScenario()
	sc.Flows = []Flow{{From: "vm-a", To: VMTarget("vm-b"), Bytes: 1 << 20, Proto: TCP}}
	rs := driveState()
	exec := &fakeExec{}
	m := driveMetrics{attached: 7, bytes: []BytesSample{{TenantID: "u1", Zone: "same_tenant", Direction: "tx", Value: 42}}}

	statePath, err := driveFixture(t, sc, rs, exec, m)
	if err != nil {
		t.Fatalf("Drive: %v", err)
	}

	// Expected call order: readiness probes (source, then target),
	// sink on the target's FIP, stream on the source's FIP.
	var sinkIdx, streamIdx = -1, -1
	for i, c := range exec.calls {
		switch {
		case strings.Contains(c.command, "nc -l -p 15000"):
			sinkIdx = i
			if c.addr != "203.0.113.11" {
				t.Errorf("sink started on %s, want target FIP 203.0.113.11", c.addr)
			}
		case strings.Contains(c.command, "dd if=/dev/zero bs=1M count=1"):
			streamIdx = i
			if c.addr != "203.0.113.10" {
				t.Errorf("stream run on %s, want source FIP 203.0.113.10", c.addr)
			}
			if !strings.Contains(c.command, "nc 10.0.1.6 15000") {
				t.Errorf("stream must dial the target's INTERNAL IP: %q", c.command)
			}
		}
	}
	if sinkIdx == -1 || streamIdx == -1 {
		t.Fatalf("missing sink or stream call: %+v", exec.calls)
	}
	if sinkIdx > streamIdx {
		t.Error("sink must start before the stream")
	}
	// Baseline was captured and persisted before traffic.
	if len(rs.Baseline) != 1 || rs.Baseline[0].Value != 42 {
		t.Errorf("baseline not captured: %+v", rs.Baseline)
	}
	saved, err := LoadRunState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(saved.Baseline) != 1 {
		t.Errorf("baseline not persisted to run-state file: %+v", saved.Baseline)
	}
}

func TestDrive_ExternalTargetUsesPing(t *testing.T) {
	sc := sameTenantScenario()
	sc.Flows = []Flow{{From: "vm-a", To: ExternalTarget("8.8.8.8"), Bytes: 1 << 20, Proto: TCP}}
	rs := driveState()
	exec := &fakeExec{}

	if _, err := driveFixture(t, sc, rs, exec, driveMetrics{attached: 7}); err != nil {
		t.Fatalf("Drive: %v", err)
	}
	found := false
	for _, c := range exec.calls {
		if strings.Contains(c.command, "ping -c 18 -s 60000 8.8.8.8") {
			found = true
			if c.addr != "203.0.113.10" {
				t.Errorf("ping run on %s, want source FIP", c.addr)
			}
		}
		if strings.Contains(c.command, "nc -l") {
			t.Errorf("external flow must not start a sink: %q", c.command)
		}
	}
	if !found {
		t.Fatalf("no ping push found in calls: %+v", exec.calls)
	}
}

func TestDrive_AttachRegressionAborts(t *testing.T) {
	sc := sameTenantScenario()
	sc.Flows = []Flow{{From: "vm-a", To: VMTarget("vm-b"), Bytes: 1 << 20, Proto: TCP}}
	rs := driveState() // recorded target 7
	exec := &fakeExec{}

	// A tap disappeared since up: gauge below the recorded target.
	_, err := driveFixture(t, sc, rs, exec, driveMetrics{attached: 6})
	if err == nil || !strings.Contains(err.Error(), "taps lost") {
		t.Fatalf("want attach-regression error, got %v", err)
	}
	if len(exec.calls) != 0 {
		t.Errorf("no traffic may run after a failed attach recheck: %+v", exec.calls)
	}
}

func TestDrive_NewAttachFailuresAbort(t *testing.T) {
	sc := sameTenantScenario()
	sc.Flows = []Flow{{From: "vm-a", To: VMTarget("vm-b"), Bytes: 1 << 20, Proto: TCP}}
	rs := driveState()
	exec := &fakeExec{}

	_, err := driveFixture(t, sc, rs, exec, driveMetrics{attached: 7, failures: 2})
	if err == nil || !strings.Contains(err.Error(), "attach failure") {
		t.Fatalf("want attach-failure error, got %v", err)
	}
	if len(exec.calls) != 0 {
		t.Errorf("no traffic may run after new attach failures: %+v", exec.calls)
	}
}

func TestDrive_UDPUnsupported(t *testing.T) {
	sc := sameTenantScenario()
	sc.Flows = []Flow{{From: "vm-a", To: VMTarget("vm-b"), Bytes: 1 << 20, Proto: UDP}}
	rs := driveState()

	_, err := driveFixture(t, sc, rs, &fakeExec{}, driveMetrics{attached: 7})
	if err == nil || !strings.Contains(err.Error(), "TCP") {
		t.Fatalf("want unsupported-protocol error, got %v", err)
	}
}

func TestDrive_MissingFIPFails(t *testing.T) {
	sc := sameTenantScenario()
	sc.Flows = []Flow{{From: "vm-a", To: VMTarget("vm-b"), Bytes: 1 << 20, Proto: TCP}}
	rs := driveState()
	rs.FIPs = rs.FIPs[:1] // vm-b has no FIP

	_, err := driveFixture(t, sc, rs, &fakeExec{}, driveMetrics{attached: 7})
	if err == nil || !strings.Contains(err.Error(), "no FIP") {
		t.Fatalf("want missing-FIP error, got %v", err)
	}
}

func TestMibCount(t *testing.T) {
	tests := []struct {
		bytes int64
		want  int64
	}{
		{1, 1}, {1 << 20, 1}, {1<<20 + 1, 2}, {10 << 20, 10}, {0, 1},
	}
	for _, tt := range tests {
		if got := mibCount(tt.bytes); got != tt.want {
			t.Errorf("mibCount(%d) = %d, want %d", tt.bytes, got, tt.want)
		}
	}
}
