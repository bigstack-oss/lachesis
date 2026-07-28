package drive

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/fake"
)

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

func driveFixture(t *testing.T, sc *scenariotest.Scenario, rs *scenariotest.RunState, exec scenariotest.VMExec, m scenariotest.MetricsSource) (string, error) {
	t.Helper()
	statePath := t.TempDir() + "/state.json"
	err := Run(context.Background(), Options{
		Config:    fake.Config(),
		Scenario:  sc,
		State:     rs,
		StatePath: statePath,
		Metrics:   m,
		Exec:      exec,
		Log:       slog.New(slog.DiscardHandler),
		SinkDelay: -1, // skip the sink-bind pause in tests
	})
	return statePath, err
}

func TestDrive_VMTargetFlow(t *testing.T) {
	sc := fake.SameTenantScenario()
	sc.Flows = []scenariotest.Flow{{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP}}
	rs := driveState()
	exec := &fake.Exec{}
	m := fake.HealthyMetrics{Attached: 7, Bytes: []scenariotest.BytesSample{{TenantID: "u1", Zone: "same_tenant", Direction: "tx", Value: 42}}}

	statePath, err := driveFixture(t, sc, rs, exec, m)
	if err != nil {
		t.Fatalf("Drive: %v", err)
	}

	// Expected call order: readiness probes (source, then target),
	// sink on the target's FIP, stream on the source's FIP.
	var sinkIdx, streamIdx = -1, -1
	for i, c := range exec.Calls {
		switch {
		case strings.Contains(c.Command, "nc -l -p 15000"):
			sinkIdx = i
			if c.Addr != "203.0.113.11" {
				t.Errorf("sink started on %s, want target FIP 203.0.113.11", c.Addr)
			}
		case strings.Contains(c.Command, "dd if=/dev/zero bs=1M count=1"):
			streamIdx = i
			if c.Addr != "203.0.113.10" {
				t.Errorf("stream run on %s, want source FIP 203.0.113.10", c.Addr)
			}
			if !strings.Contains(c.Command, "nc 10.0.1.6 15000") {
				t.Errorf("stream must dial the target's INTERNAL IP: %q", c.Command)
			}
		}
	}
	if sinkIdx == -1 || streamIdx == -1 {
		t.Fatalf("missing sink or stream call: %+v", exec.Calls)
	}
	if sinkIdx > streamIdx {
		t.Error("sink must start before the stream")
	}
	// Baseline was captured and persisted before traffic.
	if len(rs.Baseline) != 1 || rs.Baseline[0].Value != 42 {
		t.Errorf("baseline not captured: %+v", rs.Baseline)
	}
	saved, err := scenariotest.LoadRunState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(saved.Baseline) != 1 {
		t.Errorf("baseline not persisted to run-state file: %+v", saved.Baseline)
	}
}

func TestDrive_ExternalTargetUsesPing(t *testing.T) {
	sc := fake.SameTenantScenario()
	sc.Flows = []scenariotest.Flow{{From: "vm-a", To: scenariotest.ExternalTarget("8.8.8.8"), Bytes: 1 << 20, Proto: scenariotest.TCP}}
	rs := driveState()
	exec := &fake.Exec{}

	if _, err := driveFixture(t, sc, rs, exec, fake.HealthyMetrics{Attached: 7}); err != nil {
		t.Fatalf("Drive: %v", err)
	}
	found := false
	for _, c := range exec.Calls {
		if strings.Contains(c.Command, "ping -c 18 -s 60000 8.8.8.8") {
			found = true
			if c.Addr != "203.0.113.10" {
				t.Errorf("ping run on %s, want source FIP", c.Addr)
			}
		}
		if strings.Contains(c.Command, "nc -l") {
			t.Errorf("external flow must not start a sink: %q", c.Command)
		}
	}
	if !found {
		t.Fatalf("no ping push found in calls: %+v", exec.Calls)
	}
}

func TestDrive_AttachRegressionAborts(t *testing.T) {
	sc := fake.SameTenantScenario()
	sc.Flows = []scenariotest.Flow{{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP}}
	rs := driveState() // recorded target 7
	exec := &fake.Exec{}

	// A tap disappeared since up: gauge below the recorded target.
	_, err := driveFixture(t, sc, rs, exec, fake.HealthyMetrics{Attached: 6})
	if err == nil || !strings.Contains(err.Error(), "taps lost") {
		t.Fatalf("want attach-regression error, got %v", err)
	}
	if len(exec.Calls) != 0 {
		t.Errorf("no traffic may run after a failed attach recheck: %+v", exec.Calls)
	}
}

func TestDrive_NewAttachFailuresAbort(t *testing.T) {
	sc := fake.SameTenantScenario()
	sc.Flows = []scenariotest.Flow{{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP}}
	rs := driveState()
	exec := &fake.Exec{}

	_, err := driveFixture(t, sc, rs, exec, fake.HealthyMetrics{Attached: 7, Failures: 2})
	if err == nil || !strings.Contains(err.Error(), "attach failure") {
		t.Fatalf("want attach-failure error, got %v", err)
	}
	if len(exec.Calls) != 0 {
		t.Errorf("no traffic may run after new attach failures: %+v", exec.Calls)
	}
}

func TestDrive_UDPUnsupported(t *testing.T) {
	sc := fake.SameTenantScenario()
	sc.Flows = []scenariotest.Flow{{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.UDP}}
	rs := driveState()

	_, err := driveFixture(t, sc, rs, &fake.Exec{}, fake.HealthyMetrics{Attached: 7})
	if err == nil || !strings.Contains(err.Error(), "TCP") {
		t.Fatalf("want unsupported-protocol error, got %v", err)
	}
}

func TestDrive_MissingFIPFails(t *testing.T) {
	sc := fake.SameTenantScenario()
	sc.Flows = []scenariotest.Flow{{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP}}
	rs := driveState()
	rs.FIPs = rs.FIPs[:1] // vm-b has no FIP

	_, err := driveFixture(t, sc, rs, &fake.Exec{}, fake.HealthyMetrics{Attached: 7})
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

// learnMetrics is fake.HealthyMetrics whose LookupMAC reports not-found for
// the first `learnAfter` polls — the agent learning a just-created
// port a few reconcile beats after boot.
type learnMetrics struct {
	fake.HealthyMetrics
	learnAfter int
	Calls      *int
	tenant     string
}

func (m learnMetrics) LookupMAC(context.Context, string, string) (scenariotest.MACLookup, error) {
	*m.Calls++
	if *m.Calls <= m.learnAfter {
		return scenariotest.MACLookup{}, nil
	}
	return scenariotest.MACLookup{Found: true, TenantID: m.tenant}, nil
}

// macGateState is driveState plus a recorded VM-port MAC — the shape
// `up` writes since the MAC-learn gate landed.
func macGateState() *scenariotest.RunState {
	rs := driveState()
	rs.Ports = []scenariotest.ResourceRef{{DSLID: "vm-a", ID: "port-1", ProjectID: "p1", MAC: "fa:16:3e:00:00:aa"}}
	return rs
}

// TestDrive_MACGateWaitsForLearning: the gate polls until the agent
// resolves the recorded MAC, then the drive proceeds — no false FAIL
// from traffic pushed before the maps are ready (lachesis#153).
func TestDrive_MACGateWaitsForLearning(t *testing.T) {
	sc := fake.SameTenantScenario()
	sc.Flows = nil
	calls := 0
	m := learnMetrics{
		HealthyMetrics: fake.HealthyMetrics{Attached: 7},
		learnAfter:     3, Calls: &calls, tenant: "p1",
	}

	statePath := t.TempDir() + "/state.json"
	err := Run(context.Background(), Options{
		Config: fake.Config(), Scenario: sc, State: macGateState(), StatePath: statePath,
		Metrics: m, Exec: &fake.Exec{}, Log: slog.New(slog.DiscardHandler),
		SinkDelay: -1, MACLearnTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("Drive: %v", err)
	}
	if calls <= 3 {
		t.Errorf("gate polled %d time(s), want > 3 (must wait for learning)", calls)
	}
}

// TestDrive_MACGateTimesOutLoudly: an agent that never learns the MAC
// fails the drive with an error naming the port — never a silent
// zero-delta assert FAIL.
func TestDrive_MACGateTimesOutLoudly(t *testing.T) {
	sc := fake.SameTenantScenario()
	sc.Flows = nil
	calls := 0
	m := learnMetrics{HealthyMetrics: fake.HealthyMetrics{Attached: 7}, learnAfter: 1 << 30, Calls: &calls}

	statePath := t.TempDir() + "/state.json"
	err := Run(context.Background(), Options{
		Config: fake.Config(), Scenario: sc, State: macGateState(), StatePath: statePath,
		Metrics: m, Exec: &fake.Exec{}, Log: slog.New(slog.DiscardHandler),
		SinkDelay: -1, MACLearnTimeout: 200 * time.Millisecond,
	})
	if err == nil || !strings.Contains(err.Error(), "mac-learn gate") || !strings.Contains(err.Error(), "vm-a") {
		t.Fatalf("want loud mac-learn gate timeout naming vm-a, got %v", err)
	}
}

// TestDrive_MACGateRejectsStaleTenant: a MAC still resolving to a
// DIFFERENT tenant (reused MAC whose ghost hasn't swept) is not
// learned — the gate must keep waiting, not pass on Found alone.
func TestDrive_MACGateRejectsStaleTenant(t *testing.T) {
	sc := fake.SameTenantScenario()
	sc.Flows = nil
	calls := 0
	m := learnMetrics{HealthyMetrics: fake.HealthyMetrics{Attached: 7}, learnAfter: 0, Calls: &calls, tenant: "someone-else"}

	statePath := t.TempDir() + "/state.json"
	err := Run(context.Background(), Options{
		Config: fake.Config(), Scenario: sc, State: macGateState(), StatePath: statePath,
		Metrics: m, Exec: &fake.Exec{}, Log: slog.New(slog.DiscardHandler),
		SinkDelay: -1, MACLearnTimeout: 200 * time.Millisecond,
	})
	if err == nil || !strings.Contains(err.Error(), "stale tenant") {
		t.Fatalf("want stale-tenant gate timeout, got %v", err)
	}
}

// TestDrive_MACGateSkipsPreGateRunState: run-states recorded before
// MAC capture (no port MACs) skip the gate instead of failing.
func TestDrive_MACGateSkipsPreGateRunState(t *testing.T) {
	sc := fake.SameTenantScenario()
	sc.Flows = nil
	calls := 0
	m := learnMetrics{HealthyMetrics: fake.HealthyMetrics{Attached: 7}, learnAfter: 1 << 30, Calls: &calls}

	if _, err := driveFixture(t, sc, driveState(), &fake.Exec{}, m); err != nil {
		t.Fatalf("Drive with pre-gate run-state: %v", err)
	}
	if calls != 0 {
		t.Errorf("gate polled %d time(s) on a MAC-less run-state, want 0", calls)
	}
}

// flakyMACs errors the first failFirst lookups — an agent briefly
// unreachable mid-gate — then resolves.
type flakyMACs struct {
	fake.HealthyMetrics
	failFirst int
	Calls     *int
}

func (m flakyMACs) LookupMAC(context.Context, string, string) (scenariotest.MACLookup, error) {
	*m.Calls++
	if *m.Calls <= m.failFirst {
		return scenariotest.MACLookup{}, fmt.Errorf("transient: connection refused")
	}
	return scenariotest.MACLookup{Found: true, TenantID: "p1"}, nil
}

// TestDrive_MACGateToleratesTransientLookupErrors: a lookup error is
// "unresolved, keep polling", not a drive abort — one refused
// connection during a minutes-long gate must not kill the run.
func TestDrive_MACGateToleratesTransientLookupErrors(t *testing.T) {
	sc := fake.SameTenantScenario()
	sc.Flows = nil
	calls := 0
	m := flakyMACs{HealthyMetrics: fake.HealthyMetrics{Attached: 7}, failFirst: 2, Calls: &calls}

	statePath := t.TempDir() + "/state.json"
	err := Run(context.Background(), Options{
		Config: fake.Config(), Scenario: sc, State: macGateState(), StatePath: statePath,
		Metrics: m, Exec: &fake.Exec{}, Log: slog.New(slog.DiscardHandler),
		SinkDelay: -1, MACLearnTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("Drive must survive transient lookup errors: %v", err)
	}
	if calls <= 2 {
		t.Errorf("gate polled %d time(s), want > 2 (kept polling through the errors)", calls)
	}
}

// TestDrive_MACGatePersistentLookupErrorInTimeout: a lookup error that
// never clears still fails the gate at the deadline, with the error
// verbatim in the message.
func TestDrive_MACGatePersistentLookupErrorInTimeout(t *testing.T) {
	sc := fake.SameTenantScenario()
	sc.Flows = nil
	calls := 0
	m := flakyMACs{HealthyMetrics: fake.HealthyMetrics{Attached: 7}, failFirst: 1 << 30, Calls: &calls}

	statePath := t.TempDir() + "/state.json"
	err := Run(context.Background(), Options{
		Config: fake.Config(), Scenario: sc, State: macGateState(), StatePath: statePath,
		Metrics: m, Exec: &fake.Exec{}, Log: slog.New(slog.DiscardHandler),
		SinkDelay: -1, MACLearnTimeout: 200 * time.Millisecond,
	})
	if err == nil || !strings.Contains(err.Error(), "mac-learn gate") || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("want gate timeout carrying the lookup error, got %v", err)
	}
}

// TestDrive_MACGateSkipsRouterInterfaceRefs: router-interface MACs are
// recorded for the flow-peer assertions but are deliberately never in
// mac_tenant_map — the gate must not wait on them (the lachesis#146
// live regression: an 8-minute timeout on a MAC that can never
// resolve).
func TestDrive_MACGateSkipsRouterInterfaceRefs(t *testing.T) {
	sc := fake.SameTenantScenario()
	sc.Flows = nil
	calls := 0
	// The VM MAC resolves immediately; the fake never resolves anything
	// else — if the gate consulted the rif ref, it would time out.
	m := learnMetrics{HealthyMetrics: fake.HealthyMetrics{Attached: 7}, learnAfter: 0, Calls: &calls, tenant: "p1"}
	rs := macGateState()
	rs.Ports = append(rs.Ports, scenariotest.ResourceRef{
		DSLID: "p-rif-r-1", ID: "port-9", ProjectID: "p1",
		MAC: "fa:16:3e:00:00:99", RouterInterface: true,
	})

	statePath := t.TempDir() + "/state.json"
	err := Run(context.Background(), Options{
		Config: fake.Config(), Scenario: sc, State: rs, StatePath: statePath,
		Metrics: m, Exec: &fake.Exec{}, Log: slog.New(slog.DiscardHandler),
		SinkDelay: -1, MACLearnTimeout: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Drive must not gate on router-interface refs: %v", err)
	}
}

func TestDrive_FIPTargetDialsFloatingIP(t *testing.T) {
	sc := fake.SameTenantScenario()
	sc.Flows = []scenariotest.Flow{{From: "vm-a", To: scenariotest.FIPTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP}}
	rs := driveState()
	exec := &fake.Exec{}

	if _, err := driveFixture(t, sc, rs, exec, fake.HealthyMetrics{Attached: 7}); err != nil {
		t.Fatalf("Drive: %v", err)
	}
	var sinkIdx, streamIdx = -1, -1
	for i, c := range exec.Calls {
		switch {
		case strings.Contains(c.Command, "nc -l -p 15000"):
			sinkIdx = i
			if c.Addr != "203.0.113.11" {
				t.Errorf("sink started on %s, want target FIP 203.0.113.11", c.Addr)
			}
		case strings.Contains(c.Command, "dd if=/dev/zero"):
			streamIdx = i
			// The hairpin point: the stream dials the FLOATING address,
			// not the fixed IP.
			if !strings.Contains(c.Command, "nc 203.0.113.11 15000") {
				t.Errorf("stream must dial the target's FIP: %q", c.Command)
			}
		}
	}
	if sinkIdx == -1 || streamIdx == -1 {
		t.Fatalf("missing sink or stream call: %+v", exec.Calls)
	}
	if sinkIdx > streamIdx {
		t.Error("sink must start before the stream")
	}
}
