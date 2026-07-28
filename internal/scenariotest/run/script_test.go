package run

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/fake"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/steps"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// macReuseScenario mirrors the registered mac-reuse scenario: a
// step-scripted run with a deferred VM reborn from a deleted VM's MAC.
func macReuseScenario() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.7.0/24", "10.0.7.1").
		VM("vm-a", "T1", "10.0.7.5").
		VM("vm-b", "T1", "10.0.7.6")
	b.Network("net-T2", "T2").
		Subnet("sub-T2", "10.0.8.0/24", "10.0.8.1").
		VM("vm-c", "T2", "10.0.8.5").
		VM("vm-d", "T2", "10.0.8.6")
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").Attach("sub-T1", "10.0.7.1").ExternalGateway("net-ext")
	b.Router("r-T2", "T2").Attach("sub-T2", "10.0.8.1").ExternalGateway("net-ext")

	const budget = 256 << 10
	return &scenariotest.Scenario{
		Name:     "mac-reuse",
		Builder:  b,
		Deferred: []string{"vm-d"},
		Steps: []scenariotest.Step{
			steps.DriveStep{Flows: []scenariotest.Flow{{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP}}},
			steps.AssertStep{Note: "tenant A drive", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "same_tenant", Direction: "tx", MinBytes: 1 << 20},
			}},
			steps.CaptureStep{},
			steps.DeleteVMStep{VM: "vm-a"},
			// Deliberately the global-settled fallback (no ForMACOf): this
			// helper exercises that path + its metric gate; the ForMACOf
			// path is covered by the sweepMetrics tests and the registered
			// mac-reuse scenario.
			steps.AwaitSweepStep{},
			steps.MonotoneStep{Tenant: "T1", Note: "monotone across ghost sweep"},
			steps.MaxGrowthStep{Tenant: "unknown", Zone: "same_tenant", Budget: budget, Note: "no re-bucket to unknown"},
			steps.BootVMStep{VM: "vm-d", MACFrom: "vm-a"},
			steps.MaxGrowthStep{Tenant: "T2", Zone: "same_tenant", Budget: budget, Note: "reborn MAC starts from zero"},
			steps.DriveStep{Flows: []scenariotest.Flow{{From: "vm-d", To: scenariotest.VMTarget("vm-c"), Bytes: 1 << 20, Proto: scenariotest.TCP}}},
			steps.AssertStep{Note: "tenant B drive", Expect: []scenariotest.Expect{
				{TenantID: "T2", Zone: "same_tenant", Direction: "tx", MinBytes: 1 << 20},
			}},
			steps.MonotoneStep{Tenant: "T1", Note: "old tenant unchanged after reuse"},
		},
	}
}

// streamExec counts driven scenariotest.TCP streams so the metrics fake can tell
// "after tenant A's drive" from "after tenant B's drive".
type streamExec struct {
	fake.Exec
	streams int
}

func (e *streamExec) Run(ctx context.Context, addr, command string) (string, error) {
	if strings.Contains(command, "dd if=/dev/zero") {
		e.streams++
	}
	return e.Exec.Run(ctx, addr, command)
}

// stepMetrics scripts the agent's visible behavior across the steps,
// keyed off the shared fake environment: tenant counters follow the
// driven streams, the settled-flows counter advances once a server has
// been deleted (the "sweep"), and the attach gauge follows boots minus
// deletions.
//
// With bug set it reproduces the pre-fix agent instead: the sweep
// re-buckets tenant A's bytes to "unknown", and the reborn MAC hands
// tenant A's history to tenant B.
type stepMetrics struct {
	Env   *fake.Env
	cloud *fake.Cloud
	exec  *streamExec

	bug         bool
	frozenSweep bool // the sweep never fires: settled stays flat
	noSettled   bool // agent predates the fold: metric absent entirely
}

// LookupMAC mirrors a fully-synced agent: a MAC resolves to the
// project of the live (undeleted) port carrying it. Shadows the
// embedded tenant-agnostic fake.InstantMACs so the mac-reuse loop
// exercises the MAC-learn gate's stale-tenant rule (lachesis#153).
func (m *stepMetrics) LookupMAC(_ context.Context, _, mac string) (scenariotest.MACLookup, error) {
	for pid, pmac := range m.cloud.MACs {
		// Router-interface ports never resolve — mirroring the real
		// mac_tenant_map, which holds VM ports only. The MAC-learn
		// gate must not wait on them (lachesis#146 regression).
		if pmac == mac && !m.cloud.Deleted["port:"+pid] && !strings.Contains(m.cloud.PortName[pid], "p-rif-") {
			return scenariotest.MACLookup{Found: true, TenantID: m.cloud.PortProject[pid]}, nil
		}
	}
	return scenariotest.MACLookup{}, nil
}

// LookupFlows: mac-reuse's script never asserts flow peers.
func (m *stepMetrics) LookupFlows(context.Context, string, string) ([]scenariotest.FlowRow, error) {
	return nil, nil
}

const drivenBytes = float64(2 << 20)

func (m *stepMetrics) Scrape(context.Context, string) (scenariotest.ScrapeResult, error) {
	deleted := 0
	for k := range m.cloud.Deleted {
		if strings.HasPrefix(k, "server:") {
			deleted++
		}
	}
	swept := deleted > 0

	var t1, t2, unknown, settled float64
	if m.exec.streams >= 1 {
		t1 = drivenBytes
	}
	if m.exec.streams >= 2 {
		t2 += drivenBytes
	}
	if swept && !m.frozenSweep {
		settled = 4
		if m.bug {
			unknown = t1 // re-bucketed to unknown...
			t1 = 0       // ...and gone from the tenant
		}
	}
	if m.bug && m.rebornExists() {
		t2 += drivenBytes // the reborn MAC inherited tenant A's history
	}

	present := map[string]bool{
		scenariotest.MetricBytesTotal:         true,
		scenariotest.MetricAttachedInterfaces: true,
		scenariotest.MetricAttachFailures:     true,
		scenariotest.MetricSettledFlows:       !m.noSettled,
	}
	return scenariotest.ScrapeResult{
		Present:            present,
		AttachedInterfaces: m.Env.BaseAttached + float64(m.Env.Booted) - float64(deleted),
		AttachFailures:     m.Env.Failures,
		SettledFlows:       settled,
		Bytes: []scenariotest.BytesSample{
			{TenantID: "uuid-t1", Zone: "same_tenant", Direction: "tx", Value: t1},
			{TenantID: "uuid-t2", Zone: "same_tenant", Direction: "tx", Value: t2},
			{TenantID: "unknown", Zone: "same_tenant", Direction: "tx", Value: unknown},
		},
	}, nil
}

// rebornExists reports whether the explicit-MAC port has been created.
func (m *stepMetrics) rebornExists() bool {
	for _, p := range m.cloud.Ports {
		if p.MACAddress != "" {
			return true
		}
	}
	return false
}

// stepsFixture runs the mac-reuse scenario through the plain Run with
// the scripted fakes.
func stepsFixture(t *testing.T, mm *stepMetrics, sc *scenariotest.Scenario) (*fake.Cloud, *streamExec, string, scenariotest.AssertReport, error) {
	t.Helper()
	env := &fake.Env{BaseAttached: 5}
	cloud := fake.NewCloud(env)
	cloud.PreProjects["scenariotest-T1"] = "uuid-t1"
	cloud.PreProjects["scenariotest-T2"] = "uuid-t2"
	exec := &streamExec{}
	mm.Env, mm.cloud, mm.exec = env, cloud, exec

	statePath := t.TempDir() + "/state.json"
	rep, err := Run(context.Background(), Options{
		Config:     fake.Config(),
		Scenario:   sc,
		RunID:      "run1",
		StatePath:  statePath,
		ReportPath: scenariotest.DefaultReportPath(statePath),
		Cloud:      cloud,
		Metrics:    mm,
		Exec:       exec,
		Log:        slog.New(slog.DiscardHandler),
		SinkDelay:  -1,
		// Small gate timeout: with a truthful run-state the MAC-learn
		// gate resolves instantly against the fake cloud; a stale dead
		// port ref (the lachesis#153 mac-reuse regression) fails fast
		// here instead of hanging the suite.
		MACLearnTimeout: time.Second,
	})
	return cloud, exec, statePath, rep, err
}

func TestSteps_BootVMHonorsPlacementSlot(t *testing.T) {
	sc := macReuseScenario()
	sc.Placement = scenariotest.Placement{"vm-d": "node:0"} // fake.Config's only agent is compute-0
	cloud, _, _, _, err := stepsFixture(t, &stepMetrics{}, sc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// The deferred vm-d's pin must resolve to the slot's agent host.
	byName := map[string]string{}
	for _, s := range cloud.Servers {
		byName[s.Name] = s.AvailabilityZone
	}
	if az := byName["scenariotest-run1-vm-d"]; az != "nova:compute-0" {
		t.Errorf("deferred boot AZ = %q, want %q", az, "nova:compute-0")
	}
}

func TestSteps_MACReuseFullLoop(t *testing.T) {
	cloud, exec, statePath, rep, err := stepsFixture(t, &stepMetrics{}, macReuseScenario())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !rep.OK {
		t.Fatalf("report should pass: %+v", rep)
	}
	if exec.streams != 2 {
		t.Errorf("driven streams = %d, want 2 (one per tenant)", exec.streams)
	}

	// `up` deferred vm-d: only three servers booted by realize, the
	// fourth (with the pinned MAC) by the steps.BootVMStep.
	if len(cloud.Servers) != 4 {
		t.Fatalf("servers booted = %d, want 4 (3 realized + 1 deferred)", len(cloud.Servers))
	}

	// The reborn port pinned exactly the deleted VM's MAC. vm-a's ref
	// is gone from the run-state (steps.DeleteVMStep keeps the inventory
	// truthful — the MAC-learn gate must never wait on a dead port),
	// so read the ground truth from the fake cloud: the first created
	// port is vm-a's, and it must be deleted with its MAC reborn on
	// the pinned-MAC port.
	rs, err := scenariotest.LoadRunState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range rs.Ports {
		if p.DSLID == "vm-a" {
			t.Errorf("deleted vm-a's port ref still in run-state: %+v", p)
		}
	}
	var rebornMAC string
	for _, p := range cloud.Ports {
		if p.MACAddress != "" {
			rebornMAC = p.MACAddress
		}
	}
	macCount := map[string]int{}
	for _, m := range cloud.MACs {
		macCount[m]++
	}
	if rebornMAC == "" || macCount[rebornMAC] != 2 {
		t.Errorf("reborn MAC %q appears on %d port(s), want 2 (vm-a's auto-assigned + the pinned reborn)",
			rebornMAC, macCount[rebornMAC])
	}
	if len(cloud.DownOps) == 0 {
		t.Error("down did not run")
	}
	if !mustLoadReport(t, scenariotest.DefaultReportPath(statePath)).OK {
		t.Error("persisted report should pass")
	}

	// The report carries every step's checks.
	notes := map[string]int{}
	for _, row := range rep.Rows {
		notes[row.Note]++
	}
	for _, want := range []string{"tenant A drive", "monotone across ghost sweep", "no re-bucket to unknown",
		"reborn MAC starts from zero", "tenant B drive", "old tenant unchanged after reuse"} {
		if notes[want] == 0 {
			t.Errorf("report has no %q rows: %v", want, notes)
		}
	}
}

// TestSteps_DetectsRebucketRegression proves the scenario is a real
// detector: against an agent with the ghost-sweep bug (history moves
// to "unknown", the reborn MAC inherits it), the monotone, unknown,
// and zero-inheritance rows must all fail.
func TestSteps_DetectsRebucketRegression(t *testing.T) {
	_, _, _, rep, err := stepsFixture(t, &stepMetrics{bug: true}, macReuseScenario())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.OK {
		t.Fatal("report passed against a buggy agent — the scenario detects nothing")
	}
	failed := map[string]bool{}
	for _, row := range rep.Rows {
		if !row.Pass {
			failed[row.Note] = true
		}
	}
	for _, want := range []string{"monotone across ghost sweep", "no re-bucket to unknown", "reborn MAC starts from zero"} {
		if !failed[want] {
			t.Errorf("expected failing %q rows against the buggy agent; failures: %v", want, failed)
		}
	}
}

// TestSteps_RefusesPreFoldAgent: an agent without
// lachesis_gc_settled_flows_total can't signal its sweep; run must
// refuse up front — before realizing anything — instead of timing out
// mid-scenario.
func TestSteps_RefusesPreFoldAgent(t *testing.T) {
	cloud, _, _, _, err := stepsFixture(t, &stepMetrics{noSettled: true}, macReuseScenario())
	if err == nil || !strings.Contains(err.Error(), scenariotest.MetricSettledFlows) {
		t.Fatalf("want pre-fold agent refusal, got %v", err)
	}
	if len(cloud.Servers) != 0 {
		t.Errorf("refusal must precede realize; %d server(s) booted", len(cloud.Servers))
	}
}

// TestSteps_SweepTimeout: an agent whose settled counter never
// advances (sweep lost) fails the run with a diagnosable error, and
// teardown still runs.
func TestSteps_SweepTimeout(t *testing.T) {
	sc := macReuseScenario()
	for i, st := range sc.Steps {
		if _, ok := st.(steps.AwaitSweepStep); ok {
			sc.Steps[i] = steps.AwaitSweepStep{Timeout: 50 * time.Millisecond}
		}
	}
	cloud, _, _, _, err := stepsFixture(t, &stepMetrics{frozenSweep: true}, sc)
	if err == nil || !strings.Contains(err.Error(), "ghost sweep not observed") {
		t.Fatalf("want sweep-timeout error, got %v", err)
	}
	if len(cloud.DownOps) == 0 {
		t.Error("down did not run after the sweep timeout")
	}
}

// TestSteps_DefaultScriptIsDriveAssert: a scenario with no Steps still
// runs the classic linear loop — the plain zone scenarios must be
// untouched by the step machinery. (run_test.go covers the full plain
// loop; this pins that defaultSteps is what runs.)
func TestSteps_DefaultScriptIsDriveAssert(t *testing.T) {
	script := steps.Default(runScenario())
	if len(script) != 2 {
		t.Fatalf("default steps = %d, want 2", len(script))
	}
	if _, ok := script[0].(steps.DriveStep); !ok {
		t.Errorf("default step 0 = %T, want steps.DriveStep", script[0])
	}
	if _, ok := script[1].(steps.AssertStep); !ok {
		t.Errorf("default step 1 = %T, want steps.AssertStep", script[1])
	}
}

// extExec counts external ping pushes the way streamExec counts scenariotest.TCP
// streams.
type extExec struct {
	fake.Exec
	pings  int
	pings2 int // pings at the second-router prefix (8.8.9.x)
	pings3 int // pings at the gateway-less-router prefix (8.8.10.x)
	Routes int // in-guest route adds
}

func (e *extExec) Run(ctx context.Context, addr, command string) (string, error) {
	switch {
	case strings.Contains(command, "ping -c") && strings.Contains(command, "8.8.9."):
		e.pings2++
	case strings.Contains(command, "ping -c") && strings.Contains(command, "8.8.10."):
		e.pings3++
	case strings.Contains(command, "ping -c"):
		e.pings++
	case strings.Contains(command, "ip route add"):
		e.Routes++
	}
	return e.Exec.Run(ctx, addr, command)
}

// extPathMetrics scripts the agent's visible behavior for the
// multi-external-path scenario: the anomaly gauge follows whether an
// extra (non-provider) FIP is live in the fake cloud, external-zone
// counters follow the ping drive under the deterministic pick, and the
// per-server family mirrors the tenant family for the one VM.
type extPathMetrics struct {
	Env   *fake.Env
	cloud *fake.Cloud
	exec  *extExec
}

// LookupMAC mirrors the real mac_tenant_map: VM ports resolve,
// router-interface ports never do — so a MAC-learn gate wrongly
// waiting on a rif ref times out the loop test in seconds.
func (m *extPathMetrics) LookupMAC(_ context.Context, _, mac string) (scenariotest.MACLookup, error) {
	for pid, pmac := range m.cloud.MACs {
		if pmac == mac && !m.cloud.Deleted["port:"+pid] && !strings.Contains(m.cloud.PortName[pid], "p-rif-") {
			return scenariotest.MACLookup{Found: true, TenantID: m.cloud.PortProject[pid]}, nil
		}
	}
	return scenariotest.MACLookup{}, nil
}

// LookupFlows answers the flow-peer gates: a queried MAC belonging to
// a router's interface port reports the driven bytes once the drive
// that rides that router has run.
func (m *extPathMetrics) LookupFlows(_ context.Context, _, mac string) ([]scenariotest.FlowRow, error) {
	for pid, pmac := range m.cloud.MACs {
		if pmac != mac {
			continue
		}
		name := m.cloud.PortName[pid]
		switch {
		case strings.Contains(name, "r-ext2") && m.exec.pings2 >= 1:
			return []scenariotest.FlowRow{{DstMAC: mac, Zone: "external", Direction: "tx", Bytes: drivenBytes}}, nil
		case strings.Contains(name, "r-nogw") && m.exec.pings3 >= 1:
			return []scenariotest.FlowRow{{DstMAC: mac, Zone: "external", Direction: "tx", Bytes: drivenBytes}}, nil
		}
	}
	return nil, nil
}

func (m *extPathMetrics) Scrape(context.Context, string) (scenariotest.ScrapeResult, error) {
	extraFIP := 0.0
	for i, spec := range m.cloud.Fips {
		if spec.ExternalNetworkID != m.cloud.ExtNetID && !m.cloud.Deleted["fip:"+m.cloud.FipIDs[i]] {
			extraFIP = 1
		}
	}
	var ext, ext2 float64
	if m.exec.pings >= 1 {
		ext = drivenBytes
	}
	if m.exec.pings3 >= 1 {
		ext += drivenBytes // fallback tier lands on the provider label
	}
	if m.exec.pings2 >= 1 {
		ext2 = drivenBytes
	}
	var serverID string
	if len(m.cloud.ServerIDs) > 0 {
		serverID = m.cloud.ServerIDs[0]
	}
	// The created network's agent-emitted label is its run-mangled
	// Neutron name — what the per-flow router-MAC attribution resolves
	// for flows riding r-ext2.
	created := scenariotest.Mangle("scenariotest", "run1", "net-ext2")
	return scenariotest.ScrapeResult{
		Present: map[string]bool{
			scenariotest.MetricBytesTotal:         true,
			scenariotest.MetricAttachedInterfaces: true,
			scenariotest.MetricAttachFailures:     true,
			scenariotest.MetricNeutronAnomalies:   true,
		},
		AttachedInterfaces: m.Env.BaseAttached + float64(m.Env.Booted),
		Anomalies:          map[string]float64{"multi_external_path": extraFIP},
		Bytes: []scenariotest.BytesSample{
			{TenantID: "uuid-t1", Zone: "external", ExternalNetwork: "ext", Direction: "tx", Value: ext},
			{TenantID: "uuid-t1", Zone: "external", ExternalNetwork: created, Direction: "tx", Value: ext2},
		},
		Servers: []scenariotest.ServerSample{
			{ServerID: serverID, TenantID: "uuid-t1", Zone: "external", ExternalNetwork: "ext", Direction: "tx", Value: ext},
			{ServerID: serverID, TenantID: "uuid-t1", Zone: "external", ExternalNetwork: created, Direction: "tx", Value: ext2},
		},
	}, nil
}

func TestSteps_MultiExternalPathFullLoop(t *testing.T) {
	env := &fake.Env{BaseAttached: 5}
	cloud := fake.NewCloud(env)
	cloud.PreProjects["scenariotest-T1"] = "uuid-t1"
	exec := &extExec{}
	mm := &extPathMetrics{Env: env, cloud: cloud, exec: exec}

	statePath := t.TempDir() + "/state.json"
	rep, err := Run(context.Background(), Options{
		Config:     fake.Config(),
		Scenario:   extPathScenario(),
		RunID:      "run1",
		StatePath:  statePath,
		ReportPath: scenariotest.DefaultReportPath(statePath),
		Cloud:      cloud,
		Metrics:    mm,
		Exec:       exec,
		Log:        slog.New(slog.DiscardHandler),
		SinkDelay:  -1,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !rep.OK {
		t.Fatalf("report should pass: %+v", rep)
	}

	// The second external network was CREATED as router:external —
	// not bound to the provider net — and its FIP subnet realized.
	extCreated := false
	for _, n := range cloud.Nets {
		if n.External {
			extCreated = true
		}
	}
	if !extCreated {
		t.Error("net-ext2 was not created as an external network")
	}

	// Exactly one extra FIP (beyond vm-a's provider SSH FIP) was
	// allocated from the created network, and deleted mid-run.
	if len(cloud.Fips) != 2 {
		t.Fatalf("fips created = %d, want 2 (SSH + extra)", len(cloud.Fips))
	}
	extraIdx := -1
	for i, spec := range cloud.Fips {
		if spec.ExternalNetworkID != cloud.ExtNetID {
			extraIdx = i
		}
	}
	if extraIdx < 0 {
		t.Fatal("no FIP drawn from the created external network")
	}
	if !cloud.Deleted["fip:"+cloud.FipIDs[extraIdx]] {
		t.Error("the extra FIP was not deleted by steps.DeleteFIPStep")
	}
	if exec.Routes != 2 {
		t.Errorf("in-guest route adds = %d, want 2 (second router + gateway-less)", exec.Routes)
	}
	if exec.pings2 != 1 || exec.pings3 != 1 {
		t.Errorf("router-steered ping drives = %d/%d, want 1/1", exec.pings2, exec.pings3)
	}

	// The deleted FIP is gone from the persisted run-state too — down
	// must not re-delete it; the provider SSH FIP ref stays.
	rs, err := scenariotest.LoadRunState(statePath)
	if err != nil {
		t.Fatalf("LoadRunState: %v", err)
	}
	for _, f := range rs.FIPs {
		if f.Network == "net-ext2" {
			t.Errorf("deleted FIP still in run-state: %+v", f)
		}
	}
	if len(rs.FIPs) != 1 {
		t.Errorf("run-state FIPs = %+v, want only the provider SSH FIP", rs.FIPs)
	}

	// Every phase's rows are in the report.
	notes := map[string]int{}
	for _, row := range rep.Rows {
		notes[row.Note]++
	}
	for _, want := range []string{"single external path — no anomaly", "second FIP surfaces the ambiguity",
		"default route bills under the carrying network", "second-router flow bills under ITS carrying network",
		"gateway-less router falls back to the per-VM attribution",
		"steered bytes observed on r-ext2's interface",
		"fallback bytes observed on the gateway-less interface",
		"ambiguity clears after FIP removal", "series stable through FIP churn"} {
		if notes[want] == 0 {
			t.Errorf("report has no %q rows: %v", want, notes)
		}
	}
}

// cyclingExec models an agent host across SEVERAL restarts: each
// `systemctl restart` bumps MainPID, so consecutive restarts each show
// the PID change awaitReady demands. (restartExec bumps once, which is
// enough for a single-restart test but not for restore-after-restart.)
type cyclingExec struct {
	Calls []fake.ExecCall
	pid   int
}

func (e *cyclingExec) Run(_ context.Context, addr, command string) (string, error) {
	e.Calls = append(e.Calls, fake.ExecCall{Addr: addr, Command: command})
	switch {
	case strings.Contains(command, "systemctl restart"):
		e.pid++
		return "", nil
	case strings.Contains(command, "MainPID"):
		return fmt.Sprintf("MainPID=%d\n", 1000+e.pid), nil
	}
	return "", nil
}

func (e *cyclingExec) has(substr string) bool {
	for _, c := range e.Calls {
		if strings.Contains(c.Command, substr) {
			return true
		}
	}
	return false
}

// erroringStep fails on demand — the mid-scenario abort that used to
// skip a scenario's trailing restore step.
type erroringStep struct{}

func (erroringStep) Kind() string { return "boom" }
func (erroringStep) Run(context.Context, *scenariotest.StepEnv) error {
	return fmt.Errorf("injected step failure")
}

// TestRunSteps_RestoresConfigWhenAStepErrors is lachesis#274: a step
// error returns straight out of runSteps, so a scenario's trailing
// steps.RestartAgentStep{RestoreConfig} is never reached — the host would
// keep serving the scenario's temporary config, silently, into whatever
// ran next. The deferred sweep must put it back regardless.
func TestRunSteps_RestoresConfigWhenAStepErrors(t *testing.T) {
	agents := []scenariotest.AgentConfig{{Host: "compute-0", MetricsURL: "http://c0/m", SSHHost: "10.0.0.10"}}
	ac := scenariotest.AgentControlConfig{User: "root", KeyPath: "/k", Unit: "lachesis-agent",
		ConfigPath: "/etc/lachesis/agent.yaml", ReadyTimeout: time.Second}
	exec := &cyclingExec{}
	env := restartEnv(t, agents, ac, exec, nil)

	script := []scenariotest.Step{
		steps.RestartAgentStep{SetConfig: map[string]string{"reconcile.interval": "15s"}},
		erroringStep{},
		// The scenario's own restore — deliberately unreachable here.
		steps.RestartAgentStep{RestoreConfig: true},
	}
	err := runSteps(context.Background(), env, script)
	if err == nil || !strings.Contains(err.Error(), "injected step failure") {
		t.Fatalf("runSteps must surface the step error, got %v", err)
	}
	// The sweep ran the restore even though step 3 never did.
	if !exec.has("cp -f /etc/lachesis/agent.yaml.scenariotest.bak /etc/lachesis/agent.yaml") {
		t.Errorf("config was NOT restored after the abort: %+v", exec.Calls)
	}
	if left := env.TakeConfigDirty(); len(left) != 0 {
		t.Errorf("config-dirty list still holds %v after the sweep", left)
	}
}

// The happy path must not restore twice: the scenario's own restore
// clears the debt, so the sweep has nothing left to do.
func TestRunSteps_ExplicitRestoreLeavesNothingForTheSweep(t *testing.T) {
	agents := []scenariotest.AgentConfig{{Host: "compute-0", MetricsURL: "http://c0/m"}}
	ac := scenariotest.AgentControlConfig{User: "root", KeyPath: "/k", Unit: "lachesis-agent",
		ConfigPath: "/etc/lachesis/agent.yaml", ReadyTimeout: time.Second}
	exec := &cyclingExec{}
	env := restartEnv(t, agents, ac, exec, nil)

	script := []scenariotest.Step{
		steps.RestartAgentStep{SetConfig: map[string]string{"reconcile.interval": "15s"}},
		steps.RestartAgentStep{RestoreConfig: true},
	}
	if err := runSteps(context.Background(), env, script); err != nil {
		t.Fatalf("runSteps: %v", err)
	}
	var restores int
	for _, c := range exec.Calls {
		if strings.Contains(c.Command, ".scenariotest.bak /etc/lachesis/agent.yaml") {
			restores++
		}
	}
	if restores != 1 {
		t.Errorf("restore issued %d times, want exactly 1 (the sweep should be a no-op)", restores)
	}
}

// A run that never touched config must not go near the agent host at
// the end — the sweep is keyed on actual mutations, not on the step
// list containing agent-control
func TestRunSteps_NoConfigChangeNoSweep(t *testing.T) {
	agents := []scenariotest.AgentConfig{{Host: "compute-0", MetricsURL: "http://c0/m"}}
	ac := scenariotest.AgentControlConfig{User: "root", KeyPath: "/k", ReadyTimeout: time.Second}
	exec := &restartExec{}
	env := restartEnv(t, agents, ac, exec, nil)

	if err := runSteps(context.Background(), env, []scenariotest.Step{erroringStep{}}); err == nil {
		t.Fatal("want the injected error")
	}
	if len(exec.Calls) != 0 {
		t.Errorf("sweep touched the host with no config change to undo: %+v", exec.Calls)
	}
}

// extPathScenario is [fake.ExtPathTopology] plus the script that walks
// the three-tier external-path attribution ladder.
func extPathScenario() *scenariotest.Scenario {
	sc := fake.ExtPathTopology()
	sc.Steps = []scenariotest.Step{
		steps.AssertAnomalyStep{Class: "multi_external_path", Min: 0, Max: 0, Timeout: time.Second,
			Note: "single external path — no anomaly"},
		steps.AssociateFIPStep{VM: "vm-a", Network: "net-ext2"},
		steps.AssertAnomalyStep{Class: "multi_external_path", Min: 1, Max: 1, Timeout: time.Second,
			Note: "second FIP surfaces the ambiguity"},
		steps.CaptureStep{},
		steps.DriveStep{Flows: []scenariotest.Flow{{From: "vm-a", To: scenariotest.ExternalTarget("8.8.8.8"), Bytes: 1 << 20, Proto: scenariotest.TCP}}},
		steps.AssertStep{Note: "default route bills under the carrying network", Expect: []scenariotest.Expect{
			{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 1 << 20, ExternalNetwork: "net-ext"},
			{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 1 << 20, ExternalNetwork: "net-ext", VM: "vm-a"},
		}},
		steps.AddRouteStep{VM: "vm-a", CIDR: "8.8.9.0/24", Via: "10.0.11.254"},
		steps.CaptureStep{},
		steps.DriveStep{Flows: []scenariotest.Flow{{From: "vm-a", To: scenariotest.ExternalTarget("8.8.9.9"), Bytes: 1 << 20, Proto: scenariotest.TCP}}},
		steps.AssertStep{Note: "second-router flow bills under ITS carrying network", Expect: []scenariotest.Expect{
			{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 1 << 20, ExternalNetwork: "net-ext2"},
			{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 1 << 20, ExternalNetwork: "net-ext2", VM: "vm-a"},
		}},
		steps.AssertFlowPeerStep{Router: "r-ext2", Via: "10.0.11.254", Zone: "external",
			MinBytes: 1 << 20, Note: "steered bytes observed on r-ext2's interface"},
		steps.AddRouteStep{VM: "vm-a", CIDR: "8.8.10.0/24", Via: "10.0.11.253"},
		steps.CaptureStep{},
		steps.DriveStep{Flows: []scenariotest.Flow{{From: "vm-a", To: scenariotest.ExternalTarget("8.8.10.9"), Bytes: 1 << 20, Proto: scenariotest.TCP}}},
		steps.AssertStep{Note: "gateway-less router falls back to the per-VM attribution", Expect: []scenariotest.Expect{
			{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 1 << 20, ExternalNetwork: "net-ext"},
			{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 1 << 20, ExternalNetwork: "net-ext", VM: "vm-a"},
		}},
		steps.AssertFlowPeerStep{Router: "r-nogw", Via: "10.0.11.253", Zone: "external",
			MinBytes: 1 << 20, Note: "fallback bytes observed on the gateway-less interface"},
		steps.DeleteFIPStep{VM: "vm-a", Network: "net-ext2"},
		steps.AssertAnomalyStep{Class: "multi_external_path", Min: 0, Max: 0, Timeout: time.Second,
			Note: "ambiguity clears after FIP removal"},
		steps.MonotoneStep{Tenant: "T1", Note: "series stable through FIP churn"},
	}
	return sc
}

func restartEnv(t *testing.T, agents []scenariotest.AgentConfig, ac scenariotest.AgentControlConfig, exec scenariotest.VMExec, m scenariotest.MetricsSource) *scenariotest.StepEnv {
	t.Helper()
	cfg := fake.Config()
	cfg.Cluster.Agents = agents
	cfg.AgentControl = ac
	if m == nil {
		m = &restartMetrics{Attached: 5}
	}
	return &scenariotest.StepEnv{
		Config:    cfg,
		Scenario:  &scenariotest.Scenario{Name: "restart"},
		State:     &scenariotest.RunState{RunID: "run1"},
		StatePath: t.TempDir() + "/s.json",
		Metrics:   m,
		AgentExec: exec,
		Log:       slog.New(slog.DiscardHandler),
		Report:    &scenariotest.AssertReport{OK: true},
	}
}

// restartExec models the agent host: it records commands, reports the
// unit's MainPID (bumping it once a restart is issued, so awaitReady's
// PID-change evidence fires), and can be told to never cycle (the
// restart-didn't-take case) or to fail a command matching failOn.
type restartExec struct {
	Calls     []fake.ExecCall
	restarted bool
	noCycle   bool   // MainPID never changes — restart did not take
	failOn    string // a command substring that returns an error
	catOut    string // what `sudo cat <config>` returns (SetConfig reads it)
}

func (e *restartExec) Run(_ context.Context, addr, command string) (string, error) {
	e.Calls = append(e.Calls, fake.ExecCall{Addr: addr, Command: command})
	if e.failOn != "" && strings.Contains(command, e.failOn) {
		return "", fmt.Errorf("fake ssh: command failed: %s", command)
	}
	switch {
	case strings.Contains(command, "systemctl restart"):
		e.restarted = true
		return "", nil
	case strings.Contains(command, "MainPID"):
		if e.restarted && !e.noCycle {
			return "MainPID=2222\n", nil
		}
		return "MainPID=1111\n", nil
	case strings.HasPrefix(command, "sudo cat "):
		return e.catOut, nil
	}
	return "", nil
}

func (e *restartExec) has(substr string) bool {
	for _, c := range e.Calls {
		if strings.Contains(c.Command, substr) {
			return true
		}
	}
	return false
}

// restartMetrics is a minimal agent /metrics. Attached is the tap
// count; when notReadyPolls > 0 the readiness scrapes (every call after
// the pre-restart baseline, call #1) report one tap short for that many
// polls before recovering — modelling the boot re-attach window.
type restartMetrics struct {
	fake.InstantMACs
	Attached      float64
	notReadyPolls int
	scrapes       int
}

func (m *restartMetrics) Scrape(context.Context, string) (scenariotest.ScrapeResult, error) {
	m.scrapes++
	a := m.Attached
	if m.scrapes >= 2 && m.scrapes <= 1+m.notReadyPolls {
		a = m.Attached - 1 // still re-attaching
	}
	return scenariotest.ScrapeResult{
		Present: map[string]bool{
			scenariotest.MetricBytesTotal: true, scenariotest.MetricAttachedInterfaces: true,
			scenariotest.MetricSettledFlows: true, scenariotest.MetricServerBytesTotal: true,
		},
		AttachedInterfaces: a,
	}, nil
}
