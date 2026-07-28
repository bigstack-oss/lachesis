package steps

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/fake"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

func TestSteps_MigrateMovesAndRecords(t *testing.T) {
	env := &fake.Env{BaseAttached: 1}
	cloud := fake.NewCloud(env)
	cloud.Hyps = []string{"compute-0", "compute-1"}
	cloud.Hosts["srv-1"] = "compute-0"
	cfg := fake.Config()
	cfg.Cluster.Agents = append(cfg.Cluster.Agents, scenariotest.AgentConfig{Host: "compute-1", MetricsURL: "http://compute-1:9100/metrics"})
	statePath := t.TempDir() + "/state.json"
	rs := &scenariotest.RunState{RunID: "run1", Scenario: "x", Servers: []scenariotest.ResourceRef{{DSLID: "vm-a", ID: "srv-1", ProjectID: "p1"}}}
	senv := &scenariotest.StepEnv{Config: cfg, State: rs, StatePath: statePath, Cloud: cloud, Metrics: &fake.Metrics{Env: env}, Log: slog.New(slog.DiscardHandler)}

	step := MigrateStep{VM: "vm-a", Target: "node:1", Timeout: time.Second}
	if err := step.Run(context.Background(), senv); err != nil {
		t.Fatalf("MigrateStep: %v", err)
	}
	if got := cloud.Hosts["srv-1"]; got != "compute-1" {
		t.Errorf("server host = %q, want compute-1", got)
	}
	if len(rs.Migrations) != 1 || rs.Migrations[0] != (scenariotest.MigrationRecord{VM: "vm-a", From: "compute-0", To: "compute-1"}) {
		t.Errorf("migrations = %+v", rs.Migrations)
	}
	saved, err := scenariotest.LoadRunState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(saved.Migrations) != 1 {
		t.Errorf("migration not persisted: %+v", saved.Migrations)
	}
}

func TestSteps_MigrateErrors(t *testing.T) {
	env := &fake.Env{BaseAttached: 1}
	cloud := fake.NewCloud(env)
	cloud.Hyps = []string{"compute-0", "compute-1"}
	cloud.Hosts["srv-1"] = "compute-0"
	cfg := fake.Config()
	cfg.Cluster.Agents = append(cfg.Cluster.Agents, scenariotest.AgentConfig{Host: "compute-1", MetricsURL: "http://compute-1:9100/metrics"})
	rs := &scenariotest.RunState{RunID: "run1", Servers: []scenariotest.ResourceRef{{DSLID: "vm-a", ID: "srv-1", ProjectID: "p1"}}}
	senv := &scenariotest.StepEnv{Config: cfg, State: rs, StatePath: t.TempDir() + "/s.json", Cloud: cloud, Metrics: &fake.Metrics{Env: env}, Log: slog.New(slog.DiscardHandler)}

	for name, tc := range map[string]struct {
		step    MigrateStep
		wantErr string
	}{
		"unknown vm":        {MigrateStep{VM: "vm-x", Timeout: time.Second}, "no server for VM"},
		"target is current": {MigrateStep{VM: "vm-a", Target: "node:0", Timeout: time.Second}, "already on"},
		"bad slot":          {MigrateStep{VM: "vm-a", Target: "node:9", Timeout: time.Second}, "config lists 2 agent(s)"},
	} {
		t.Run(name, func(t *testing.T) {
			err := tc.step.Run(context.Background(), senv)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
	if len(rs.Migrations) != 0 {
		t.Errorf("failed steps must record nothing: %+v", rs.Migrations)
	}
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

func TestSteps_RestartAgent(t *testing.T) {
	agents := []scenariotest.AgentConfig{{Host: "compute-0", MetricsURL: "http://compute-0:9100/metrics", SSHHost: "10.0.0.10"}}
	ac := scenariotest.AgentControlConfig{User: "root", KeyPath: "/k", Unit: "lachesis-agent", ReadyTimeout: time.Second}
	exec := &restartExec{}

	if err := (RestartAgentStep{}).Run(context.Background(), restartEnv(t, agents, ac, exec, nil)); err != nil {
		t.Fatalf("restart: %v", err)
	}
	if !exec.has("systemctl restart lachesis-agent") {
		t.Errorf("no restart command issued: %+v", exec.Calls)
	}
	if !exec.has("MainPID") {
		t.Errorf("no MainPID read (restart evidence) issued: %+v", exec.Calls)
	}
	for _, c := range exec.Calls {
		if c.Addr != "10.0.0.10" {
			t.Errorf("SSHed to %q, want the agent's ssh_host 10.0.0.10", c.Addr)
		}
	}
}

func TestSteps_RestartAgentAwaitsReattach(t *testing.T) {
	agents := []scenariotest.AgentConfig{{Host: "compute-0", MetricsURL: "http://c0/m"}}
	ac := scenariotest.AgentControlConfig{User: "root", KeyPath: "/k", ReadyTimeout: 5 * time.Second}
	m := &restartMetrics{Attached: 5, notReadyPolls: 2} // two short polls, then recovered
	if err := (RestartAgentStep{}).Run(context.Background(), restartEnv(t, agents, ac, &restartExec{}, m)); err != nil {
		t.Fatalf("restart: %v", err)
	}
	if m.scrapes < 4 {
		t.Errorf("expected several readiness polls awaiting re-attach, got %d scrapes", m.scrapes)
	}
}

// TestSteps_RestartAgentTimeout: when the unit never cycles (MainPID
// unchanged) the restart is not confirmed and the step times out with a
// clear message, rather than passing on the still-running old process.
func TestSteps_RestartAgentTimeout(t *testing.T) {
	agents := []scenariotest.AgentConfig{{Host: "compute-0", MetricsURL: "http://c0/m"}}
	ac := scenariotest.AgentControlConfig{User: "root", KeyPath: "/k", ReadyTimeout: 150 * time.Millisecond}
	exec := &restartExec{noCycle: true}
	err := (RestartAgentStep{}).Run(context.Background(), restartEnv(t, agents, ac, exec, nil))
	if err == nil || !strings.Contains(err.Error(), "restart not confirmed") {
		t.Fatalf("want a 'restart not confirmed' timeout, got %v", err)
	}
}

func TestSteps_RestartAgentErrors(t *testing.T) {
	agents := []scenariotest.AgentConfig{{Host: "compute-0", MetricsURL: "http://c0/m"}}
	ac := scenariotest.AgentControlConfig{User: "root", KeyPath: "/k", ReadyTimeout: time.Second}
	twoAgents := []scenariotest.AgentConfig{agents[0], {Host: "compute-1", MetricsURL: "http://c1/m"}}

	cases := map[string]struct {
		agents  []scenariotest.AgentConfig
		ac      scenariotest.AgentControlConfig
		exec    scenariotest.VMExec
		step    RestartAgentStep
		wantErr string
	}{
		"no agent exec": {agents, ac, nil, RestartAgentStep{}, "no agent-host SSH transport"},
		"missing creds": {agents, scenariotest.AgentControlConfig{ReadyTimeout: time.Second}, &restartExec{}, RestartAgentStep{}, "user and agent_control.key_path"},
		"node needed":   {twoAgents, ac, &restartExec{}, RestartAgentStep{}, "node is required"},
		"unknown host":  {agents, ac, &restartExec{}, RestartAgentStep{Node: "ghost"}, "not a configured agent host"},
		"unsafe unit":   {agents, scenariotest.AgentControlConfig{User: "root", KeyPath: "/k", Unit: "agent; rm -rf /", ReadyTimeout: time.Second}, &restartExec{}, RestartAgentStep{}, "unsafe for a shell command"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := tc.step.Run(context.Background(), restartEnv(t, tc.agents, tc.ac, tc.exec, nil))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestSkip_AgentControlUnconfigured(t *testing.T) {
	sc := &scenariotest.Scenario{Name: "r", Steps: []scenariotest.Step{RestartAgentStep{}}}
	cfg := fake.Config() // no agent_control creds
	if r := scenariotest.SkipReason(sc, cfg); r == "" {
		t.Error("a restart scenario must SKIP when agent_control.key_path is unset")
	}
	cfg.AgentControl.KeyPath = "/k"
	if r := scenariotest.SkipReason(sc, cfg); r != "" {
		t.Errorf("with creds set it must run, got skip %q", r)
	}
}

// nicMetrics reports the attach gauge from the fake cloud's live
// state: boots plus hot-plugged NICs, minus deleted servers — so the
// attach/detach gates in the NIC lifecycle steps resolve instantly and
// truthfully against what the step just did.
type nicMetrics struct {
	fake.InstantMACs
	Env   *fake.Env
	cloud *fake.Cloud

	Servers []scenariotest.ServerSample
	Ports   []scenariotest.PortSample
	settled float64
	ghosts  float64
}

func (m *nicMetrics) Scrape(context.Context, string) (scenariotest.ScrapeResult, error) {
	deleted := 0
	for k := range m.cloud.Deleted {
		if strings.HasPrefix(k, "server:") {
			deleted++
		}
	}
	return scenariotest.ScrapeResult{
		Present: map[string]bool{
			scenariotest.MetricBytesTotal: true, scenariotest.MetricAttachedInterfaces: true,
			scenariotest.MetricAttachFailures: true, scenariotest.MetricSettledFlows: true,
			scenariotest.MetricServerBytesTotal: true, scenariotest.MetricLingeringGhosts: true,
		},
		AttachedInterfaces: m.Env.BaseAttached + float64(m.Env.Booted) + float64(len(m.cloud.HotAttached)) - float64(deleted),
		AttachFailures:     m.Env.Failures,
		SettledFlows:       m.settled,
		PortBytes:          m.Ports,
		LingeringGhosts:    m.ghosts,
		Servers:            m.Servers,
	}, nil
}

// nicFixture is a live vm-a (booted through the fake cloud so the
// server binding is real) with a second DSL network for hot-plugging.
func nicFixture(t *testing.T) (*fake.Cloud, *nicMetrics, *scenariotest.StepEnv) {
	t.Helper()
	b := scenario.New()
	b.Network("net-a", "T1").Subnet("sub-a", "10.0.30.0/24", "10.0.30.1").VM("vm-a", "T1", "10.0.30.5")
	b.Network("net-b", "T1").Subnet("sub-b", "10.0.31.0/24", "10.0.31.1")
	sc := &scenariotest.Scenario{Name: "nic-lifecycle", Builder: b}

	env := &fake.Env{BaseAttached: 3}
	cloud := fake.NewCloud(env)
	bootPort, err := cloud.CreatePort(context.Background(), "uuid-t1", scenariotest.PortSpec{Name: "boot", NetworkID: "net-1"})
	if err != nil {
		t.Fatal(err)
	}
	srvID, err := cloud.CreateServer(context.Background(), "uuid-t1", scenariotest.ServerSpec{Name: "vm-a", PortID: bootPort})
	if err != nil {
		t.Fatal(err)
	}
	rs := &scenariotest.RunState{
		RunID:    "run1",
		Projects: map[string]scenariotest.ProjectRef{"T1": {Name: "T1", ID: "uuid-t1"}},
		Networks: []scenariotest.ResourceRef{{DSLID: "net-b", ID: "net-2"}},
		Subnets:  []scenariotest.ResourceRef{{DSLID: "sub-b", ID: "sub-2"}},
		Servers:  []scenariotest.ResourceRef{{DSLID: "vm-a", ID: srvID, ProjectID: "uuid-t1"}},
		FIPs:     []scenariotest.FIPRef{{VMID: "vm-a", Address: "203.0.113.9", ProjectID: "uuid-t1"}},
	}
	nm := &nicMetrics{Env: env, cloud: cloud}
	senv := &scenariotest.StepEnv{
		Config: fake.Config(), Scenario: sc, State: rs,
		StatePath: t.TempDir() + "/s.json",
		Cloud:     cloud, Metrics: nm, Exec: &fake.Exec{},
		Log:    slog.New(slog.DiscardHandler),
		Report: &scenariotest.AssertReport{OK: true},
	}
	return cloud, nm, senv
}

func TestSteps_NICLifecycle(t *testing.T) {
	cloud, _, senv := nicFixture(t)
	ctx := context.Background()

	// Attach: fresh port on net-b, recorded with MAC, gate target +1.
	if err := (AttachPortStep{VM: "vm-a", ID: "vm-a-nic2", Network: "net-b", Subnet: "sub-b", IP: "10.0.31.9"}).Run(ctx, senv); err != nil {
		t.Fatalf("attach: %v", err)
	}
	nicID := scenariotest.LiveID(senv.State.Ports, "vm-a-nic2")
	if nicID == "" {
		t.Fatal("attach recorded no nic ref")
	}
	var ref scenariotest.ResourceRef
	for _, p := range senv.State.Ports {
		if p.DSLID == "vm-a-nic2" {
			ref = p
		}
	}
	if ref.MAC == "" {
		t.Error("nic ref carries no MAC — the MAC-learn gate would skip it")
	}
	if got, want := senv.State.Attach.Target, senv.Metrics.(*nicMetrics).Env.BaseAttached+1+1; got != want {
		t.Errorf("attach gate target = %v, want %v", got, want)
	}
	if len(cloud.IfaceOps) != 1 || !strings.HasPrefix(cloud.IfaceOps[0], "attach:") {
		t.Fatalf("ifaceOps = %v, want one attach", cloud.IfaceOps)
	}

	// A bound port must refuse deletion until detached.
	if err := cloud.DeletePort(ctx, "uuid-t1", nicID); err == nil {
		t.Error("DeletePort on an attached port must fail")
	}

	// Detach (keep the port): ref stays, attach record re-baselined down.
	if err := (DetachPortStep{VM: "vm-a", Port: "vm-a-nic2"}).Run(ctx, senv); err != nil {
		t.Fatalf("detach: %v", err)
	}
	if scenariotest.LiveID(senv.State.Ports, "vm-a-nic2") == "" {
		t.Error("detach without Delete must keep the ref")
	}
	// The detached MAC is recorded so a following AwaitSweepStep{ForMACOf}
	// can wait for its fold — even once Delete drops the ref.
	if senv.RecordedMAC("vm-a-nic2") != ref.MAC {
		t.Errorf("detach must record the MAC: RecordedMAC(vm-a-nic2)=%q, want %q", senv.RecordedMAC("vm-a-nic2"), ref.MAC)
	}
	if got, want := senv.State.Attach.Target, senv.Metrics.(*nicMetrics).Env.BaseAttached+1; got != want {
		t.Errorf("post-detach attach target = %v, want %v", got, want)
	}

	// Reattach the same port, then detach+delete it.
	if err := (ReattachPortStep{VM: "vm-a", Port: "vm-a-nic2"}).Run(ctx, senv); err != nil {
		t.Fatalf("reattach: %v", err)
	}
	if err := (DetachPortStep{VM: "vm-a", Port: "vm-a-nic2", Delete: true}).Run(ctx, senv); err != nil {
		t.Fatalf("detach+delete: %v", err)
	}
	if scenariotest.LiveID(senv.State.Ports, "vm-a-nic2") != "" {
		t.Error("detach with Delete must drop the ref (truthful inventory)")
	}
	if !cloud.Deleted["port:"+nicID] {
		t.Error("detach with Delete must delete the Neutron port")
	}
	if len(cloud.IfaceOps) != 4 {
		t.Errorf("ifaceOps = %v, want attach/detach/attach/detach", cloud.IfaceOps)
	}
}

func TestSteps_ConfigureNIC(t *testing.T) {
	_, _, senv := nicFixture(t)
	exec := senv.Exec.(*fake.Exec)
	if err := (ConfigureNICStep{VM: "vm-a", Dev: "eth1", CIDR: "10.0.31.9/24"}).Run(context.Background(), senv); err != nil {
		t.Fatalf("configure-nic: %v", err)
	}
	// Two Calls: the ssh-ready probe (lachesis#253 — the step must not
	// race the fresh VM's sshd), then the configure command.
	if len(exec.Calls) != 2 {
		t.Fatalf("exec calls = %d, want 2 (ssh-ready probe + command)", len(exec.Calls))
	}
	if exec.Calls[0].Command != "true" {
		t.Errorf("first call = %q, want the ssh-ready probe (lachesis#253)", exec.Calls[0].Command)
	}
	call := exec.Calls[1]
	if call.Addr != "203.0.113.9" {
		t.Errorf("configured over %s, want the SSH FIP", call.Addr)
	}
	for _, want := range []string{"ip addr add 10.0.31.9/24 dev eth1", "netmask 255.255.255.0", "link set eth1 up"} {
		if !strings.Contains(call.Command, want) {
			t.Errorf("command lacks %q: %s", want, call.Command)
		}
	}
	// Malformed CIDR fails before any SSH.
	if err := (ConfigureNICStep{VM: "vm-a", Dev: "eth1", CIDR: "not-a-cidr"}).Run(context.Background(), senv); err == nil {
		t.Error("bad CIDR must error")
	}
	// A shell-unsafe Dev is rejected before it reaches the command line.
	if err := (ConfigureNICStep{VM: "vm-a", Dev: "eth1; reboot", CIDR: "10.0.31.9/24"}).Run(context.Background(), senv); err == nil {
		t.Error("shell-unsafe Dev must error")
	}
}

func TestSteps_ServerMonotone(t *testing.T) {
	_, nm, senv := nicFixture(t)
	ctx := context.Background()
	srvID := senv.State.Servers[0].ID

	nm.Servers = []scenariotest.ServerSample{
		{ServerID: srvID, Zone: "same_tenant", Direction: "tx", Value: 100},
		{ServerID: srvID, Zone: "external", Direction: "tx", Value: 40},
	}
	if err := (CaptureStep{}).Run(ctx, senv); err != nil {
		t.Fatal(err)
	}

	// One tuple dips (the partial-fold shape), one keeps growing.
	nm.Servers = []scenariotest.ServerSample{
		{ServerID: srvID, Zone: "same_tenant", Direction: "tx", Value: 60},
		{ServerID: srvID, Zone: "external", Direction: "tx", Value: 41},
	}
	if err := (ServerMonotoneStep{VM: "vm-a", Note: "dip"}).Run(ctx, senv); err != nil {
		t.Fatal(err)
	}
	if senv.Report.OK {
		t.Error("a dipped server tuple must fail the report")
	}
	var fails, passes int
	for _, r := range senv.Report.Rows {
		if r.Pass {
			passes++
		} else {
			fails++
			if r.Zone != "same_tenant" {
				t.Errorf("failing row zone = %s, want same_tenant", r.Zone)
			}
		}
	}
	if fails != 1 || passes != 1 {
		t.Errorf("rows = %d fail / %d pass, want 1/1", fails, passes)
	}

	// No captured tuples for the VM is a scenario bug, not a pass.
	senv.Captured.Servers = map[scenariotest.ServerTuple]float64{}
	if err := (ServerMonotoneStep{VM: "vm-a"}).Run(ctx, senv); err == nil {
		t.Error("no captured tuples must error")
	}
}

func TestSteps_MaxSettled(t *testing.T) {
	_, nm, senv := nicFixture(t)
	ctx := context.Background()

	nm.settled = 7
	if err := (CaptureStep{}).Run(ctx, senv); err != nil {
		t.Fatal(err)
	}

	// Unchanged counter passes a zero budget.
	if err := (MaxSettledStep{Note: "none"}).Run(ctx, senv); err != nil {
		t.Fatal(err)
	}
	if !senv.Report.OK {
		t.Fatalf("no growth must pass: %+v", senv.Report.Rows)
	}

	// Any fold beyond budget fails.
	nm.settled = 9
	if err := (MaxSettledStep{Budget: 1, Note: "folded"}).Run(ctx, senv); err != nil {
		t.Fatal(err)
	}
	if senv.Report.OK {
		t.Error("growth beyond budget must fail the report")
	}
}

func TestSteps_MaxGhosts(t *testing.T) {
	_, nm, senv := nicFixture(t)
	ctx := context.Background()

	nm.ghosts = 3 // a pre-existing ghost on the (shared) agent
	if err := (CaptureStep{}).Run(ctx, senv); err != nil {
		t.Fatal(err)
	}
	// No NEW ghost marked → delta 0 → passes a zero budget, even though
	// the absolute count is non-zero (delta-from-capture, not absolute).
	if err := (MaxGhostsStep{Note: "migration marks no ghost"}).Run(ctx, senv); err != nil {
		t.Fatal(err)
	}
	if !senv.Report.OK {
		t.Fatalf("no new ghost must pass despite a non-zero baseline: %+v", senv.Report.Rows)
	}
	// A newly-marked ghost (e.g. a wrongful migration ghost) fails.
	nm.ghosts = 4
	if err := (MaxGhostsStep{Note: "wrongful ghost"}).Run(ctx, senv); err != nil {
		t.Fatal(err)
	}
	if senv.Report.OK {
		t.Error("a newly-marked ghost must fail the report")
	}
}

// sweepMetrics models a SHARED agent: the global settled counter rises
// on every scrape (other tenants' folds), while the target MAC leaves
// the metadata map only after macGoneAfterLookups lookups.
type sweepMetrics struct {
	settledStart        float64
	macGoneAfterLookups int
	lookups             int
	scrapes             int
}

func (m *sweepMetrics) Scrape(context.Context, string) (scenariotest.ScrapeResult, error) {
	m.scrapes++
	return scenariotest.ScrapeResult{
		Present:      map[string]bool{scenariotest.MetricSettledFlows: true, scenariotest.MetricBytesTotal: true, scenariotest.MetricAttachedInterfaces: true},
		SettledFlows: m.settledStart + float64(m.scrapes), // always rising
	}, nil
}

func (m *sweepMetrics) LookupMAC(_ context.Context, _, _ string) (scenariotest.MACLookup, error) {
	m.lookups++
	if m.lookups >= m.macGoneAfterLookups {
		return scenariotest.MACLookup{Found: false}, nil
	}
	return scenariotest.MACLookup{Found: true, TenantID: "t"}, nil
}

func (m *sweepMetrics) LookupFlows(context.Context, string, string) ([]scenariotest.FlowRow, error) {
	return nil, nil
}

func sweepEnv(t *testing.T, m scenariotest.MetricsSource) *scenariotest.StepEnv {
	t.Helper()
	env := &scenariotest.StepEnv{
		Config:   fake.Config(), // one agent
		State:    &scenariotest.RunState{RunID: "r"},
		Metrics:  m,
		Log:      slog.New(slog.DiscardHandler),
		Report:   &scenariotest.AssertReport{OK: true},
		Captured: scenariotest.Capture{SettledFlows: 10},
	}
	env.RecordMAC("nic", "fa:16:3e:00:00:aa")
	return env
}

// The fix (lachesis#240): ForMACOf waits for the MAC to leave metadata,
// returning as soon as it does — regardless of the rising global counter.
func TestSteps_AwaitSweep_ForMACReturnsWhenGone(t *testing.T) {
	m := &sweepMetrics{settledStart: 10, macGoneAfterLookups: 1}
	if err := (AwaitSweepStep{ForMACOf: "nic", Timeout: time.Second}).Run(context.Background(), sweepEnv(t, m)); err != nil {
		t.Fatalf("await-sweep: %v", err)
	}
	if m.lookups != 1 {
		t.Errorf("lookups = %d, want 1 (MAC gone on first poll)", m.lookups)
	}
}

// The bug it fixes: a rising global settled counter must NOT satisfy a
// ForMACOf wait — while the MAC is still in metadata the step keeps
// waiting and ultimately times out on the MAC, never on the counter.
func TestSteps_AwaitSweep_ForMACIgnoresGlobalSettled(t *testing.T) {
	m := &sweepMetrics{settledStart: 10, macGoneAfterLookups: 1_000_000} // never gone
	err := (AwaitSweepStep{ForMACOf: "nic", Timeout: 60 * time.Millisecond}).Run(context.Background(), sweepEnv(t, m))
	if err == nil || !strings.Contains(err.Error(), "still in metadata") {
		t.Fatalf("want a MAC-still-in-metadata timeout (not a global-settled pass), got %v", err)
	}
}

// Fallback (no ForMACOf) keeps the legacy global-settled behavior.
func TestSteps_AwaitSweep_GlobalFallback(t *testing.T) {
	m := &sweepMetrics{settledStart: 10, macGoneAfterLookups: 1}
	if err := (AwaitSweepStep{Timeout: time.Second}).Run(context.Background(), sweepEnv(t, m)); err != nil {
		t.Fatalf("await-sweep global fallback: %v", err)
	}
	if m.lookups != 0 {
		t.Errorf("global fallback must not call LookupMAC, got %d lookups", m.lookups)
	}
}

// twoAgentCfg returns a config with two agents, for all-agents semantics.
func twoAgentCfg() scenariotest.Config {
	cfg := fake.Config()
	cfg.Cluster.Agents = []scenariotest.AgentConfig{
		{Host: "compute-0", MetricsURL: "http://compute-0:9100/metrics"},
		{Host: "compute-1", MetricsURL: "http://compute-1:9100/metrics"},
	}
	return cfg
}

// perAgentSweep answers LookupMAC per agent URL, and errors when errAll
// is set — for the all-agents and transient-tolerance tests.
type perAgentSweep struct {
	foundOn map[string]bool // metrics URL → MAC still resolves there
	errAll  bool
}

func (m *perAgentSweep) Scrape(context.Context, string) (scenariotest.ScrapeResult, error) {
	return scenariotest.ScrapeResult{Present: map[string]bool{scenariotest.MetricBytesTotal: true, scenariotest.MetricAttachedInterfaces: true}}, nil
}
func (m *perAgentSweep) LookupMAC(_ context.Context, url, _ string) (scenariotest.MACLookup, error) {
	if m.errAll {
		return scenariotest.MACLookup{}, fmt.Errorf("boom: %s unreachable", url)
	}
	return scenariotest.MACLookup{Found: m.foundOn[url]}, nil
}
func (m *perAgentSweep) LookupFlows(context.Context, string, string) ([]scenariotest.FlowRow, error) {
	return nil, nil
}

// Happy path with a real Found→gone transition (fast: shrunk poll interval).
func TestSteps_AwaitSweep_ForMACTransition(t *testing.T) {
	defer func(d time.Duration) { sweepPollInterval = d }(sweepPollInterval)
	sweepPollInterval = 2 * time.Millisecond

	m := &sweepMetrics{settledStart: 10, macGoneAfterLookups: 3} // Found twice, then gone
	env := sweepEnv(t, m)
	if err := (AwaitSweepStep{ForMACOf: "nic", Timeout: time.Second}).Run(context.Background(), env); err != nil {
		t.Fatalf("await-sweep: %v", err)
	}
	if m.lookups < 3 {
		t.Errorf("expected to poll until the MAC folded (>=3 lookups), got %d", m.lookups)
	}
}

// All-agents semantics: while the MAC still resolves on ANY agent the
// wait must not return — it times out here because compute-1 keeps it.
func TestSteps_AwaitSweep_WaitsForAllAgents(t *testing.T) {
	m := &perAgentSweep{foundOn: map[string]bool{
		"http://compute-0:9100/metrics": false, // swept here
		"http://compute-1:9100/metrics": true,  // still present here
	}}
	env := &scenariotest.StepEnv{
		Config: twoAgentCfg(), State: &scenariotest.RunState{RunID: "r"}, Metrics: m,
		Log: slog.New(slog.DiscardHandler), Report: &scenariotest.AssertReport{OK: true},
	}
	env.RecordMAC("nic", "fa:16:3e:00:00:aa")
	err := (AwaitSweepStep{ForMACOf: "nic", Timeout: 60 * time.Millisecond}).Run(context.Background(), env)
	if err == nil || !strings.Contains(err.Error(), "still in metadata") {
		t.Fatalf("must keep waiting while any agent still has the MAC; got %v", err)
	}
}

// Transient lookup errors must not abort the wait: it keeps polling and
// surfaces the last error on timeout, rather than returning immediately.
func TestSteps_AwaitSweep_ToleratesTransientErrors(t *testing.T) {
	m := &perAgentSweep{errAll: true}
	env := sweepEnv(t, m)
	start := time.Now()
	err := (AwaitSweepStep{ForMACOf: "nic", Timeout: 60 * time.Millisecond}).Run(context.Background(), env)
	if err == nil || !strings.Contains(err.Error(), "last lookup error") {
		t.Fatalf("want a timeout carrying the last lookup error (not an immediate abort), got %v", err)
	}
	if time.Since(start) < 40*time.Millisecond {
		t.Errorf("returned too fast (%s) — it aborted on the first error instead of waiting", time.Since(start))
	}
}

// TestSteps_AttachPortMACFrom: MACFrom pins a previously recorded MAC
// onto the new port; an unrecorded handle errors before any cloud call.
func TestSteps_AttachPortMACFrom(t *testing.T) {
	cloud, _, senv := nicFixture(t)
	ctx := context.Background()

	// Record a MAC as DetachPortStep{Delete:true} would.
	senv.RecordMAC("vm-a-nic2", "fa:16:3e:00:00:aa")
	if err := (AttachPortStep{VM: "vm-a", ID: "vm-a-nic3", Network: "net-b", Subnet: "sub-b",
		IP: "10.0.31.10", MACFrom: "vm-a-nic2"}).Run(ctx, senv); err != nil {
		t.Fatalf("attach with MACFrom: %v", err)
	}
	nicID := scenariotest.LiveID(senv.State.Ports, "vm-a-nic3")
	if got := cloud.MACs[nicID]; got != "fa:16:3e:00:00:aa" {
		t.Errorf("created port MAC = %q, want the pinned MAC", got)
	}
	if err := (AttachPortStep{VM: "vm-a", ID: "vm-a-nic4", Network: "net-b", Subnet: "sub-b",
		IP: "10.0.31.11", MACFrom: "never-recorded"}).Run(ctx, senv); err == nil {
		t.Error("MACFrom with no recorded MAC must error")
	}
}

// TestSteps_PortSeries: the port-tier assertion sums only the target
// port's samples; a port whose id is absent (mislabeled traffic) fails.
func TestSteps_PortSeries(t *testing.T) {
	_, nm, senv := nicFixture(t)
	ctx := context.Background()
	senv.State.Ports = append(senv.State.Ports, scenariotest.ResourceRef{DSLID: "vm-a-nic3", ID: "port-new"})

	nm.Ports = []scenariotest.PortSample{
		{PortID: "port-new", ServerID: "srv", Zone: "same_tenant", Direction: "tx", Value: 2 << 20},
		{PortID: "port-old", ServerID: "srv", Zone: "same_tenant", Direction: "tx", Value: 9 << 20},
	}
	if err := (PortSeriesStep{VM: "vm-a", Port: "vm-a-nic3", MinBytes: 1 << 20, Note: "ok"}).Run(ctx, senv); err != nil {
		t.Fatal(err)
	}
	if !senv.Report.OK {
		t.Fatalf("port with enough bytes must pass: %+v", senv.Report.Rows)
	}
	// Traffic mislabeled under another port's id → the target sums 0.
	nm.Ports = []scenariotest.PortSample{
		{PortID: "port-old", ServerID: "srv", Zone: "same_tenant", Direction: "tx", Value: 9 << 20},
	}
	defer func(d time.Duration) { sweepPollInterval = d }(sweepPollInterval)
	sweepPollInterval = 2 * time.Millisecond
	if err := (PortSeriesStep{VM: "vm-a", Port: "vm-a-nic3", MinBytes: 1 << 20, Timeout: 30 * time.Millisecond, Note: "stale"}).Run(ctx, senv); err != nil {
		t.Fatal(err)
	}
	if senv.Report.OK {
		t.Error("absent port_id must fail the row (mislabeled traffic)")
	}
}

// TestSteps_RestartAgentRestoreConfig: the restore variant copies the
// backup over the config WITHOUT re-backing-up first — the backup-first
// spelling would clobber its own source with the alt config (the
// self-destroying restore observed live on c36, 2026-07-22).
func TestSteps_RestartAgentRestoreConfig(t *testing.T) {
	agents := []scenariotest.AgentConfig{{Host: "compute-0", MetricsURL: "http://c0/m"}}
	ac := scenariotest.AgentControlConfig{User: "root", KeyPath: "/k", ConfigPath: "/etc/lachesis/agent.yaml", ReadyTimeout: time.Second}
	exec := &restartExec{}

	if err := (RestartAgentStep{RestoreConfig: true}).Run(context.Background(), restartEnv(t, agents, ac, exec, nil)); err != nil {
		t.Fatalf("restart restore: %v", err)
	}
	if !exec.has("cp -f /etc/lachesis/agent.yaml.scenariotest.bak /etc/lachesis/agent.yaml") {
		t.Errorf("restore copy not issued: %+v", exec.Calls)
	}
	for _, c := range exec.Calls {
		if strings.Contains(c.Command, "agent.yaml /etc/lachesis/agent.yaml.scenariotest.bak") {
			t.Errorf("restore must NOT back up first (clobbers its own source): %q", c.Command)
		}
	}
}

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

func TestZoneGrowthStep(t *testing.T) {
	// The loop timing isn't under test — kill the settle and shrink the
	// poll so cases resolve in milliseconds.
	defer func(s, p time.Duration) { zoneGrowthSettle, sweepPollInterval = s, p }(zoneGrowthSettle, sweepPollInterval)
	zoneGrowthSettle, sweepPollInterval = 0, time.Millisecond

	k := scenariotest.Tuple{Tenant: "u1", Zone: "external", Direction: "tx"}
	cases := []struct {
		name     string
		min, max int64
		current  float64
		wantPass bool
	}{
		{"within [min,max]", 1 << 20, 3 << 20, 2 << 20, true},
		{"below min", 1 << 20, 0, 512 << 10, false},
		{"min met, no ceiling", 1 << 20, 0, 2 << 20, true},
		{"pure upper bound satisfied", 0, 256 << 10, 100 << 10, true},
		{"pure upper bound exceeded", 0, 256 << 10, 1 << 20, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := &scenariotest.StepEnv{
				Config:   fake.Config(),
				State:    &scenariotest.RunState{},
				Metrics:  fake.HealthyMetrics{Bytes: []scenariotest.BytesSample{{TenantID: "u1", Zone: "external", Direction: "tx", Value: tc.current}}},
				Log:      slog.New(slog.DiscardHandler),
				Report:   &scenariotest.AssertReport{OK: true},
				Captured: scenariotest.Capture{Tuples: map[scenariotest.Tuple]float64{k: 0}},
			}
			step := ZoneGrowthStep{Tenant: "u1", Zone: "external", Direction: "tx",
				MinBytes: tc.min, MaxBytes: tc.max, Timeout: 10 * time.Millisecond}
			if err := step.Run(context.Background(), env); err != nil {
				t.Fatalf("Run: %v", err)
			}
			row := env.Report.Rows[len(env.Report.Rows)-1]
			if row.Pass != tc.wantPass {
				t.Errorf("Pass = %v, want %v (delta %.0f, bounds [%d,%d])", row.Pass, tc.wantPass, row.Delta, tc.min, tc.max)
			}
		})
	}
}

// tupleMetrics reports a fixed settled-tuple sum, for SettledTuplesGrewStep.
type tupleMetrics struct{ tuples float64 }

func (m tupleMetrics) Scrape(context.Context, string) (scenariotest.ScrapeResult, error) {
	return scenariotest.ScrapeResult{
		Present:       map[string]bool{scenariotest.MetricTenantSettledTuples: true, scenariotest.MetricBytesTotal: true, scenariotest.MetricAttachedInterfaces: true},
		SettledTuples: m.tuples,
	}, nil
}
func (tupleMetrics) LookupMAC(context.Context, string, string) (scenariotest.MACLookup, error) {
	return scenariotest.MACLookup{}, nil
}
func (tupleMetrics) LookupFlows(context.Context, string, string) ([]scenariotest.FlowRow, error) {
	return nil, nil
}

func TestSettledTuplesGrewStep(t *testing.T) {
	// Timing isn't under test: shrink the poll so the timeout (fail) cases
	// resolve in milliseconds.
	defer func(d time.Duration) { sweepPollInterval = d }(sweepPollInterval)
	sweepPollInterval = time.Millisecond

	cases := []struct {
		name          string
		base, current float64
		min           int64
		wantPass      bool
	}{
		{"fold fired (grew past floor)", 5, 8, 1, true},
		{"exactly at floor", 5, 6, 1, true},
		{"flat — no fold — fails", 5, 5, 1, false},
		{"grew but short of floor", 5, 6, 3, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := &scenariotest.StepEnv{
				Config:   fake.Config(),
				State:    &scenariotest.RunState{},
				Metrics:  tupleMetrics{tuples: tc.current},
				Log:      slog.New(slog.DiscardHandler),
				Report:   &scenariotest.AssertReport{OK: true},
				Captured: scenariotest.Capture{SettledTuples: tc.base},
			}
			step := SettledTuplesGrewStep{Min: tc.min, Timeout: 10 * time.Millisecond}
			if err := step.Run(context.Background(), env); err != nil {
				t.Fatalf("Run: %v", err)
			}
			row := env.Report.Rows[len(env.Report.Rows)-1]
			if row.Pass != tc.wantPass {
				t.Errorf("Pass = %v, want %v (delta %.0f, min %d)", row.Pass, tc.wantPass, row.Delta, tc.min)
			}
		})
	}
}

func TestDeleteFIPStep_ProviderAndGuard(t *testing.T) {
	// vm-a carries two FIPs: the provider SSH FIP (Network "") and a
	// scenario-net FIP (Network "net-ext").
	newEnv := func() *scenariotest.StepEnv {
		return &scenariotest.StepEnv{
			Config: fake.Config(),
			State: &scenariotest.RunState{FIPs: []scenariotest.FIPRef{
				{VMID: "vm-a", ID: "fip-ssh", Address: "203.0.113.9", Network: ""},
				{VMID: "vm-a", ID: "fip-ext", Address: "203.0.113.10", Network: "net-ext"},
			}},
			StatePath: t.TempDir() + "/s.json",
			Cloud:     fake.NewCloud(&fake.Env{}),
			Log:       slog.New(slog.DiscardHandler),
		}
	}
	remaining := func(env *scenariotest.StepEnv) []string {
		var ids []string
		for _, f := range env.State.FIPs {
			ids = append(ids, f.ID)
		}
		return ids
	}

	// Provider deletes exactly the SSH FIP, keeps the scenario one.
	t.Run("provider targets the SSH FIP", func(t *testing.T) {
		env := newEnv()
		if err := (DeleteFIPStep{VM: "vm-a", Provider: true}).Run(context.Background(), env); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if got := remaining(env); len(got) != 1 || got[0] != "fip-ext" {
			t.Errorf("remaining FIPs = %v, want [fip-ext]", got)
		}
	})

	// A normal (non-provider) delete targets the named scenario net and
	// leaves the SSH FIP alone.
	t.Run("non-provider targets the named net", func(t *testing.T) {
		env := newEnv()
		if err := (DeleteFIPStep{VM: "vm-a", Network: "net-ext"}).Run(context.Background(), env); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if got := remaining(env); len(got) != 1 || got[0] != "fip-ssh" {
			t.Errorf("remaining FIPs = %v, want [fip-ssh]", got)
		}
	})

	// The guard: a non-provider delete with an empty Network must NOT
	// sacrifice the SSH FIP — it matches nothing, errors, and deletes none.
	t.Run("non-provider empty network spares the SSH FIP", func(t *testing.T) {
		env := newEnv()
		err := (DeleteFIPStep{VM: "vm-a", Network: ""}).Run(context.Background(), env)
		if err == nil || !strings.Contains(err.Error(), "no matching FIP") {
			t.Fatalf("want a no-match error, got %v", err)
		}
		if len(env.State.FIPs) != 2 {
			t.Errorf("no FIP should have been deleted, have %d", len(env.State.FIPs))
		}
	})
}

func TestSetRouterGatewayStep(t *testing.T) {
	build := func() *scenariotest.Scenario {
		b := scenario.New()
		b.Network("net-T1", "T1").Subnet("sub-T1", "10.0.42.0/24", "10.0.42.1").VM("vm-a", "T1", "10.0.42.5")
		b.ExternalNetwork("net-ext", "admin") // provider marker (not created)
		b.ExternalNetwork("net-ext2", "admin").Subnet("sub-ext2", "172.24.98.0/24", "172.24.98.1")
		b.Router("r-T1", "T1").Attach("sub-T1", "10.0.42.1").ExternalGateway("net-ext")
		return &scenariotest.Scenario{Name: "regw", Builder: b, CreateExternalNets: []string{"net-ext2"}}
	}
	newEnv := func(cloud *fake.Cloud, nets []scenariotest.ResourceRef) *scenariotest.StepEnv {
		return &scenariotest.StepEnv{
			Config:   fake.Config(),
			Scenario: build(),
			State: &scenariotest.RunState{
				Routers:  []scenariotest.ResourceRef{{DSLID: "r-T1", ID: "rtr-1", ProjectID: "uuid-t1"}},
				Networks: nets,
			},
			StatePath: t.TempDir() + "/s.json",
			Cloud:     cloud,
			Log:       slog.New(slog.DiscardHandler),
		}
	}

	// A created external net (net-ext2) resolves straight from run-state.
	t.Run("created net resolves from run-state", func(t *testing.T) {
		cloud := fake.NewCloud(&fake.Env{})
		env := newEnv(cloud, []scenariotest.ResourceRef{{DSLID: "net-ext2", ID: "netid-ext2"}})
		if err := (SetRouterGatewayStep{Router: "r-T1", ExternalNet: "net-ext2"}).Run(context.Background(), env); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if got := cloud.RouterExt["rtr-1"]; got != "netid-ext2" {
			t.Errorf("gateway = %q, want netid-ext2", got)
		}
	})

	// A provider-bound marker (net-ext, absent from run-state) falls back
	// to FindExternalNetwork — the round-trip re-gateway-BACK path.
	t.Run("provider marker falls back to the config external net", func(t *testing.T) {
		cloud := fake.NewCloud(&fake.Env{})
		cloud.ExtNetID = "provider-real"
		env := newEnv(cloud, nil)
		if err := (SetRouterGatewayStep{Router: "r-T1", ExternalNet: "net-ext"}).Run(context.Background(), env); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if got := cloud.RouterExt["rtr-1"]; got != "provider-real" {
			t.Errorf("gateway = %q, want provider-real", got)
		}
	})

	// An id that is neither a created net nor an external marker errors.
	t.Run("unknown network errors", func(t *testing.T) {
		env := newEnv(fake.NewCloud(&fake.Env{}), nil)
		err := (SetRouterGatewayStep{Router: "r-T1", ExternalNet: "net-nope"}).Run(context.Background(), env)
		if err == nil || !strings.Contains(err.Error(), "no live network") {
			t.Fatalf("want a no-live-network error, got %v", err)
		}
	})
}

// resolvedMetrics reports a fixed unresolved-resolved total, for ResolvedGrewStep.
type resolvedMetrics struct{ resolved float64 }

func (m resolvedMetrics) Scrape(context.Context, string) (scenariotest.ScrapeResult, error) {
	return scenariotest.ScrapeResult{
		Present:            map[string]bool{scenariotest.MetricUnresolvedResolved: true, scenariotest.MetricBytesTotal: true, scenariotest.MetricAttachedInterfaces: true},
		UnresolvedResolved: m.resolved,
	}, nil
}
func (resolvedMetrics) LookupMAC(context.Context, string, string) (scenariotest.MACLookup, error) {
	return scenariotest.MACLookup{}, nil
}
func (resolvedMetrics) LookupFlows(context.Context, string, string) ([]scenariotest.FlowRow, error) {
	return nil, nil
}

func TestResolvedGrewStep(t *testing.T) {
	// Timing isn't under test: shrink the poll so the timeout (fail) cases
	// resolve in milliseconds.
	defer func(d time.Duration) { sweepPollInterval = d }(sweepPollInterval)
	sweepPollInterval = time.Millisecond

	cases := []struct {
		name          string
		base, current float64
		min           int64
		wantPass      bool
	}{
		{"late-bind fired (grew past floor)", 3, 12, 1, true},
		{"exactly at floor", 3, 4, 1, true},
		{"none resolved — fails", 3, 3, 1, false},
		{"grew but short of floor", 3, 5, 5, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := &scenariotest.StepEnv{
				Config:   fake.Config(),
				State:    &scenariotest.RunState{},
				Metrics:  resolvedMetrics{resolved: tc.current},
				Log:      slog.New(slog.DiscardHandler),
				Report:   &scenariotest.AssertReport{OK: true},
				Captured: scenariotest.Capture{Resolved: tc.base},
			}
			step := ResolvedGrewStep{Min: tc.min, Timeout: 10 * time.Millisecond}
			if err := step.Run(context.Background(), env); err != nil {
				t.Fatalf("Run: %v", err)
			}
			row := env.Report.Rows[len(env.Report.Rows)-1]
			if row.Pass != tc.wantPass {
				t.Errorf("Pass = %v, want %v (delta %.0f, min %d)", row.Pass, tc.wantPass, row.Delta, tc.min)
			}
		})
	}
}

// evictionMetrics reports a fixed pressure-relief eviction total, for
// EvictionsGrewStep.
type evictionMetrics struct{ evictions float64 }

func (m evictionMetrics) Scrape(context.Context, string) (scenariotest.ScrapeResult, error) {
	return scenariotest.ScrapeResult{
		Present:                 map[string]bool{scenariotest.MetricGCEvictions: true, scenariotest.MetricBytesTotal: true, scenariotest.MetricAttachedInterfaces: true},
		PressureReliefEvictions: m.evictions,
	}, nil
}
func (evictionMetrics) LookupMAC(context.Context, string, string) (scenariotest.MACLookup, error) {
	return scenariotest.MACLookup{}, nil
}
func (evictionMetrics) LookupFlows(context.Context, string, string) ([]scenariotest.FlowRow, error) {
	return nil, nil
}

func TestEvictionsGrewStep(t *testing.T) {
	// Timing isn't under test: shrink the poll so the timeout (fail) cases
	// resolve in milliseconds.
	defer func(d time.Duration) { sweepPollInterval = d }(sweepPollInterval)
	sweepPollInterval = time.Millisecond

	cases := []struct {
		name          string
		base, current float64
		min           int64
		wantPass      bool
	}{
		{"relief ran (grew past floor)", 2000, 5858, 1, true},
		{"exactly at floor", 2000, 2001, 1, true},
		{"never tripped the watermark — fails", 2000, 2000, 1, false},
		{"grew but short of floor", 2000, 2500, 1000, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := &scenariotest.StepEnv{
				Config:   fake.Config(),
				State:    &scenariotest.RunState{},
				Metrics:  evictionMetrics{evictions: tc.current},
				Log:      slog.New(slog.DiscardHandler),
				Report:   &scenariotest.AssertReport{OK: true},
				Captured: scenariotest.Capture{Evictions: tc.base},
			}
			step := EvictionsGrewStep{Min: tc.min, Timeout: 10 * time.Millisecond}
			if err := step.Run(context.Background(), env); err != nil {
				t.Fatalf("Run: %v", err)
			}
			row := env.Report.Rows[len(env.Report.Rows)-1]
			if row.Pass != tc.wantPass {
				t.Errorf("Pass = %v, want %v (delta %.0f, min %d)", row.Pass, tc.wantPass, row.Delta, tc.min)
			}
		})
	}
}

func TestReloadAgentStep(t *testing.T) {
	agents := []scenariotest.AgentConfig{{Host: "compute-0", MetricsURL: "http://c0/m", SSHHost: "10.0.0.10"}}

	// No SetConfig → pure re-read: SIGHUP only, no config write.
	t.Run("no config overrides sends SIGHUP only", func(t *testing.T) {
		ac := scenariotest.AgentControlConfig{User: "root", KeyPath: "/k", Unit: "lachesis-agent"}
		exec := &restartExec{}
		if err := (ReloadAgentStep{}).Run(context.Background(), restartEnv(t, agents, ac, exec, nil)); err != nil {
			t.Fatalf("reload: %v", err)
		}
		if exec.has("cp -f") || exec.has("base64 -d") {
			t.Errorf("no SetConfig, but a config write was issued: %+v", exec.Calls)
		}
		if !exec.has("systemctl kill -s HUP lachesis-agent") {
			t.Errorf("SIGHUP not issued: %+v", exec.Calls)
		}
	})

	// Error paths: each must fail BEFORE the SIGHUP.
	ac := scenariotest.AgentControlConfig{User: "root", KeyPath: "/k", ConfigPath: "/etc/lachesis/agent.yaml"}
	cases := map[string]struct {
		agents  []scenariotest.AgentConfig
		ac      scenariotest.AgentControlConfig
		exec    scenariotest.VMExec
		step    ReloadAgentStep
		wantErr string
	}{
		"no agent exec":               {agents, ac, nil, ReloadAgentStep{}, "no agent-host SSH transport"},
		"missing creds":               {agents, scenariotest.AgentControlConfig{}, &restartExec{}, ReloadAgentStep{}, "user and agent_control.key_path"},
		"set-config without cfg path": {agents, scenariotest.AgentControlConfig{User: "root", KeyPath: "/k"}, &restartExec{}, ReloadAgentStep{SetConfig: map[string]string{"a.b": "1"}}, "config_path is empty"},
		"unsafe unit":                 {agents, scenariotest.AgentControlConfig{User: "root", KeyPath: "/k", Unit: "u; rm -rf /"}, &restartExec{}, ReloadAgentStep{}, "unsafe for a shell command"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := tc.step.Run(context.Background(), restartEnv(t, tc.agents, tc.ac, tc.exec, nil))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
			if re, ok := tc.exec.(*restartExec); ok && re.has("systemctl kill") {
				t.Errorf("must not SIGHUP when validation failed: %+v", re.Calls)
			}
		})
	}
}

// SetConfig patches the node's own config and restarts; it must refuse to
// combine with RestoreConfig, and must validate before touching the host.
func TestRestartAgentStep_SetConfig(t *testing.T) {
	agents := []scenariotest.AgentConfig{{Host: "compute-0", MetricsURL: "http://c0/m", SSHHost: "10.0.0.10"}}
	ac := scenariotest.AgentControlConfig{User: "root", KeyPath: "/k", Unit: "lachesis", ConfigPath: "/root/agent.yaml"}

	t.Run("patches the node config then restarts", func(t *testing.T) {
		exec := &restartExec{catOut: "gc:\n  ghost_grace: 120s\n"}
		env := restartEnv(t, agents, ac, exec, nil)
		step := RestartAgentStep{SetConfig: map[string]string{"gc.pressure_high_watermark": "0.0001"}}
		if err := step.Run(context.Background(), env); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if !exec.has("sudo cat /root/agent.yaml") {
			t.Error("did not read the node's config")
		}
		if !exec.has(".scenariotest.bak") {
			t.Error("did not back up the original")
		}
		if !exec.has("systemctl restart lachesis") {
			t.Error("did not restart the unit")
		}
	})

	// A rejected combination must fail BEFORE touching the host: erroring
	// after the config write would abort the scenario with the node left
	// modified and its restore step never reached.
	t.Run("rejects RestoreConfig combination without mutating the host", func(t *testing.T) {
		exec := &restartExec{catOut: "gc: {}\n"}
		env := restartEnv(t, agents, ac, exec, nil)
		step := RestartAgentStep{RestoreConfig: true, SetConfig: map[string]string{"a.b": "1"}}
		if err := step.Run(context.Background(), env); err == nil {
			t.Error("RestoreConfig + SetConfig should error")
		}
		if exec.has("cp -f") || exec.has("systemctl restart") {
			t.Errorf("host mutated before the combination was rejected: %+v", exec.Calls)
		}
	})

	t.Run("requires config_path", func(t *testing.T) {
		bare := scenariotest.AgentControlConfig{User: "root", KeyPath: "/k", Unit: "lachesis"}
		exec := &restartExec{catOut: "gc: {}\n"}
		env := restartEnv(t, agents, bare, exec, nil)
		step := RestartAgentStep{SetConfig: map[string]string{"a.b": "1"}}
		if err := step.Run(context.Background(), env); err == nil {
			t.Error("SetConfig without agent_control.config_path should error")
		}
		if exec.has("systemctl restart") {
			t.Error("must not restart when the config change is invalid")
		}
	})
}

// The reload half of SetConfig: patches the config already in force,
// SIGHUPs, and — unlike the restart half — takes no backup. Its guards
// must also fire before the host is touched.
func TestReloadAgentStep_SetConfig(t *testing.T) {
	agents := []scenariotest.AgentConfig{{Host: "compute-0", MetricsURL: "http://c0/m", SSHHost: "10.0.0.10"}}
	ac := scenariotest.AgentControlConfig{User: "root", KeyPath: "/k", Unit: "lachesis", ConfigPath: "/root/agent.yaml"}

	t.Run("patches in place and SIGHUPs, no backup", func(t *testing.T) {
		exec := &restartExec{catOut: "reconcile:\n  interval: 600s\n"}
		env := restartEnv(t, agents, ac, exec, nil)
		step := ReloadAgentStep{SetConfig: map[string]string{"reconcile.interval": "15s"}}
		if err := step.Run(context.Background(), env); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if !exec.has("sudo cat /root/agent.yaml") {
			t.Error("did not read the in-force config")
		}
		if exec.has(".scenariotest.bak") {
			t.Error("reload must not back up — it would clobber the restart's copy of the real config")
		}
		if !exec.has("systemctl kill -s HUP lachesis") {
			t.Errorf("did not SIGHUP the unit: %+v", exec.Calls)
		}
		for _, c := range exec.Calls {
			if c.Addr != "10.0.0.10" {
				t.Errorf("SSHed to %q, want the agent's ssh_host 10.0.0.10", c.Addr)
			}
		}
	})

	t.Run("requires config_path", func(t *testing.T) {
		bare := scenariotest.AgentControlConfig{User: "root", KeyPath: "/k", Unit: "lachesis"}
		env := restartEnv(t, agents, bare, &restartExec{catOut: "gc: {}\n"}, nil)
		step := ReloadAgentStep{SetConfig: map[string]string{"a.b": "1"}}
		if err := step.Run(context.Background(), env); err == nil {
			t.Error("SetConfig without agent_control.config_path should error")
		}
	})
}

// forwardExec answers the ip_forward read-back with a canned value; the
// ssh-ready probe ("true") gets an empty reply like the plain fake.
type forwardExec struct {
	Calls    []fake.ExecCall
	readback string
}

func (e *forwardExec) Run(_ context.Context, addr, command string) (string, error) {
	e.Calls = append(e.Calls, fake.ExecCall{Addr: addr, Command: command})
	if strings.Contains(command, "ip_forward") {
		return e.readback, nil
	}
	return "", nil
}

func TestSteps_EnableForwarding(t *testing.T) {
	// Happy path: the guest reports forwarding on, over the SSH FIP.
	t.Run("sets and verifies ip_forward", func(t *testing.T) {
		_, _, senv := nicFixture(t)
		exec := &forwardExec{readback: "1\n0\n"}
		senv.Exec = exec
		if err := (EnableForwardingStep{VM: "vm-a"}).Run(context.Background(), senv); err != nil {
			t.Fatalf("enable-forwarding: %v", err)
		}
		last := exec.Calls[len(exec.Calls)-1]
		if last.Addr != "203.0.113.9" {
			t.Errorf("ran over %s, want the SSH FIP", last.Addr)
		}
		for _, want := range []string{"ip_forward", "rp_filter", "sort -u"} {
			if !strings.Contains(last.Command, want) {
				t.Errorf("command lacks %q: %s", want, last.Command)
			}
		}
	})

	// The branch that matters: a sysctl that did not take (a per-device
	// rp_filter left at 1, a read-only /proc) must fail HERE, not as a
	// mystifying zero-delta at the appliance's tap — which is exactly how
	// it presented the first time this scenario ran live.
	t.Run("a surviving rp_filter fails", func(t *testing.T) {
		_, _, senv := nicFixture(t)
		senv.Exec = &forwardExec{readback: "1\n1\n"} // a per-device rp_filter survived
		err := (EnableForwardingStep{VM: "vm-a"}).Run(context.Background(), senv)
		if err == nil || !strings.Contains(err.Error(), "want [1 0]") {
			t.Fatalf("want a read-back error, got %v", err)
		}
	})

	// No SSH FIP is a scenario bug, caught before any exec.
	t.Run("missing FIP errors", func(t *testing.T) {
		_, _, senv := nicFixture(t)
		senv.State.FIPs = nil
		if err := (EnableForwardingStep{VM: "vm-a"}).Run(context.Background(), senv); err == nil {
			t.Error("missing SSH FIP must error")
		}
	})
}

// TestRemoveStateCmd pins the cold-restart removal Command: WAL always
// (with its .bak), pins only on request, missing paths and the
// pins-without-WAL shape refused, shell-unsafe paths rejected.
func TestRemoveStateCmd(t *testing.T) {
	cases := []struct {
		name    string
		step    RestartAgentStep
		ac      scenariotest.AgentControlConfig
		want    string
		wantErr string
	}{
		{
			name: "wal only",
			step: RestartAgentStep{RemoveWAL: true},
			ac:   scenariotest.AgentControlConfig{WALPath: "/var/lib/lachesis/wal.json"},
			want: "sudo rm -f /var/lib/lachesis/wal.json /var/lib/lachesis/wal.json.bak",
		},
		{
			name: "wal and pins",
			step: RestartAgentStep{RemoveWAL: true, RemovePins: true},
			ac:   scenariotest.AgentControlConfig{WALPath: "/var/lib/lachesis/wal.json", PinPath: "/sys/fs/bpf/lachesis"},
			want: "sudo rm -f /var/lib/lachesis/wal.json /var/lib/lachesis/wal.json.bak && sudo rm -rf /sys/fs/bpf/lachesis",
		},
		{
			name:    "pins without wal refused",
			step:    RestartAgentStep{RemovePins: true},
			ac:      scenariotest.AgentControlConfig{PinPath: "/sys/fs/bpf/lachesis"},
			wantErr: "not a modeled failure shape",
		},
		{
			name:    "missing wal_path",
			step:    RestartAgentStep{RemoveWAL: true},
			ac:      scenariotest.AgentControlConfig{},
			wantErr: "agent_control.wal_path is empty",
		},
		{
			name:    "missing pin_path",
			step:    RestartAgentStep{RemoveWAL: true, RemovePins: true},
			ac:      scenariotest.AgentControlConfig{WALPath: "/w.json"},
			wantErr: "agent_control.pin_path is empty",
		},
		{
			name:    "shell-unsafe wal_path",
			step:    RestartAgentStep{RemoveWAL: true},
			ac:      scenariotest.AgentControlConfig{WALPath: "/tmp/wal; rm -rf /"},
			wantErr: "agent_control.wal_path",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.step.removeStateCmd(tc.ac)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if got != tc.want {
				t.Fatalf("cmd = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestEpochStep pins the assertion semantics: Changed=false demands
// the captured epoch back exactly (and nonzero — an absent gauge must
// not pass as "unchanged"); Changed=true demands a strictly later one.
func TestEpochStep(t *testing.T) {
	cases := []struct {
		name     string
		captured float64
		current  float64
		changed  bool
		wantPass bool
	}{
		{"carried epoch passes unchanged", 1000, 1000, false, true},
		{"new epoch fails unchanged", 1000, 2000, false, false},
		{"zero gauge fails unchanged", 0, 0, false, false},
		{"later epoch passes changed", 1000, 2000, true, true},
		{"same epoch fails changed", 1000, 1000, true, false},
		{"earlier epoch fails changed", 2000, 1000, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := fake.Config()
			host := cfg.Cluster.Agents[0].Host
			env := &scenariotest.StepEnv{
				Config:   cfg,
				Log:      slog.New(slog.DiscardHandler),
				Report:   &scenariotest.AssertReport{OK: true},
				Metrics:  &epochMetrics{epoch: tc.current},
				Captured: scenariotest.Capture{Epochs: map[string]float64{host: tc.captured}},
			}
			if err := (EpochStep{Changed: tc.changed}).Run(context.Background(), env); err != nil {
				t.Fatalf("Run: %v", err)
			}
			rows := env.Report.Rows
			if len(rows) != 1 {
				t.Fatalf("rows = %d, want 1", len(rows))
			}
			if rows[0].Pass != tc.wantPass {
				t.Fatalf("pass = %v, want %v (baseline %v current %v)", rows[0].Pass, tc.wantPass, tc.captured, tc.current)
			}
		})
	}
}

// epochMetrics is a scenariotest.MetricsSource stub returning a fixed epoch gauge.
type epochMetrics struct{ epoch float64 }

func (m *epochMetrics) Scrape(context.Context, string) (scenariotest.ScrapeResult, error) {
	return scenariotest.ScrapeResult{CountersResetEpoch: m.epoch}, nil
}
func (m *epochMetrics) LookupMAC(context.Context, string, string) (scenariotest.MACLookup, error) {
	return scenariotest.MACLookup{}, nil
}
func (m *epochMetrics) LookupFlows(context.Context, string, string) ([]scenariotest.FlowRow, error) {
	return nil, nil
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
