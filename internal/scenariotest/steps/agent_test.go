package steps

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
		"set-config without cfg path": {agents, scenariotest.AgentControlConfig{User: "root", KeyPath: "/k"}, &restartExec{}, ReloadAgentStep{SetConfig: map[string]string{"a.b": "1"}}, "config changes need agent_control.config_path"},
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
