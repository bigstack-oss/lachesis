// Package agentctl drives the telemetry agent on a compute host: the
// systemd lifecycle, the on-host config, the durable state a cold
// restart destroys, and the readiness gate proving the process cycled.
//
// It exists so a step says WHAT it wants while the HOW — credential
// checks, shell-safety, the exact systemctl line, the config round-trip
// — lives in one testable place.
//
// Everything that could reject a request is checked BEFORE the host is
// touched: a check firing after the config swap would abort with the
// node already modified and its restore step never reached.
package agentctl

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
)

// defaultUnit is the systemd unit an unconfigured agent_control drives.
const defaultUnit = "lachesis-agent"

// readyPollInterval is the pause between readiness probes after a
// restart.
const readyPollInterval = 2 * time.Second

// Controller drives one agent host. Build it with [For]; by the time
// you hold one, the credentials, the unit name and any config path
// have been validated and the SSH address resolved.
type Controller struct {
	// Agent is the configured agent this controller drives.
	Agent scenariotest.AgentConfig
	// Host is the address to SSH to (agent_control's ssh_host, else the
	// hypervisor host).
	Host string
	// Unit is the systemd unit name.
	Unit string

	control scenariotest.AgentControlConfig
	exec    scenariotest.VMExec
	metrics scenariotest.MetricsSource
	log     *slog.Logger
}

// For resolves the controller for node ("" = the sole agent) and
// validates everything that must hold before the host is touched: an
// agent-host SSH transport exists, the credentials are configured, and
// the unit name is safe to interpolate into a root command line.
func For(env *scenariotest.StepEnv, node string) (*Controller, error) {
	if env.AgentExec == nil {
		return nil, fmt.Errorf("no agent-host SSH transport — set agent_control in the config")
	}
	ac := env.Config.AgentControl
	if ac.KeyPath == "" || ac.User == "" {
		return nil, fmt.Errorf("agent_control.user and agent_control.key_path are required")
	}
	agent, err := scenariotest.AgentForNode(env.Config, node)
	if err != nil {
		return nil, err
	}
	unit := ac.Unit
	if unit == "" {
		unit = defaultUnit
	}
	// The unit and any config paths are interpolated into an SSH command
	// line; reject shell-unsafe values (operator/scenario-controlled, but
	// a stray metacharacter would misexecute as root).
	if err := scenariotest.ShellSafe("agent_control.unit", unit); err != nil {
		return nil, err
	}
	return &Controller{
		Agent: agent, Host: agent.SSHAddr(), Unit: unit,
		control: ac, exec: env.AgentExec, metrics: env.Metrics, log: env.Log,
	}, nil
}

// Baseline scrapes this agent once — the tap count [Controller.AwaitReady]
// waits to see restored after a restart.
func (c *Controller) Baseline(ctx context.Context) (scenariotest.ScrapeResult, error) {
	res, err := c.metrics.Scrape(ctx, c.Agent.MetricsURL)
	if err != nil {
		return res, fmt.Errorf("baseline scrape %s: %w", c.Agent.MetricsURL, err)
	}
	return res, nil
}

// MainPID reads the systemd MainPID of the unit — the restart evidence
// [Controller.AwaitReady] gates on. Returns the bare PID string ("0"
// when the unit is stopped).
func (c *Controller) MainPID(ctx context.Context) (string, error) {
	out, err := c.exec.Run(ctx, c.Host, "systemctl show -p MainPID "+c.Unit)
	if err != nil {
		return "", err
	}
	// Output is "MainPID=<n>" (possibly with surrounding whitespace).
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(out), "MainPID=")), nil
}

// Change is a requested edit to the agent's on-host config.
type Change struct {
	// Set overrides individual keys by dotted YAML path.
	Set map[string]string
	// Restore copies the backup an earlier Set took back over the live
	// config. Mutually exclusive with Set.
	Restore bool
	// Backup takes a copy of the original before applying Set, so a later
	// Restore can put it back. False when the source is already a patched
	// config whose backup must survive.
	Backup bool
}

func (ch Change) none() bool { return len(ch.Set) == 0 && !ch.Restore }

// validate rejects an impossible request before anything is written.
func (ch Change) validate(ac scenariotest.AgentControlConfig) error {
	if ch.none() {
		return nil
	}
	if len(ch.Set) > 0 && ch.Restore {
		return fmt.Errorf("SetConfig and RestoreConfig are mutually exclusive")
	}
	if ac.ConfigPath == "" {
		return fmt.Errorf("config changes need agent_control.config_path")
	}
	return scenariotest.ShellSafe("agent_control.config_path", ac.ConfigPath)
}

// ApplyConfig performs ch against the host. It reports whether the
// node now owes a restore (Set applied) or has settled its debt
// (Restore applied) so the caller can keep the run's dirty list
// accurate; a no-op Change reports neither.
func (c *Controller) ApplyConfig(ctx context.Context, ch Change) (dirty, restored bool, err error) {
	if err := ch.validate(c.control); err != nil {
		return false, false, err
	}
	if ch.none() {
		return false, false, nil
	}
	path := c.control.ConfigPath
	if ch.Restore {
		// Copy the backup an earlier Set took back over the live config.
		// No backup-first here: the source IS the backup, so backing up
		// would clobber it (a self-destroying restore).
		cmd := fmt.Sprintf("sudo cp -f %s.scenariotest.bak %s", path, path)
		if out, err := c.exec.Run(ctx, c.Host, cmd); err != nil {
			return false, false, fmt.Errorf("restore config on %s: %w (output: %s)", c.Host, err, out)
		}
		c.log.Info("agent config restored", "host", c.Host, "path", path)
		return false, true, nil
	}
	if err := applySet(ctx, c.exec, c.Host, path, ch.Set, ch.Backup); err != nil {
		return false, false, err
	}
	c.log.Info("agent config overrides applied", "host", c.Host, "path", path, "keys", len(ch.Set))
	return true, false, nil
}

// Cycle names what a restart destroys on the way through.
type Cycle struct {
	// RemoveWAL deletes the agent's WAL and its .bak between stop and
	// start — the WAL-destroyed cold boot.
	RemoveWAL bool
	// RemovePins additionally removes the bpffs pin directory; combined
	// with RemoveWAL this simulates a host reboot.
	RemovePins bool
}

// Restart cycles the unit, optionally destroying durable state in the
// gap. It returns the pre-restart MainPID, which [Controller.AwaitReady]
// needs as restart evidence. Reading the PID is best-effort: if the
// agent is down the returned value is empty and any running new PID
// counts as evidence.
func (c *Controller) Restart(ctx context.Context, cy Cycle) (oldPID string, err error) {
	cmd := "sudo systemctl restart " + c.Unit
	if cy.RemoveWAL || cy.RemovePins {
		rm, err := c.removeStateCmd(cy)
		if err != nil {
			return "", err
		}
		// Stop first so the final flush cannot re-create the WAL after
		// the removal; the gap is the cold boot under test.
		cmd = "sudo systemctl stop " + c.Unit + " && " + rm + " && sudo systemctl start " + c.Unit
	}
	oldPID, _ = c.MainPID(ctx)
	if out, err := c.exec.Run(ctx, c.Host, cmd); err != nil {
		return "", fmt.Errorf("cycle %s on %s: %w (output: %s)", c.Unit, c.Host, err, out)
	}
	c.log.Info("agent restart issued", "host", c.Host, "unit", c.Unit,
		"old_pid", oldPID, "remove_wal", cy.RemoveWAL, "remove_pins", cy.RemovePins)
	return oldPID, nil
}

// removeStateCmd builds the state-removal command for a cold restart:
// the WAL (and .bak) always; the bpffs pins when RemovePins asks for a
// full host-reboot simulation. Paths come from agent_control so
// scenarios stay cluster-portable.
func (c *Controller) removeStateCmd(cy Cycle) (string, error) {
	if !cy.RemoveWAL {
		return "", fmt.Errorf("RemovePins without RemoveWAL is not a modeled failure shape — pins cannot vanish while the WAL survives a running host")
	}
	if c.control.WALPath == "" {
		return "", fmt.Errorf("RemoveWAL set but agent_control.wal_path is empty")
	}
	if err := scenariotest.ShellSafe("agent_control.wal_path", c.control.WALPath); err != nil {
		return "", err
	}
	cmd := fmt.Sprintf("sudo rm -f %s %s.bak", c.control.WALPath, c.control.WALPath)
	if cy.RemovePins {
		if c.control.PinPath == "" {
			return "", fmt.Errorf("RemovePins set but agent_control.pin_path is empty")
		}
		if err := scenariotest.ShellSafe("agent_control.pin_path", c.control.PinPath); err != nil {
			return "", err
		}
		cmd += fmt.Sprintf(" && sudo rm -rf %s", c.control.PinPath)
	}
	return cmd, nil
}

// Reload SIGHUPs the unit's main process so the agent re-reads its YAML
// and applies the hot-reloadable fields; the process keeps running.
// (No ExecReload on the unit — the signal goes directly.)
func (c *Controller) Reload(ctx context.Context) error {
	if out, err := c.exec.Run(ctx, c.Host, "sudo systemctl kill -s HUP "+c.Unit); err != nil {
		return fmt.Errorf("SIGHUP %s on %s: %w (output: %s)", c.Unit, c.Host, err, out)
	}
	c.log.Info("agent SIGHUP sent", "host", c.Host, "unit", c.Unit)
	return nil
}

// AwaitReady blocks until the restart is confirmed AND the agent is
// serving: a MainPID different from oldPID, and /metrics answering with
// the tap count back at baseTaps.
//
// Both halves matter. Without the PID check the probe can pass against
// the very process meant to be replaced; without the tap check the next
// step drives traffic into a tapless host.
func (c *Controller) AwaitReady(ctx context.Context, oldPID string, baseTaps float64, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = c.control.ReadyTimeout
	}
	if timeout <= 0 {
		timeout = scenariotest.DefaultAgentReadyTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	restarted := false
	for {
		if !restarted {
			pid, err := c.MainPID(ctx)
			if err == nil && pid != "" && pid != "0" && pid != oldPID {
				restarted = true
				c.log.Info("agent process cycled", "host", c.Host, "old_pid", oldPID, "new_pid", pid)
			}
		}
		if restarted {
			res, err := c.metrics.Scrape(ctx, c.Agent.MetricsURL)
			if err == nil && scenariotest.CheckRequiredMetrics(res) == nil && res.AttachedInterfaces >= baseTaps {
				c.log.Info("agent ready", "host", c.Host,
					"attached", res.AttachedInterfaces, "baseline", baseTaps)
				return nil
			}
		}
		select {
		case <-ctx.Done():
			if !restarted {
				return fmt.Errorf("%s MainPID never changed from %q within %s — restart not confirmed: %w",
					c.Unit, oldPID, timeout, ctx.Err())
			}
			return fmt.Errorf("%s not ready within %s: %w", c.Agent.MetricsURL, timeout, ctx.Err())
		case <-time.After(readyPollInterval):
		}
	}
}
