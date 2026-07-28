// Agent-host steps: restarting and reloading the telemetry agent
// itself. The mechanics live in [agentctl]; these declare intent and
// keep the run's config-restore debt honest.

package steps

import (
	"context"
	"fmt"
	"time"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/agentctl"
)

// RestartAgentStep restarts the telemetry agent on one compute host
// over SSH and waits for it to come back on /metrics with its taps
// re-attached — the prerequisite behind WAL-restart continuity,
// zombie-hunter verification, pressure-GC, and fault-injection
// scenarios. It restarts the agent; the billing-continuity assertions
// (monotone, no reset) are the scenario's own steps after it.
//
// With SetConfig the step derives a modified config from the one the
// node already runs before restarting, bringing the agent back under
// different tunables; the original is backed up to
// <config>.scenariotest.bak on the host. Restoring it is the scenario's
// concern (a later RestartAgentStep with RestoreConfig) — deliberately
// not automatic, since a step has no post-hook.
type RestartAgentStep struct {
	// Node selects the agent: a placement slot ("node:0") or a literal
	// agent host. Empty means the sole agent (errors if more than one).
	Node string
	// SetConfig overrides individual keys in the node's OWN agent config
	// before the restart — dotted YAML path to value, e.g.
	// {"gc.pressure_high_watermark": "0.0001"}. Values are decoded as
	// YAML scalars, so they land with their natural type (float, bool,
	// duration string). Everything not named is preserved, and the
	// original is backed up to <config_path>.scenariotest.bak, so a later
	// RestoreConfig undoes it.
	//
	// This is the cluster-portable way to run an agent under different
	// tunables: nothing has to be pre-staged, and the derived config
	// keeps the node's own broker list, WAL path and credentials.
	// Mutually exclusive with RestoreConfig.
	SetConfig map[string]string
	// RestoreConfig restores the config an earlier SetConfig backed up
	// (<config_path>.scenariotest.bak) before the restart — how a
	// scenario ends a modified-config phase and leaves the node as found.
	RestoreConfig bool
	// RemoveWAL deletes the agent's WAL and its .bak (agent_control.wal_path)
	// between stop and start — the WAL-destroyed cold boot of the
	// counters-reset-epoch design (docs/architecture/boot-and-recovery.md#counters-reset-epoch).
	// With pinned maps still in place the restart is the ADOPTED shape:
	// the kernel counters carry on and only the WAL-held state is lost.
	RemoveWAL bool
	// RemovePins additionally removes the agent's bpffs pin directory
	// (agent_control.pin_path) — combined with RemoveWAL this simulates
	// a host reboot: the true restart-from-zero shape.
	RemovePins bool
	// Timeout overrides [scenariotest.AgentControlConfig.ReadyTimeout] for the
	// post-restart readiness wait.
	Timeout time.Duration
}

func (RestartAgentStep) Kind() string { return "restart-agent" }

// HostNeeds declares the agent_control keys this step reads, so a
// cluster that has not staged them SKIPs rather than failing mid-run.
func (s RestartAgentStep) HostNeeds() scenariotest.HostNeeds {
	return scenariotest.HostNeeds{AgentSSH: true, WALPath: s.RemoveWAL, PinPath: s.RemovePins}
}

// requiredMetrics declares both families the readiness gate checks
// ([requiredMetrics]), so the pre-create step-metric gate refuses up
// front on an agent missing either — not just the one this step reads
// for the tap baseline.
func (RestartAgentStep) RequiredMetrics() []string {
	return []string{scenariotest.MetricBytesTotal, scenariotest.MetricAttachedInterfaces}
}

func (s RestartAgentStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	ctl, err := agentctl.For(env, s.Node)
	if err != nil {
		return fmt.Errorf("restart-agent: %w", err)
	}
	// Baseline THIS agent's tap count so readiness can wait for the
	// re-attach (the boot zombie-hunt drops filters, then re-attaches).
	base, err := ctl.Baseline(ctx)
	if err != nil {
		return fmt.Errorf("restart-agent: %w", err)
	}
	// Backup on Set: this step owns the restore debt, so a run that dies
	// before the scenario's restore step still finds its way home
	// (lachesis#274).
	dirty, restored, err := ctl.ApplyConfig(ctx, agentctl.Change{
		Set: s.SetConfig, Restore: s.RestoreConfig, Backup: true,
	})
	if err != nil {
		return fmt.Errorf("restart-agent: %w", err)
	}
	switch {
	case dirty:
		env.MarkConfigDirty(s.Node)
	case restored:
		env.ClearConfigDirty(s.Node)
	}
	oldPID, err := ctl.Restart(ctx, agentctl.Cycle{RemoveWAL: s.RemoveWAL, RemovePins: s.RemovePins})
	if err != nil {
		return fmt.Errorf("restart-agent: %w", err)
	}
	if err := ctl.AwaitReady(ctx, oldPID, base.AttachedInterfaces, s.Timeout); err != nil {
		return fmt.Errorf("restart-agent: %w", err)
	}
	return nil
}

func (s ReloadAgentStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	ctl, err := agentctl.For(env, s.Node)
	if err != nil {
		return fmt.Errorf("reload-agent: %w", err)
	}
	// Backup false, per the PRECONDITION on the type: the earlier
	// restart's backup holds the real config and must survive.
	dirty, _, err := ctl.ApplyConfig(ctx, agentctl.Change{Set: s.SetConfig, Backup: false})
	if err != nil {
		return fmt.Errorf("reload-agent: %w", err)
	}
	if dirty {
		// Idempotent with the restart that took the backup (the documented
		// precondition), so the normal chained case records one debt, not
		// two. Used standalone — where no backup exists — this turns a
		// silently-modified host into a loud end-of-run failure instead
		// (lachesis#274).
		env.MarkConfigDirty(s.Node)
	}
	if err := ctl.Reload(ctx); err != nil {
		return fmt.Errorf("reload-agent: %w", err)
	}
	return nil
}

// ReloadAgentStep installs an alternate config on an agent host and
// sends SIGHUP — a HOT reload, not a restart: the process does not
// cycle, so in-memory state (crucially the UnresolvedBuffer) survives.
// It is how the unresolved-latebind scenario "resumes the metadata
// feed" — swap in a config with a short reconcile interval and SIGHUP,
// and the running agent's next periodic reconcile learns the newly
// booted VM and late-binds its buffered bytes. Only hot-reloadable
// fields take effect (docs/operations/runtime.md); a restart would
// discard the buffer this scenario depends on.
//
// PRECONDITION when SetConfig is set: unlike [RestartAgentStep], this
// deliberately does NOT back up the current config (a reload chains
// after a restart's config change, and a second backup would clobber
// that restart's original-config backup). So it is only safe after a
// RestartAgentStep has already backed up the real config, and the
// scenario must restore it explicitly (its final RestartAgentStep with
// RestoreConfig). Used standalone, it would modify the config with no
// way back.
type ReloadAgentStep struct {
	// Node selects the agent (a placement slot or literal host); empty
	// means the sole agent.
	Node string
	// SetConfig overrides individual keys in the config the node is
	// currently running, before the SIGHUP — dotted YAML path to value,
	// like [RestartAgentStep.SetConfig]. Because it patches the CURRENT
	// config, overrides an earlier restart applied stay in force and this
	// step only names what changes.
	//
	// NO backup is taken (see the PRECONDITION on the type): the earlier
	// restart's backup is the scenario's way home.
	SetConfig map[string]string
}

func (ReloadAgentStep) Kind() string { return "reload-agent" }

// RestoreDirtyConfigs puts back every agent config a step modified and
// did not restore. It is the safety net for the abort paths: a step
// error returns straight out of the executor, so a scenario's trailing
// restore step is never reached and the host would otherwise keep
// serving the scenario's temporary config — silently, into whatever
// runs next (lachesis#274).
//
// Deliberately best-effort and loud: a failure here is logged at error
// level naming the host, never returned, because it must not mask the
// original step error that caused the abort. Restores run newest-first
// and through the ordinary [RestartAgentStep] path, so the running
// agent ends up on the restored file rather than merely the file being
// right on disk.
//
// The context is detached from ctx (a cancelled run — Ctrl-C — is
// exactly when config gets stranded) but bounded, so a wedged host
// cannot hang the run's exit.
func RestoreDirtyConfigs(ctx context.Context, env *scenariotest.StepEnv) {
	nodes := env.TakeConfigDirty()
	if len(nodes) == 0 {
		return
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), configRestoreTimeout)
	defer cancel()
	for i := len(nodes) - 1; i >= 0; i-- {
		node := nodes[i]
		env.Log.Warn("restoring an agent config the run left modified", "node", node)
		if err := (RestartAgentStep{Node: node, RestoreConfig: true}).Run(rctx, env); err != nil {
			env.Log.Error("agent config NOT restored — the host is still on the scenario's config",
				"node", node, "err", err)
		}
	}
}
