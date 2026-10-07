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

// RestartAgentStep restarts the agent on one compute host and waits
// for it to return on /metrics with its taps re-attached. It only
// restarts; the billing-continuity assertions are the scenario's own
// steps after it.
//
// SetConfig derives a modified config from the node's own before
// restarting, backing the original up on the host. Restoring is the
// scenario's job — a step has no post-hook.
type RestartAgentStep struct {
	// Node selects the agent: a placement slot ("node:0") or a literal
	// agent host. Empty means the sole agent (errors if more than one).
	Node string
	// SetConfig overrides individual keys in the node's OWN config —
	// dotted YAML path to value, decoded as YAML scalars so each lands
	// with its natural type. Unnamed keys are preserved and the original
	// is backed up, which keeps the node's own brokers, WAL path and
	// credentials. Mutually exclusive with RestoreConfig.
	SetConfig map[string]string
	// RestoreConfig restores the config an earlier SetConfig backed up
	// (<config_path>.scenariotest.bak) before the restart — how a
	// scenario ends a modified-config phase and leaves the node as found.
	RestoreConfig bool
	// RemoveWAL deletes the agent's WAL and its .bak (agent_control.wal_path)
	// between stop and start — the WAL-destroyed cold boot of the
	// counters-reset-epoch design. With pinned maps still in place the
	// restart is the ADOPTED shape: the kernel counters carry on and
	// only the WAL-held state is lost.
	//
	// Counters-reset epoch: docs/architecture/boot-and-recovery.md#counters-reset-epoch
	RemoveWAL bool
	// RemovePins additionally removes the agent's bpffs pin directory
	// (agent_control.pin_path) — combined with RemoveWAL this simulates
	// a host reboot: the true restart-from-zero shape.
	RemovePins bool
	// Down runs these steps while the agent is stopped, between stop and
	// start — e.g. a [DeleteVMStep], to model a VM deleted during an
	// agent outage. They must not need the agent's /metrics. The agent
	// is started again even if one fails.
	Down []scenariotest.Step
	// TapsGoneWhileDown is how many of this node's taps the Down steps
	// remove, so the readiness wait expects that many fewer re-attached.
	TapsGoneWhileDown int
	// Timeout overrides [scenariotest.AgentControlConfig.ReadyTimeout] for the
	// post-restart readiness wait.
	Timeout time.Duration
}

func (RestartAgentStep) Kind() string { return "restart-agent" }

// HostNeeds declares the agent_control keys this step reads, so a
// cluster that has not staged them SKIPs rather than failing mid-run.
func (s RestartAgentStep) HostNeeds() scenariotest.HostNeeds {
	n := scenariotest.HostNeeds{AgentSSH: true, WALPath: s.RemoveWAL, PinPath: s.RemovePins}
	for _, st := range s.Down {
		if r, ok := st.(scenariotest.HostRequirer); ok {
			m := r.HostNeeds()
			n.WALPath = n.WALPath || m.WALPath
			n.PinPath = n.PinPath || m.PinPath
		}
	}
	return n
}

// requiredMetrics declares both families the readiness gate checks
// ([requiredMetrics]), so the pre-create step-metric gate refuses up
// front on an agent missing either — not just the one this step reads
// for the tap baseline.
func (s RestartAgentStep) RequiredMetrics() []string {
	return append([]string{scenariotest.MetricBytesTotal, scenariotest.MetricAttachedInterfaces},
		RequiredMetrics(s.Down)...)
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
	cycle := agentctl.Cycle{RemoveWAL: s.RemoveWAL, RemovePins: s.RemovePins}
	var oldPID string
	if len(s.Down) == 0 {
		if oldPID, err = ctl.Restart(ctx, cycle); err != nil {
			return fmt.Errorf("restart-agent: %w", err)
		}
	} else if oldPID, err = s.cycleAround(ctx, env, ctl, cycle); err != nil {
		return fmt.Errorf("restart-agent: %w", err)
	}
	wantTaps := base.AttachedInterfaces - float64(s.TapsGoneWhileDown)
	if err := ctl.AwaitReady(ctx, oldPID, wantTaps, s.Timeout); err != nil {
		return fmt.Errorf("restart-agent: %w", err)
	}
	return nil
}

// cycleAround stops the agent, runs the Down steps, and starts it again
// — always, so a failed Down step never leaves the host without its
// agent. A Down failure wins over a start failure in the error.
func (s RestartAgentStep) cycleAround(ctx context.Context, env *scenariotest.StepEnv, ctl *agentctl.Controller, cy agentctl.Cycle) (string, error) {
	oldPID, err := ctl.Stop(ctx)
	if err != nil {
		return "", err
	}
	var downErr error
	for _, st := range s.Down {
		env.Log.Info("restart-agent: agent down", "step", st.Kind())
		if downErr = st.Run(ctx, env); downErr != nil {
			downErr = fmt.Errorf("while agent down: %s: %w", st.Kind(), downErr)
			break
		}
	}
	startErr := ctl.Start(ctx, cy)
	if downErr != nil {
		return "", downErr
	}
	return oldPID, startErr
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

// ReloadAgentStep installs an alternate config and sends SIGHUP — a
// HOT reload, so in-memory state (crucially the UnresolvedBuffer)
// survives where a restart would discard it. Only hot-reloadable fields
// take effect.
//
// PRECONDITION with SetConfig: this deliberately takes NO backup, since
// a reload chains after a restart's config change and a second backup
// would clobber that restart's. Safe only after a RestartAgentStep has
// backed up the real config; used standalone there is no way home.
//
// docs/operations/runtime.md
type ReloadAgentStep struct {
	// Node selects the agent (a placement slot or literal host); empty
	// means the sole agent.
	Node string
	// SetConfig patches the CURRENT config before the SIGHUP, so an
	// earlier restart's overrides stay in force and this step names only
	// what changes. No backup — see the PRECONDITION on the type.
	SetConfig map[string]string
}

func (ReloadAgentStep) Kind() string { return "reload-agent" }

// StripTCStep deletes the clsact qdisc — and with it the agent's
// telemetry filters — on a VM's tap, behind the agent's back. No link
// event marks it, so the netlink subscriber's event path cannot see it;
// only the agent's attach-presence sweep restores the filters. Pair it
// with a [CaptureStep] before and a [ReattachHealedStep] after.
//
// docs/architecture/boot-and-recovery.md#attach-presence-resync
type StripTCStep struct {
	// VM is the DSL id of the VM whose tap is stripped.
	VM string
	// Node selects the agent host the VM's tap lives on: a placement
	// slot ("node:0") or a literal agent host. Empty means the sole
	// agent (errors if more than one).
	Node string
}

func (StripTCStep) Kind() string { return "strip-tc" }

// HostNeeds declares the agent-host SSH this step drives, so a cluster
// without agent_control SKIPs rather than failing mid-run.
func (StripTCStep) HostNeeds() scenariotest.HostNeeds {
	return scenariotest.HostNeeds{AgentSSH: true}
}

func (s StripTCStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	portID := scenariotest.LiveID(env.State.Ports, s.VM)
	if len(portID) < tapNameLen-len("tap") {
		return fmt.Errorf("strip-tc: run-state has no port for VM %q", s.VM)
	}
	ctl, err := agentctl.For(env, s.Node)
	if err != nil {
		return fmt.Errorf("strip-tc: %w", err)
	}
	if err := ctl.StripTC(ctx, tapName(portID)); err != nil {
		return fmt.Errorf("strip-tc: %w", err)
	}
	return nil
}

// tapName is the host-side tap interface of the Neutron port portID.
func tapName(portID string) string {
	return ("tap" + portID)[:tapNameLen]
}

// RestoreDirtyConfigs puts back every agent config a step modified and
// did not restore — the safety net for abort paths, where a step error
// returns straight out of the executor and the trailing restore step
// never runs.
//
// Best-effort and loud: failures log at error level and are never
// returned, so they cannot mask the original error. Restores run
// newest-first through the ordinary restart path, so the agent ends up
// running the restored file. The context is detached (a Ctrl-C is
// exactly when config gets stranded) but bounded.
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
