// Package gate holds the poll-until-predicate waits the harness uses
// to sequence a scenario against a cluster that changes asynchronously.
//
// Every gate has the same shape — sample, test, sleep, until a deadline
// — and every one of them exists because something downstream would
// otherwise race: traffic driven before the tap is attached, a guest
// command issued before cloud-init has opened SSH. Naming them
// separately keeps the steps that use them readable as intent, and
// keeps the timeout-and-cadence policy in one place rather than
// re-derived at each call site.
package gate

import (
	"context"
	"fmt"
	"time"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
)

// AttachRise blocks until the agents' summed attached-interfaces gauge
// rises one above baseline with no new attach failures, then refreshes
// the run-state's attach record so a later drive's recheck expects the
// new count. Used by every step that plugs one new tap in.
//
// The no-new-failures half is what makes this a gate rather than a
// sleep: an attach that FAILS also ends the wait, loudly, instead of
// timing out with a misleading "gauge never rose".
//
// kind names the calling step, for the log line.
func AttachRise(ctx context.Context, env *scenariotest.StepEnv, baseline scenariotest.MetricsSnapshot, kind string) error {
	target := baseline.AttachedInterfaces + 1
	ctx, cancel := context.WithTimeout(ctx, scenariotest.DefaultAttachTimeout)
	defer cancel()
	for {
		snap, err := env.Scrape(ctx)
		if err != nil {
			return fmt.Errorf("attach gate scrape: %w", err)
		}
		if snap.AttachFailures > baseline.AttachFailures {
			return fmt.Errorf("attach gate: %.0f new TC attach failure(s)", snap.AttachFailures-baseline.AttachFailures)
		}
		if snap.AttachedInterfaces >= target {
			env.Log.Info(kind+": attach gate green", "attached", snap.AttachedInterfaces, "target", target)
			env.State.Attach = scenariotest.AttachRecord{Target: target, Failures: snap.AttachFailures}
			return env.State.Save(env.StatePath)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("attach gate: attached_interfaces %.0f < %.0f before timeout: %w",
				snap.AttachedInterfaces, target, ctx.Err())
		case <-time.After(scenariotest.AttachPollInterval):
		}
	}
}

// SSHReady polls a trivial command until the VM answers SSH — the
// step-side twin of drive's readiness wait (lachesis#253): Nova ACTIVE
// races cloud-init by tens of seconds, so any step that execs in the
// guest right after `up` must gate on readiness or fail spuriously with
// "Connection refused" on clusters where realize outpaces the boot.
func SSHReady(ctx context.Context, env *scenariotest.StepEnv, vmID, addr string) error {
	ctx, cancel := context.WithTimeout(ctx, scenariotest.DefaultReadyTimeout)
	defer cancel()
	env.Log.Info("waiting for ssh-ready", "vm", vmID, "addr", addr, "timeout", scenariotest.DefaultReadyTimeout)
	for {
		if _, err := env.Exec.Run(ctx, addr, "true"); err == nil {
			env.Log.Info("vm ssh-ready", "vm", vmID, "addr", addr)
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("vm %s (%s) not ssh-ready before deadline: %w", vmID, addr, ctx.Err())
		case <-time.After(scenariotest.ReadyPollInterval):
		}
	}
}
