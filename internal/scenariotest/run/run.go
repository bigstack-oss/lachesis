// Package run composes the whole loop — preflight, up, the scenario's
// step script, down — into the single command CI and operators invoke.
// It is the only package that depends on every phase; each phase below
// it knows nothing of the others.
package run

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/down"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/preflight"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/realize"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/steps"
)

// teardownTimeout bounds the deferred teardown when it has been
// detached from an already-cancelled run context (operator interrupt).
// Live teardown of the largest scenario is ~1 minute (server deletes
// wait until Nova forgets them); 5 minutes is generous margin without
// hanging an unattended run forever.
const teardownTimeout = 5 * time.Minute

// Options bundles everything the composed `run` needs.
type Options struct {
	Config     scenariotest.Config
	Scenario   *scenariotest.Scenario
	RunID      string
	StatePath  string
	ReportPath string
	Cloud      scenariotest.Cloud
	Metrics    scenariotest.MetricsSource
	Exec       scenariotest.VMExec
	// AgentExec is the agent-host SSH transport for [steps.RestartAgentStep];
	// nil is fine unless a scenario restarts an agent.
	AgentExec scenariotest.VMExec
	Log       *slog.Logger

	// HardStop, when non-nil, aborts even the deferred teardown once
	// cancelled — the CLI cancels it on a second interrupt. The run
	// context's own cancellation (first interrupt) stops the scenario
	// but teardown still runs to completion under [teardownTimeout].
	HardStop context.Context

	// State, when non-nil, resumes against an already-realized
	// topology (a prior `run --keep` or `up`): realize is skipped, the
	// full preflight narrows to the agent checks (the realize-only
	// prerequisites no longer matter to kept VMs), and the step script
	// runs directly — the drive step's attach recheck re-verifies the
	// gate against the state's attach record. StatePath must be the
	// loaded file's own path; RunID is ignored (the state's is used).
	// Teardown semantics are unchanged (Keep still leaves the topology
	// up).
	State *scenariotest.RunState

	// Keep skips the teardown, leaving the topology up for debugging.
	// The run-state records everything a later `down` needs.
	Keep bool

	// SinkDelay passes through to [drive.Options.SinkDelay]; tests set
	// a negative value to skip the sink-bind pause.
	SinkDelay time.Duration
	// MACLearnTimeout passes through to [drive.Options.MACLearnTimeout];
	// zero uses [drive.DefaultMACLearnTimeout], tests set a small value.
	MACLearnTimeout time.Duration
}

// Run composes the whole loop: preflight → up → the scenario's step
// script → down. With [Options.State] set it resumes instead:
// realize is skipped and the script runs against the kept topology.
// An empty [scenariotest.Scenario.Steps] runs the classic linear
// script — drive every declared flow, assert every declared
// expectation — so plain scenarios behave as always; a scripted
// scenario (e.g. mac-reuse) declares its own step order instead.
// Teardown runs whenever `up` created anything — even after a
// mid-script failure — unless Keep is set; the report and run-state
// files always survive. The returned report carries every row the
// script evaluated before a failure.
//
// Error semantics mirror the subcommands: a mechanical failure
// (preflight not ready, realize or a step unable to run) is the
// returned error; a failed assertion is a false Report.OK, not an
// error — the script keeps going so the report shows every check.
func Run(ctx context.Context, opts Options) (scenariotest.AssertReport, error) {
	if opts.Log == nil {
		opts.Log = slog.New(slog.DiscardHandler)
	}
	if opts.State != nil && opts.State.TornDown {
		// Checked before any network work: the answer is in the file.
		return scenariotest.AssertReport{}, fmt.Errorf("run: run-state %s is already torn down — start a fresh run", opts.StatePath)
	}
	if opts.ReportPath == "" {
		opts.ReportPath = scenariotest.DefaultReportPath(opts.StatePath)
	}
	script := opts.Scenario.Steps
	if len(script) == 0 {
		script = steps.Default(opts.Scenario)
	}

	if opts.State == nil {
		pre := preflight.Run(ctx, opts.Config, opts.Scenario, opts.Cloud, opts.Metrics)
		if pre.Skip != "" {
			// Nothing was created; there is nothing to tear down. The
			// resume path never gates: a kept topology already proved
			// the cluster fits.
			return scenariotest.AssertReport{}, &scenariotest.SkipError{Reason: pre.Skip}
		}
		if !pre.OK {
			for _, c := range pre.Checks {
				if !c.OK {
					opts.Log.Error("preflight check failed", "check", c.Name, "detail", c.Detail)
				}
			}
			return scenariotest.AssertReport{}, fmt.Errorf("run: preflight not ready")
		}
	} else if err := preflightResume(ctx, opts.Config, opts.Metrics); err != nil {
		return scenariotest.AssertReport{}, err
	}
	if err := checkStepMetrics(ctx, opts, script); err != nil {
		return scenariotest.AssertReport{}, err
	}
	opts.Log.Info("preflight ready")

	rs := opts.State
	var upErr error
	if rs == nil {
		rs, upErr = realize.Run(ctx, realize.Options{
			Config:    opts.Config,
			Scenario:  opts.Scenario,
			RunID:     opts.RunID,
			StatePath: opts.StatePath,
			Cloud:     opts.Cloud,
			Metrics:   opts.Metrics,
			Log:       opts.Log,
		})
	} else {
		opts.Log.Info("resuming against kept topology", "run_id", rs.RunID, "state", opts.StatePath)
	}
	// From here on, anything recorded in rs gets torn down on every
	// exit path (unless Keep) — including a partial `up`.
	defer func() {
		if opts.Keep {
			opts.Log.Info("--keep set; topology left up", "state", opts.StatePath)
			return
		}
		// Teardown must survive the run context's cancellation — an
		// interrupt mid-run would otherwise fail every delete and
		// strand the topology for a manual `down`. Detach, bounded by
		// teardownTimeout; a cancelled HardStop still aborts.
		tctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), teardownTimeout)
		defer cancel()
		if opts.HardStop != nil {
			defer context.AfterFunc(opts.HardStop, cancel)()
			// AfterFunc fires asynchronously — an interrupt that
			// already arrived must abort before the first delete.
			if opts.HardStop.Err() != nil {
				cancel()
			}
		}
		if err := down.Run(tctx, down.Options{
			Config:    opts.Config,
			State:     rs,
			StatePath: opts.StatePath,
			Cloud:     opts.Cloud,
			Log:       opts.Log,
		}); err != nil {
			opts.Log.Error("teardown incomplete", "err", err)
		}
	}()
	if upErr != nil {
		return scenariotest.AssertReport{}, fmt.Errorf("run: up: %w", upErr)
	}

	report := scenariotest.AssertReport{Scenario: rs.Scenario, RunID: rs.RunID, OK: true}
	env := &scenariotest.StepEnv{
		Config:          opts.Config,
		Scenario:        opts.Scenario,
		State:           rs,
		StatePath:       opts.StatePath,
		ReportPath:      opts.ReportPath,
		Cloud:           opts.Cloud,
		Metrics:         opts.Metrics,
		Exec:            opts.Exec,
		AgentExec:       opts.AgentExec,
		Log:             opts.Log,
		SinkDelay:       opts.SinkDelay,
		MACLearnTimeout: opts.MACLearnTimeout,
		Report:          &report,
	}
	if err := runSteps(ctx, env, script); err != nil {
		return report, err
	}

	if err := report.Save(opts.ReportPath); err != nil {
		return report, err
	}
	opts.Log.Info("report written", "path", opts.ReportPath)
	return report, nil
}

// runSteps executes a scenario's script in order, stopping at the first
// step that errors (a FAILING assertion is not an error — the step
// records its rows and returns nil, so the script continues).
//
// It owns the guarantee that an aborted run does not leave an agent
// host on the scenario's temporary config: the deferred sweep restores
// whatever a step modified and did not put back, on every exit path
// (lachesis#274). That mirrors how [Run] already defers resource
// teardown — a run that dies half-way must not leave state behind,
// whether that state is a Neutron port or a config file.
func runSteps(ctx context.Context, env *scenariotest.StepEnv, script []scenariotest.Step) error {
	defer steps.RestoreDirtyConfigs(ctx, env)
	for i, st := range script {
		env.Log.Info("step", "n", i+1, "of", len(script), "kind", st.Kind())
		if err := st.Run(ctx, env); err != nil {
			return fmt.Errorf("run: %s: %w", st.Kind(), err)
		}
	}
	return nil
}

// preflightResume is the resume-path replacement for the full
// preflight: every agent reachable and exposing the required families.
// The realize-only prerequisites (image, flavor, keypair, secgroup,
// external network) are deliberately not re-checked — the kept VMs no
// longer depend on them, and a prerequisite deleted after `up` must
// not block iterating against the topology it built.
func preflightResume(ctx context.Context, cfg scenariotest.Config, m scenariotest.MetricsSource) error {
	for _, u := range scenariotest.AgentURLs(cfg) {
		res, err := m.Scrape(ctx, u)
		if err != nil {
			return fmt.Errorf("run: scrape %s: %w", u, err)
		}
		if err := scenariotest.CheckRequiredMetrics(res); err != nil {
			return fmt.Errorf("run: agent at %s: %w", u, err)
		}
	}
	return nil
}

// checkStepMetrics scrapes each agent once and verifies it exposes
// every /metrics family the script's script declare they need (e.g.
// [steps.AwaitSweepStep] needs the settled-flows counter, absent on agents
// predating the settled-bytes fold). Failing here — before any
// topology exists — beats a mid-scenario timeout with a misleading
// cause.
func checkStepMetrics(ctx context.Context, opts Options, script []scenariotest.Step) error {
	required := steps.RequiredMetrics(script)
	if len(required) == 0 {
		return nil
	}
	for _, u := range scenariotest.AgentURLs(opts.Config) {
		r, err := opts.Metrics.Scrape(ctx, u)
		if err != nil {
			return fmt.Errorf("run: scrape %s: %w", u, err)
		}
		for _, name := range required {
			if !r.Present[name] {
				return fmt.Errorf("run: agent at %s does not expose %s, which this scenario's script require — deploy a newer agent first", u, name)
			}
		}
	}
	return nil
}
