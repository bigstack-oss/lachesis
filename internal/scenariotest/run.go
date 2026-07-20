package scenariotest

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// teardownTimeout bounds the deferred teardown when it has been
// detached from an already-cancelled run context (operator interrupt).
// Live teardown of the largest scenario is ~1 minute (server deletes
// wait until Nova forgets them); 5 minutes is generous margin without
// hanging an unattended run forever.
const teardownTimeout = 5 * time.Minute

// SkipError reports that the scenario cannot run on this cluster —
// its placement slots need more nodes than the config lists. Not a
// failure: the CLI maps it to a SKIPPED verdict and exit 0, and the
// suite counts it separately (`--no-skip` tightens both to failures,
// for clusters that are supposed to satisfy every scenario).
type SkipError struct{ Reason string }

func (e *SkipError) Error() string { return "skipped: " + e.Reason }

// RunOptions bundles everything the composed `run` needs.
type RunOptions struct {
	Config     Config
	Scenario   *Scenario
	RunID      string
	StatePath  string
	ReportPath string
	Cloud      Cloud
	Metrics    MetricsSource
	Exec       VMExec
	// AgentExec is the agent-host SSH transport for [RestartAgentStep];
	// nil is fine unless a scenario restarts an agent.
	AgentExec VMExec
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
	State *RunState

	// Keep skips the teardown, leaving the topology up for debugging.
	// The run-state records everything a later `down` needs.
	Keep bool

	// SinkDelay passes through to [DriveOptions.SinkDelay]; tests set
	// a negative value to skip the sink-bind pause.
	SinkDelay time.Duration
	// MACLearnTimeout passes through to [DriveOptions.MACLearnTimeout];
	// zero uses [DefaultMACLearnTimeout], tests set a small value.
	MACLearnTimeout time.Duration
}

// Run composes the whole loop: preflight → up → the scenario's step
// script → down. With [RunOptions.State] set it resumes instead:
// realize is skipped and the script runs against the kept topology.
// An empty [Scenario.Steps] runs the classic linear
// script — drive every declared flow, assert every declared
// expectation — so plain scenarios behave as always; a scripted
// scenario (e.g. mac-reuse) declares its own step order instead.
// Teardown runs whenever `up` created anything — even after a
// mid-script failure — unless Keep is set; the report and run-state
// files always survive. The returned report carries every row the
// steps evaluated before a failure.
//
// Error semantics mirror the subcommands: a mechanical failure
// (preflight not ready, realize or a step unable to run) is the
// returned error; a failed assertion is a false Report.OK, not an
// error — the script keeps going so the report shows every check.
func Run(ctx context.Context, opts RunOptions) (AssertReport, error) {
	if opts.Log == nil {
		opts.Log = slog.New(slog.DiscardHandler)
	}
	if opts.State != nil && opts.State.TornDown {
		// Checked before any network work: the answer is in the file.
		return AssertReport{}, fmt.Errorf("run: run-state %s is already torn down — start a fresh run", opts.StatePath)
	}
	if opts.ReportPath == "" {
		opts.ReportPath = DefaultReportPath(opts.StatePath)
	}
	steps := opts.Scenario.Steps
	if len(steps) == 0 {
		steps = defaultSteps(opts.Scenario)
	}

	if opts.State == nil {
		pre := Preflight(ctx, opts.Config, opts.Scenario, opts.Cloud, opts.Metrics)
		if pre.Skip != "" {
			// Nothing was created; there is nothing to tear down. The
			// resume path never gates: a kept topology already proved
			// the cluster fits.
			return AssertReport{}, &SkipError{Reason: pre.Skip}
		}
		if !pre.OK {
			for _, c := range pre.Checks {
				if !c.OK {
					opts.Log.Error("preflight check failed", "check", c.Name, "detail", c.Detail)
				}
			}
			return AssertReport{}, fmt.Errorf("run: preflight not ready")
		}
	} else if err := preflightResume(ctx, opts.Config, opts.Metrics); err != nil {
		return AssertReport{}, err
	}
	if err := checkStepMetrics(ctx, opts, steps); err != nil {
		return AssertReport{}, err
	}
	opts.Log.Info("preflight ready")

	rs := opts.State
	var upErr error
	if rs == nil {
		rs, upErr = Realize(ctx, RealizeOptions{
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
		if err := Down(tctx, DownOptions{
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
		return AssertReport{}, fmt.Errorf("run: up: %w", upErr)
	}

	report := AssertReport{Scenario: rs.Scenario, RunID: rs.RunID, OK: true}
	env := &StepEnv{
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
	for i, st := range steps {
		opts.Log.Info("step", "n", i+1, "of", len(steps), "kind", st.Kind())
		if err := st.Run(ctx, env); err != nil {
			return report, fmt.Errorf("run: %s: %w", st.Kind(), err)
		}
	}

	if err := report.Save(opts.ReportPath); err != nil {
		return report, err
	}
	opts.Log.Info("report written", "path", opts.ReportPath)
	return report, nil
}

// preflightResume is the resume-path replacement for the full
// preflight: every agent reachable and exposing the required families.
// The realize-only prerequisites (image, flavor, keypair, secgroup,
// external network) are deliberately not re-checked — the kept VMs no
// longer depend on them, and a prerequisite deleted after `up` must
// not block iterating against the topology it built.
func preflightResume(ctx context.Context, cfg Config, m MetricsSource) error {
	for _, u := range agentURLs(cfg) {
		res, err := m.Scrape(ctx, u)
		if err != nil {
			return fmt.Errorf("run: scrape %s: %w", u, err)
		}
		if err := requiredMetrics(res); err != nil {
			return fmt.Errorf("run: agent at %s: %w", u, err)
		}
	}
	return nil
}

// checkStepMetrics scrapes each agent once and verifies it exposes
// every /metrics family the script's steps declare they need (e.g.
// [AwaitSweepStep] needs the settled-flows counter, absent on agents
// predating the settled-bytes fold). Failing here — before any
// topology exists — beats a mid-scenario timeout with a misleading
// cause.
func checkStepMetrics(ctx context.Context, opts RunOptions, steps []Step) error {
	required := requiredStepMetrics(steps)
	if len(required) == 0 {
		return nil
	}
	for _, u := range agentURLs(opts.Config) {
		r, err := opts.Metrics.Scrape(ctx, u)
		if err != nil {
			return fmt.Errorf("run: scrape %s: %w", u, err)
		}
		for _, name := range required {
			if !r.Present[name] {
				return fmt.Errorf("run: agent at %s does not expose %s, which this scenario's steps require — deploy a newer agent first", u, name)
			}
		}
	}
	return nil
}
