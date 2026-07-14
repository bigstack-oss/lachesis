package scenariotest

import (
	"context"
	"fmt"
	"io"
	"time"
)

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
	Log        io.Writer

	// Keep skips the teardown, leaving the topology up for debugging.
	// The run-state records everything a later `down` needs.
	Keep bool

	// SinkDelay passes through to [DriveOptions.SinkDelay]; tests set
	// a negative value to skip the sink-bind pause.
	SinkDelay time.Duration
}

// Run composes the whole loop: preflight → up → the scenario's step
// script → down. An empty [Scenario.Steps] runs the classic linear
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
		opts.Log = io.Discard
	}
	if opts.ReportPath == "" {
		opts.ReportPath = DefaultReportPath(opts.StatePath)
	}
	steps := opts.Scenario.Steps
	if len(steps) == 0 {
		steps = defaultSteps(opts.Scenario)
	}

	pre := Preflight(ctx, opts.Config, opts.Scenario, opts.Cloud, opts.Metrics)
	if !pre.OK {
		_ = pre.Emit(opts.Log, "human")
		return AssertReport{}, fmt.Errorf("run: preflight not ready")
	}
	if err := checkStepMetrics(ctx, opts, steps); err != nil {
		return AssertReport{}, err
	}
	fmt.Fprintln(opts.Log, "run: preflight ready")

	rs, upErr := Realize(ctx, RealizeOptions{
		Config:    opts.Config,
		Scenario:  opts.Scenario,
		RunID:     opts.RunID,
		StatePath: opts.StatePath,
		Cloud:     opts.Cloud,
		Metrics:   opts.Metrics,
		Log:       opts.Log,
	})
	// From here on, anything recorded in rs gets torn down on every
	// exit path (unless Keep) — including a partial `up`.
	defer func() {
		if opts.Keep {
			fmt.Fprintf(opts.Log, "run: -keep set; topology left up (run-state at %s)\n", opts.StatePath)
			return
		}
		if err := Down(ctx, DownOptions{
			Config:    opts.Config,
			State:     rs,
			StatePath: opts.StatePath,
			Cloud:     opts.Cloud,
			Log:       opts.Log,
		}); err != nil {
			fmt.Fprintf(opts.Log, "run: teardown incomplete: %v\n", err)
		}
	}()
	if upErr != nil {
		return AssertReport{}, fmt.Errorf("run: up: %w", upErr)
	}

	report := AssertReport{Scenario: rs.Scenario, RunID: rs.RunID, OK: true}
	env := &StepEnv{
		Config:     opts.Config,
		Scenario:   opts.Scenario,
		State:      rs,
		StatePath:  opts.StatePath,
		ReportPath: opts.ReportPath,
		Cloud:      opts.Cloud,
		Metrics:    opts.Metrics,
		Exec:       opts.Exec,
		Log:        opts.Log,
		SinkDelay:  opts.SinkDelay,
		Report:     &report,
	}
	for i, st := range steps {
		fmt.Fprintf(opts.Log, "run: step %d/%d: %s\n", i+1, len(steps), st.Kind())
		if err := st.Run(ctx, env); err != nil {
			return report, fmt.Errorf("run: %s: %w", st.Kind(), err)
		}
	}

	if err := report.Save(opts.ReportPath); err != nil {
		return report, err
	}
	fmt.Fprintf(opts.Log, "run: report written to %s\n", opts.ReportPath)
	return report, nil
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
