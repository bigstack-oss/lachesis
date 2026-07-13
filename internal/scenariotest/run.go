package scenariotest

import (
	"context"
	"fmt"
	"io"
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
}

// Run composes the whole loop: preflight → up → drive → assert →
// down. Teardown runs whenever `up` created anything — even after a
// drive or assert failure — unless Keep is set; the assert report and
// run-state files always survive. The returned report is zero-valued
// when the run failed before assert evaluated.
//
// Error semantics mirror the subcommands: a mechanical failure
// (preflight not ready, realize/drive/assert unable to run) is the
// returned error; expectations failing is a false Report.OK, not an
// error.
func Run(ctx context.Context, opts RunOptions) (AssertReport, error) {
	if opts.Log == nil {
		opts.Log = io.Discard
	}

	pre := Preflight(ctx, opts.Config, opts.Scenario, opts.Cloud, opts.Metrics)
	if !pre.OK {
		_ = pre.Emit(opts.Log, "human")
		return AssertReport{}, fmt.Errorf("run: preflight not ready")
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

	if err := Drive(ctx, DriveOptions{
		Config:    opts.Config,
		Scenario:  opts.Scenario,
		State:     rs,
		StatePath: opts.StatePath,
		Metrics:   opts.Metrics,
		Exec:      opts.Exec,
		Log:       opts.Log,
	}); err != nil {
		return AssertReport{}, fmt.Errorf("run: drive: %w", err)
	}

	report, err := Assert(ctx, AssertOptions{
		Config:     opts.Config,
		Scenario:   opts.Scenario,
		State:      rs,
		ReportPath: opts.ReportPath,
		Metrics:    opts.Metrics,
		Log:        opts.Log,
	})
	if err != nil {
		return report, fmt.Errorf("run: assert: %w", err)
	}
	return report, nil
}
