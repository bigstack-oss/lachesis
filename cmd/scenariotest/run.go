package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"github.com/bigstack-oss/lachesis/cmd/scenariotest/scenarios"
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/spf13/cobra"
)

func newRunCmd(opts *rootOptions) *cobra.Command {
	var keep, all bool
	var skip []string
	cmd := &cobra.Command{
		Use:   "run [--all] <scenario>...",
		Short: "preflight → up → the scenario's steps → down, per scenario, one command.",
		Long: `preflight → up → the scenario's steps → down, per scenario, one command.
--keep skips down. Plain scenarios run drive → assert; step-scripted scenarios
(e.g. mac-reuse) run their declared step list — deleting VMs mid-run, awaiting
the agent's ghost sweep, booting a deferred VM with a captured MAC, and so on.

Multiple names run sequentially (scenarios share the cluster's quotas, attach
gate, and metrics baselines); --all runs every registered scenario in registry
order, minus any named by --skip. A failing scenario is torn down and the
suite continues — the exit code is non-zero if any failed — and the run ends
with a suite summary. Each scenario keeps its own run-state and report files,
so --state/--report only apply when running a single scenario.`,
		Args: func(_ *cobra.Command, args []string) error {
			switch {
			case all && len(args) > 0:
				return usageError{errors.New("--all takes no scenario names")}
			case !all && len(args) == 0:
				return usageError{errors.New("missing scenario name (or --all)")}
			case !all && len(skip) > 0:
				return usageError{errors.New("--skip only applies with --all (with explicit names, just leave the scenario out)")}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			var scs []*scenariotest.Scenario
			if all {
				skipped := map[string]bool{}
				for _, name := range skip {
					if _, err := scenarios.Get(name); err != nil {
						return usageError{fmt.Errorf("--skip: %w", err)}
					}
					skipped[name] = true
				}
				for _, sc := range scenarios.All() {
					if !skipped[sc.Name] {
						scs = append(scs, sc)
					}
				}
				if len(scs) == 0 {
					return usageError{errors.New("--skip left no scenarios to run")}
				}
			} else {
				for _, name := range args {
					sc, err := scenarios.Get(name)
					if err != nil {
						return err
					}
					scs = append(scs, sc)
				}
			}
			if len(scs) > 1 && (opts.state != "" || opts.report != "") {
				return usageError{errors.New("--state/--report name single files; drop them when running multiple scenarios")}
			}

			log := opts.logger()
			ctx, hardStop, stop := interruptContexts(cmd.Context(), log)
			defer stop()
			if len(scs) == 1 {
				return runOne(ctx, hardStop, opts, log, scs[0], keep)
			}
			return runSuite(ctx, hardStop, opts, log, scs, keep)
		},
	}
	cmd.Flags().BoolVar(&keep, "keep", false, "leave each topology up after assert")
	cmd.Flags().BoolVar(&all, "all", false, "run every registered scenario in registry order")
	cmd.Flags().StringSliceVar(&skip, "skip", nil, "with --all: scenario names to leave out (repeatable or comma-separated); unknown names are an error")
	return cmd
}

// interruptContexts arms `run`'s two-stage interrupt handling: the
// first Ctrl-C cancels the returned run context (the scenario stops,
// teardown still happens); the second cancels hardStop (teardown
// aborts) and releases the handler, so a third falls through to the
// default process kill. stop releases everything on normal exit.
func interruptContexts(parent context.Context, log *slog.Logger) (runCtx, hardStop context.Context, stop func()) {
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, os.Interrupt)
	return twoStageContexts(parent, sig, func() { signal.Stop(sig) }, log)
}

// twoStageContexts is interruptContexts with the signal source
// injected so tests can drive it with a plain channel.
func twoStageContexts(parent context.Context, sig <-chan os.Signal, release func(), log *slog.Logger) (context.Context, context.Context, func()) {
	runCtx, runCancel := context.WithCancel(parent)
	hardCtx, hardCancel := context.WithCancel(parent)
	go func() {
		select {
		case <-sig:
			log.Warn("interrupt: stopping the run — teardown still happens (interrupt again to abort it)")
			runCancel()
		case <-hardCtx.Done():
			return
		}
		select {
		case <-sig:
			log.Warn("interrupt: hard stop — teardown aborted; run `down` with the run-state file to clean up")
			hardCancel()
			release()
		case <-hardCtx.Done():
		}
	}()
	return runCtx, hardCtx, func() { release(); runCancel(); hardCancel() }
}

// runOne is the single-scenario path — behavior identical to `run`
// before multi-scenario support.
func runOne(ctx, hardStop context.Context, opts *rootOptions, log *slog.Logger, sc *scenariotest.Scenario, keep bool) error {
	cfg, sc, err := loadConfigAndScenario(opts.config, sc.Name)
	if err != nil {
		return err
	}
	runID, err := scenariotest.NewRunID()
	if err != nil {
		return fmt.Errorf("run: %w", err)
	}
	state := opts.state
	if state == "" {
		state = scenariotest.DefaultStatePath(cfg.Naming.Prefix, runID)
	}
	report := opts.report
	if report == "" {
		report = scenariotest.DefaultReportPath(state)
	}

	cloud, err := newCloud(ctx, cfg, log)
	if err != nil {
		return fmt.Errorf("run: %w", err)
	}
	res, err := scenariotest.Run(ctx, scenariotest.RunOptions{
		Config:     cfg,
		Scenario:   sc,
		RunID:      runID,
		StatePath:  state,
		ReportPath: report,
		Cloud:      cloud,
		Metrics:    newMetrics(log),
		Exec:       scenariotest.NewSSHExec(cfg.SSH, log),
		Log:        log,
		HardStop:   hardStop,
		Keep:       keep,
	})
	if err != nil {
		return fmt.Errorf("run: %w", err)
	}
	if err := emitAssert(os.Stdout, opts.output, res); err != nil {
		return err
	}
	fmt.Printf("report: %s\n", report)
	if !res.OK {
		return errFailed
	}
	return nil
}

// suiteScenario is one scenario's outcome in a multi-scenario run.
type suiteScenario struct {
	Scenario string `json:"scenario"`
	OK       bool   `json:"ok"`
	// Error is set for mechanical failures (preflight not ready, a
	// step unable to run); a failed assertion is OK=false with the
	// detail in the scenario's own report file.
	Error           string  `json:"error,omitempty"`
	DurationSeconds float64 `json:"duration_seconds"`
	State           string  `json:"state"`
	// Report is empty when a mechanical failure aborted the scenario
	// before its report was written.
	Report string `json:"report,omitempty"`
}

// suiteReport is the multi-scenario verdict; the machine format for
// `run --all -output json`.
type suiteReport struct {
	OK        bool            `json:"ok"`
	Scenarios []suiteScenario `json:"scenarios"`
}

// runSuite runs the scenarios sequentially, continuing past failures
// (each scenario tears its own topology down either way, so the next
// one starts from a clean cluster) and ends with the suite summary.
func runSuite(ctx, hardStop context.Context, opts *rootOptions, log *slog.Logger, scs []*scenariotest.Scenario, keep bool) error {
	if opts.config == "" {
		return usageError{errors.New("missing required --config")}
	}
	cfg, err := scenariotest.LoadConfig(opts.config)
	if err != nil {
		return err
	}
	cloud, err := newCloud(ctx, cfg, log)
	if err != nil {
		return fmt.Errorf("run: %w", err)
	}

	suite := suiteReport{OK: true}
	for i, sc := range scs {
		log.Info("suite: scenario starting", "n", i+1, "of", len(scs), "name", sc.Name)
		row := runSuiteOne(ctx, hardStop, cfg, cloud, sc, keep, log)
		suite.Scenarios = append(suite.Scenarios, row)
		if !row.OK {
			suite.OK = false
		}
		if ctx.Err() != nil {
			log.Warn("suite interrupted", "ran", i+1, "of", len(scs))
			break
		}
	}

	if err := emitSuite(os.Stdout, opts.output, suite); err != nil {
		return err
	}
	if !suite.OK {
		return errFailed
	}
	return nil
}

func runSuiteOne(ctx, hardStop context.Context, cfg scenariotest.Config, cloud scenariotest.Cloud, sc *scenariotest.Scenario, keep bool, log *slog.Logger) suiteScenario {
	row := suiteScenario{Scenario: sc.Name}
	runID, err := scenariotest.NewRunID()
	if err != nil {
		row.Error = err.Error()
		return row
	}
	row.State = scenariotest.DefaultStatePath(cfg.Naming.Prefix, runID)
	report := scenariotest.DefaultReportPath(row.State)

	start := time.Now()
	res, err := scenariotest.Run(ctx, scenariotest.RunOptions{
		Config:     cfg,
		Scenario:   sc,
		RunID:      runID,
		StatePath:  row.State,
		ReportPath: report,
		Cloud:      cloud,
		Metrics:    newMetrics(log),
		Exec:       scenariotest.NewSSHExec(cfg.SSH, log),
		Log:        log,
		HardStop:   hardStop,
		Keep:       keep,
	})
	row.DurationSeconds = time.Since(start).Seconds()
	switch {
	case err != nil:
		row.Error = err.Error()
		log.Error("suite: scenario failed", "name", sc.Name, "err", err)
	case !res.OK:
		row.Report = report
		log.Error("suite: scenario assertions failed", "name", sc.Name, "report", report)
	default:
		row.OK = true
		row.Report = report
	}
	return row
}
