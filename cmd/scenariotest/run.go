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

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer stop()
			if len(scs) == 1 {
				return runOne(ctx, opts, scs[0], keep)
			}
			return runSuite(ctx, opts, scs, keep)
		},
	}
	cmd.Flags().BoolVar(&keep, "keep", false, "leave each topology up after assert")
	cmd.Flags().BoolVar(&all, "all", false, "run every registered scenario in registry order")
	cmd.Flags().StringSliceVar(&skip, "skip", nil, "with --all: scenario names to leave out (repeatable or comma-separated); unknown names are an error")
	return cmd
}

// runOne is the single-scenario path — behavior identical to `run`
// before multi-scenario support.
func runOne(ctx context.Context, opts *rootOptions, sc *scenariotest.Scenario, keep bool) error {
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

	log := opts.logger()
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
func runSuite(ctx context.Context, opts *rootOptions, scs []*scenariotest.Scenario, keep bool) error {
	if opts.config == "" {
		return usageError{errors.New("missing required --config")}
	}
	cfg, err := scenariotest.LoadConfig(opts.config)
	if err != nil {
		return err
	}
	log := opts.logger()
	cloud, err := newCloud(ctx, cfg, log)
	if err != nil {
		return fmt.Errorf("run: %w", err)
	}

	suite := suiteReport{OK: true}
	for i, sc := range scs {
		log.Info("suite: scenario starting", "n", i+1, "of", len(scs), "name", sc.Name)
		row := runSuiteOne(ctx, cfg, cloud, opts, sc, keep, log)
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

func runSuiteOne(ctx context.Context, cfg scenariotest.Config, cloud scenariotest.Cloud, opts *rootOptions, sc *scenariotest.Scenario, keep bool, log *slog.Logger) suiteScenario {
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
