package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"github.com/bigstack-oss/lachesis/cmd/scenariotest/scenarios"
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/spf13/cobra"
)

func newRunCmd(opts *rootOptions) *cobra.Command {
	var keep, all, noSkip bool
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
so --state/--report only apply when running a single scenario.

With a single scenario, --state pointing at an existing, still-live run-state
file resumes against that kept topology (the partner of --keep): realize is
skipped, the attach gate is re-verified, and the step script runs directly. A
torn-down file (a completed run's leftover) is overwritten by a fresh run.

A scenario whose placement slots need more nodes than the config lists is
SKIPPED, not failed: nothing is created, the verdict says why, and the exit
code stays 0 (the suite summary counts skips separately). --no-skip tightens
that to a failure, for clusters that are supposed to satisfy every scenario.`,
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
				return runOne(ctx, hardStop, opts, log, scs[0], keep, noSkip)
			}
			return runSuite(ctx, hardStop, opts, log, scs, keep, noSkip)
		},
	}
	cmd.Flags().BoolVar(&keep, "keep", false, "leave each topology up after assert")
	cmd.Flags().BoolVar(&all, "all", false, "run every registered scenario in registry order")
	cmd.Flags().StringSliceVar(&skip, "skip", nil, "with --all: scenario names to leave out (repeatable or comma-separated); unknown names are an error")
	cmd.Flags().BoolVar(&noSkip, "no-skip", false, "treat SKIPPED scenarios (cluster smaller than the placement slots need) as failures")
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

// resolveResume decides what an existing --state file means: a
// still-live one resumes against its kept topology (the partner of
// --keep); a torn-down one is a completed run's leftover and gets
// overwritten by a fresh run (the pre-resume behavior, so scripts
// pinning --state to a fixed path keep working). A file for a
// different scenario is an error, as it is for drive/assert/down.
func resolveResume(statePath string, sc *scenariotest.Scenario, log *slog.Logger) (*scenariotest.RunState, error) {
	if statePath == "" {
		return nil, nil
	}
	rs, err := loadRunState(statePath, sc, "run")
	switch {
	case err == nil && rs.TornDown:
		log.Info("existing run-state is torn down — starting a fresh run over it", "state", statePath)
		return nil, nil
	case err == nil:
		if len(sc.Steps) > 0 {
			log.Warn("resuming a step-scripted scenario — its script may not be idempotent against the already-mutated topology")
		}
		return rs, nil
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil // fresh run writing there
	default:
		return nil, err
	}
}

// runOne is the single-scenario path — behavior identical to `run`
// before multi-scenario support.
func runOne(ctx, hardStop context.Context, opts *rootOptions, log *slog.Logger, sc *scenariotest.Scenario, keep, noSkip bool) error {
	cfg, sc, err := loadConfigAndScenario(opts.config, sc.Name)
	if err != nil {
		return err
	}

	resume, err := resolveResume(opts.state, sc, log)
	if err != nil {
		return err
	}

	runID := ""
	if resume == nil {
		if runID, err = scenariotest.NewRunID(); err != nil {
			return fmt.Errorf("run: %w", err)
		}
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
		AgentExec:  scenariotest.NewSSHExec(cfg.AgentControl.SSHConfig(), log),
		Log:        log,
		HardStop:   hardStop,
		State:      resume,
		Keep:       keep,
	})
	var skip *scenariotest.SkipError
	if errors.As(err, &skip) {
		if err := emitSkip(os.Stdout, opts.output, sc.Name, skip.Reason); err != nil {
			return err
		}
		if noSkip {
			return errFailed
		}
		return nil
	}
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
	Error string `json:"error,omitempty"`
	// Skipped carries the reason the scenario could not run on this
	// cluster (placement slots need more nodes than configured).
	// A skipped row never fails the suite unless --no-skip is set.
	Skipped         string  `json:"skipped,omitempty"`
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
	Pass      int             `json:"pass"`
	Fail      int             `json:"fail"`
	Skipped   int             `json:"skipped"`
	Scenarios []suiteScenario `json:"scenarios"`
}

// summarize fills the suite counts and verdict from the rows: skipped
// rows never fail the suite unless noSkip tightens them.
func summarize(rows []suiteScenario, noSkip bool) suiteReport {
	r := suiteReport{Scenarios: rows}
	for _, s := range rows {
		switch {
		case s.Skipped != "":
			r.Skipped++
		case s.OK:
			r.Pass++
		default:
			r.Fail++
		}
	}
	r.OK = r.Fail == 0 && (!noSkip || r.Skipped == 0)
	return r
}

// runSuite runs the scenarios sequentially, continuing past failures
// (each scenario tears its own topology down either way, so the next
// one starts from a clean cluster) and ends with the suite summary.
func runSuite(ctx, hardStop context.Context, opts *rootOptions, log *slog.Logger, scs []*scenariotest.Scenario, keep, noSkip bool) error {
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

	var rows []suiteScenario
	for i, sc := range scs {
		log.Info("suite: scenario starting", "n", i+1, "of", len(scs), "name", sc.Name)
		rows = append(rows, runSuiteOne(ctx, hardStop, cfg, cloud, sc, keep, log))
		if ctx.Err() != nil {
			log.Warn("suite interrupted", "ran", i+1, "of", len(scs))
			break
		}
	}
	suite := summarize(rows, noSkip)

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
		AgentExec:  scenariotest.NewSSHExec(cfg.AgentControl.SSHConfig(), log),
		Log:        log,
		HardStop:   hardStop,
		Keep:       keep,
	})
	row.DurationSeconds = time.Since(start).Seconds()
	var skip *scenariotest.SkipError
	switch {
	case errors.As(err, &skip):
		// Nothing ran: no state file was written, so don't point at one.
		row.Skipped, row.State = skip.Reason, ""
		log.Warn("suite: scenario skipped", "name", sc.Name, "reason", skip.Reason)
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
