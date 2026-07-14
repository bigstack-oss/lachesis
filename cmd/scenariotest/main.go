// Command scenariotest realizes a declared topology + traffic +
// expectations on a live OpenStack cluster and asserts whether the
// agent's /metrics deltas match the description.
//
// Usage:
//
//	scenariotest <subcommand> [flags]
//
// Subcommands:
//
//	list                 — show registered scenarios
//	preflight <name>     — check cluster readiness (read-only)
//	up        <name>     — realize topology, leave it attached-ready
//	drive     <name>     — push declared flows (not yet implemented)
//	assert    <name>     — scrape + compare deltas (not yet implemented)
//	run       <name>     — preflight → up → drive → assert → down
//	down                 — tear down (not yet implemented)
//
// See docs/test-strategy.md (Tier 4) for where scenariotest sits
// relative to the unit and integration tiers.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"text/tabwriter"

	"github.com/bigstack-oss/lachesis/cmd/scenariotest/scenarios"
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
)

const usage = `scenariotest — describe a topology, realize it on a live cluster, assert /metrics deltas.

Usage:
  scenariotest <subcommand> [flags]

Subcommands:
  list                  Show registered scenarios.
  preflight <name>      Check cluster readiness (read-only).
  up        <name>      Realize topology and wait for the agents to attach.
  drive     <name>      Re-check the attach gate, snapshot the metrics baseline, push declared flows.
  assert    <name>      Evaluate MinBytes expectations against /metrics deltas; write the report.
  down      <name>      Tear down everything in the run-state (idempotent; projects and
                        report/run-state files are never touched).
  run       <name>      preflight → up → the scenario's steps → down, one command. -keep skips down.
                        Plain scenarios run drive → assert; step-scripted scenarios (e.g. mac-reuse)
                        run their declared step list — deleting VMs mid-run, awaiting the agent's
                        ghost sweep, booting a deferred VM with a captured MAC, and so on.

Common flags:
  -config <path>        Config file path. Required for everything except list.
  -output <human|json>  preflight/assert/run output format (default human).
  -state  <path>        Run-state file: written by up/run (default .scenariotest/<prefix>-<runid>.json),
                        required by drive, assert, and down.
  -report <path>        assert/run report file (default <state>-report.json). Survives down.
  -keep                 run only: leave the topology up after assert.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	sub, args := os.Args[1], os.Args[2:]
	switch sub {
	case "list":
		os.Exit(runList(os.Stdout, args))
	case "preflight":
		os.Exit(runPreflight(args))
	case "up":
		os.Exit(runUp(args))
	case "drive":
		os.Exit(runDrive(args))
	case "assert":
		os.Exit(runAssert(args))
	case "down":
		os.Exit(runDown(args))
	case "run":
		os.Exit(runRun(args))
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, usage)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n%s", sub, usage)
		os.Exit(2)
	}
}

func runList(out io.Writer, args []string) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, "list:", err)
		return 2
	}
	all := scenarios.All()
	if len(all) == 0 {
		fmt.Fprintln(out, "(no scenarios registered)")
		return 0
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tFLOWS\tEXPECT\tSTEPS\tPLACEMENT\tDESC")
	for _, s := range all {
		placement := "(scheduler)"
		if len(s.Placement) > 0 {
			placement = fmt.Sprintf("%d pinned", len(s.Placement))
		}
		flows, expects := countDeclared(s)
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%s\t%s\n", s.Name, flows, expects, len(s.Steps), placement, s.Desc)
	}
	tw.Flush()
	return 0
}

// countDeclared totals a scenario's flows and expectations wherever
// they are declared — top-level for plain scenarios, inside Drive and
// Assert steps for scripted ones.
func countDeclared(s *scenariotest.Scenario) (flows, expects int) {
	flows, expects = len(s.Flows), len(s.Expect)
	for _, st := range s.Steps {
		switch st := st.(type) {
		case scenariotest.DriveStep:
			flows += len(st.Flows)
		case scenariotest.AssertStep:
			expects += len(st.Expect)
		}
	}
	return flows, expects
}

func runPreflight(args []string) int {
	fs := flag.NewFlagSet("preflight", flag.ContinueOnError)
	configPath := fs.String("config", "", "config file path (required)")
	output := fs.String("output", "human", "output format: human|json")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, sc, code := loadConfigAndScenario(*configPath, fs.Arg(0))
	if code != 0 {
		return code
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	cloud, err := newCloud(ctx, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "preflight:", err)
		return 1
	}
	report := scenariotest.Preflight(ctx, cfg, sc, cloud, scenariotest.NewHTTPMetrics(nil))
	if err := report.Emit(os.Stdout, *output); err != nil {
		fmt.Fprintln(os.Stderr, "preflight:", err)
		return 1
	}
	if !report.OK {
		return 1
	}
	return 0
}

func runUp(args []string) int {
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	configPath := fs.String("config", "", "config file path (required)")
	statePath := fs.String("state", "", "run-state file path (default .scenariotest/<prefix>-<runid>.json)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, sc, code := loadConfigAndScenario(*configPath, fs.Arg(0))
	if code != 0 {
		return code
	}

	runID, err := scenariotest.NewRunID()
	if err != nil {
		fmt.Fprintln(os.Stderr, "up:", err)
		return 1
	}
	state := *statePath
	if state == "" {
		state = scenariotest.DefaultStatePath(cfg.Naming.Prefix, runID)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	cloud, err := newCloud(ctx, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "up:", err)
		return 1
	}

	rs, err := scenariotest.Realize(ctx, scenariotest.RealizeOptions{
		Config:    cfg,
		Scenario:  sc,
		RunID:     runID,
		StatePath: state,
		Cloud:     cloud,
		Metrics:   scenariotest.NewHTTPMetrics(nil),
		Log:       os.Stderr,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "up:", err)
		if rs != nil {
			fmt.Fprintf(os.Stderr, "partial run-state written to %s; run `down` to clean up\n", state)
		}
		return 1
	}
	fmt.Printf("up ok: scenario=%s run-id=%s vms=%d fips=%d state=%s\n",
		sc.Name, runID, len(rs.Servers), len(rs.FIPs), state)
	return 0
}

func runDrive(args []string) int {
	fs := flag.NewFlagSet("drive", flag.ContinueOnError)
	configPath := fs.String("config", "", "config file path (required)")
	statePath := fs.String("state", "", "run-state file written by up (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, sc, code := loadConfigAndScenario(*configPath, fs.Arg(0))
	if code != 0 {
		return code
	}
	if *statePath == "" {
		fmt.Fprintln(os.Stderr, "missing required -state (the file `up` wrote)")
		return 2
	}
	rs, err := scenariotest.LoadRunState(*statePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "drive:", err)
		return 1
	}
	if rs.Scenario != sc.Name {
		fmt.Fprintf(os.Stderr, "drive: run-state %s is for scenario %q, not %q\n", *statePath, rs.Scenario, sc.Name)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	err = scenariotest.Drive(ctx, scenariotest.DriveOptions{
		Config:    cfg,
		Scenario:  sc,
		State:     rs,
		StatePath: *statePath,
		Metrics:   scenariotest.NewHTTPMetrics(nil),
		Exec:      scenariotest.NewSSHExec(cfg.SSH),
		Log:       os.Stderr,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "drive:", err)
		return 1
	}
	fmt.Printf("drive ok: scenario=%s flows=%d state=%s\n", sc.Name, len(sc.Flows), *statePath)
	return 0
}

func runAssert(args []string) int {
	fs := flag.NewFlagSet("assert", flag.ContinueOnError)
	configPath := fs.String("config", "", "config file path (required)")
	statePath := fs.String("state", "", "run-state file written by up + drive (required)")
	reportPath := fs.String("report", "", "report file (default <state>-report.json)")
	output := fs.String("output", "human", "output format: human|json")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, sc, code := loadConfigAndScenario(*configPath, fs.Arg(0))
	if code != 0 {
		return code
	}
	if *statePath == "" {
		fmt.Fprintln(os.Stderr, "missing required -state (the file `up` wrote)")
		return 2
	}
	rs, err := scenariotest.LoadRunState(*statePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "assert:", err)
		return 1
	}
	if rs.Scenario != sc.Name {
		fmt.Fprintf(os.Stderr, "assert: run-state %s is for scenario %q, not %q\n", *statePath, rs.Scenario, sc.Name)
		return 1
	}
	report := *reportPath
	if report == "" {
		report = scenariotest.DefaultReportPath(*statePath)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	res, err := scenariotest.Assert(ctx, scenariotest.AssertOptions{
		Config:     cfg,
		Scenario:   sc,
		State:      rs,
		ReportPath: report,
		Metrics:    scenariotest.NewHTTPMetrics(nil),
		Log:        os.Stderr,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "assert:", err)
		return 1
	}
	if err := res.Emit(os.Stdout, *output); err != nil {
		fmt.Fprintln(os.Stderr, "assert:", err)
		return 1
	}
	if !res.OK {
		return 1
	}
	return 0
}

func runDown(args []string) int {
	fs := flag.NewFlagSet("down", flag.ContinueOnError)
	configPath := fs.String("config", "", "config file path (required)")
	statePath := fs.String("state", "", "run-state file written by up (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, sc, code := loadConfigAndScenario(*configPath, fs.Arg(0))
	if code != 0 {
		return code
	}
	if *statePath == "" {
		fmt.Fprintln(os.Stderr, "missing required -state (the file `up` wrote)")
		return 2
	}
	rs, err := scenariotest.LoadRunState(*statePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "down:", err)
		return 1
	}
	if rs.Scenario != sc.Name {
		fmt.Fprintf(os.Stderr, "down: run-state %s is for scenario %q, not %q\n", *statePath, rs.Scenario, sc.Name)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	cloud, err := newCloud(ctx, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "down:", err)
		return 1
	}
	if err := scenariotest.Down(ctx, scenariotest.DownOptions{
		Config:    cfg,
		State:     rs,
		StatePath: *statePath,
		Cloud:     cloud,
		Log:       os.Stderr,
	}); err != nil {
		fmt.Fprintln(os.Stderr, "down:", err)
		return 1
	}
	fmt.Printf("down ok: scenario=%s run-id=%s (projects kept; state and report files kept)\n", sc.Name, rs.RunID)
	return 0
}

func runRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	configPath := fs.String("config", "", "config file path (required)")
	statePath := fs.String("state", "", "run-state file path (default .scenariotest/<prefix>-<runid>.json)")
	reportPath := fs.String("report", "", "report file (default <state>-report.json)")
	output := fs.String("output", "human", "output format: human|json")
	keep := fs.Bool("keep", false, "leave the topology up after assert")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, sc, code := loadConfigAndScenario(*configPath, fs.Arg(0))
	if code != 0 {
		return code
	}
	runID, err := scenariotest.NewRunID()
	if err != nil {
		fmt.Fprintln(os.Stderr, "run:", err)
		return 1
	}
	state := *statePath
	if state == "" {
		state = scenariotest.DefaultStatePath(cfg.Naming.Prefix, runID)
	}
	report := *reportPath
	if report == "" {
		report = scenariotest.DefaultReportPath(state)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	cloud, err := newCloud(ctx, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "run:", err)
		return 1
	}
	res, err := scenariotest.Run(ctx, scenariotest.RunOptions{
		Config:     cfg,
		Scenario:   sc,
		RunID:      runID,
		StatePath:  state,
		ReportPath: report,
		Cloud:      cloud,
		Metrics:    scenariotest.NewHTTPMetrics(nil),
		Exec:       scenariotest.NewSSHExec(cfg.SSH),
		Log:        os.Stderr,
		Keep:       *keep,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "run:", err)
		return 1
	}
	if err := res.Emit(os.Stdout, *output); err != nil {
		fmt.Fprintln(os.Stderr, "run:", err)
		return 1
	}
	fmt.Printf("report: %s\n", report)
	if !res.OK {
		return 1
	}
	return 0
}

// loadConfigAndScenario loads the config file and resolves the named
// scenario, returning a non-zero exit code on any error.
func loadConfigAndScenario(configPath, name string) (scenariotest.Config, *scenariotest.Scenario, int) {
	if configPath == "" {
		fmt.Fprintln(os.Stderr, "missing required -config")
		return scenariotest.Config{}, nil, 2
	}
	if name == "" {
		fmt.Fprintln(os.Stderr, "missing scenario name")
		return scenariotest.Config{}, nil, 2
	}
	cfg, err := scenariotest.LoadConfig(configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return scenariotest.Config{}, nil, 1
	}
	sc, err := scenarios.Get(name)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return scenariotest.Config{}, nil, 1
	}
	return cfg, sc, 0
}

// newCloud authenticates the live OpenStack client (credential
// resolution happens inside NewOpenStack).
func newCloud(ctx context.Context, cfg scenariotest.Config) (scenariotest.Cloud, error) {
	return scenariotest.NewOpenStack(ctx, cfg.OpenStack)
}
