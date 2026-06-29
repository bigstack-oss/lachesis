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

	"github.com/bigstack-oss/cube-cos-network-telemetry/cmd/scenariotest/scenarios"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/scenariotest"
)

const usage = `scenariotest — describe a topology, realize it on a live cluster, assert /metrics deltas.

Usage:
  scenariotest <subcommand> [flags]

Subcommands:
  list                  Show registered scenarios.
  preflight <name>      Check cluster readiness (read-only).
  up        <name>      Realize topology and wait for the agents to attach.
  drive     <name>      Push declared flows (not yet implemented).
  assert    <name>      Scrape + compare deltas (not yet implemented).
  run       <name>      preflight → up → drive → assert → down (not yet implemented).
  down                  Tear down (not yet implemented).

Common flags:
  -config <path>        Config file path. Required for everything except list.
  -output <human|json>  preflight output format (default human).
  -state  <path>        up run-state file (default .scenariotest/<prefix>-<runid>.json).
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
	case "drive", "assert", "run", "down":
		fmt.Fprintf(os.Stderr, "scenariotest %s: not implemented yet\n", sub)
		os.Exit(2)
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
	fmt.Fprintln(tw, "NAME\tFLOWS\tEXPECT\tPLACEMENT\tDESC")
	for _, s := range all {
		placement := "(scheduler)"
		if len(s.Placement) > 0 {
			placement = fmt.Sprintf("%d pinned", len(s.Placement))
		}
		fmt.Fprintf(tw, "%s\t%d\t%d\t%s\t%s\n", s.Name, len(s.Flows), len(s.Expect), placement, s.Desc)
	}
	tw.Flush()
	return 0
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

// newCloud resolves credentials and authenticates the live OpenStack
// client.
func newCloud(ctx context.Context, cfg scenariotest.Config) (scenariotest.Cloud, error) {
	creds, err := cfg.OpenStack.ResolveCredentials()
	if err != nil {
		return nil, err
	}
	return scenariotest.NewOpenStack(ctx, creds)
}
