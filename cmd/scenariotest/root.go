package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/bigstack-oss/lachesis/cmd/scenariotest/scenarios"
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/agentmetrics"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/openstack"
	"github.com/charmbracelet/lipgloss"
	charmlog "github.com/charmbracelet/log"
	"github.com/spf13/cobra"
)

// rootOptions carries the persistent flag values shared by the
// subcommands. Which of them a subcommand reads varies (list reads
// none); validation happens where the value is used.
type rootOptions struct {
	config string
	output string
	state  string
	report string
	debug  bool
	trace  bool
}

// logger builds the stderr logger every subcommand logs through:
// charmbracelet/log rendering (TTY-aware, NO_COLOR honored, plain text
// when piped) behind the stdlib slog API the internal packages accept.
// INFO and above by default; --debug adds the per-resource detail;
// --trace adds the wire tier (one line per API call / scrape / ssh).
func (o *rootOptions) logger() *slog.Logger {
	lvl := charmlog.InfoLevel
	switch {
	case o.trace:
		lvl = charmlog.Level(scenariotest.LevelTrace)
	case o.debug:
		lvl = charmlog.DebugLevel
	}
	h := charmlog.NewWithOptions(os.Stderr, charmlog.Options{
		Level:           lvl,
		ReportTimestamp: true,
	})
	styles := charmlog.DefaultStyles()
	styles.Levels[charmlog.Level(scenariotest.LevelTrace)] = lipgloss.NewStyle().
		SetString("TRCE").Bold(true).MaxWidth(4).Foreground(lipgloss.Color("245"))
	h.SetStyles(styles)
	return slog.New(h)
}

// newMetrics builds the agent-scrape source with the wire-trace
// transport installed; the lines only surface under --trace.
func newMetrics(log *slog.Logger) *agentmetrics.Client {
	return agentmetrics.New(&http.Client{
		Transport: scenariotest.NewTraceTransport(nil, log),
	})
}

func newRoot() *cobra.Command {
	opts := &rootOptions{}
	root := &cobra.Command{
		Use:   "scenariotest",
		Short: "Describe a topology, realize it on a live cluster, assert /metrics deltas.",
		// Errors and usage are printed by main / RunE so that exit
		// codes and the stdout/stderr split stay exactly as before.
		SilenceUsage:  true,
		SilenceErrors: true,
		// Unknown subcommands are rejected here (not cobra's default
		// legacyArgs) so they classify as usage errors → exit 2.
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				return nil
			}
			return usageError{fmt.Errorf("unknown subcommand %q", args[0])}
		},
		// Bare invocation: usage to stderr, exit 2 — as before.
		RunE: func(cmd *cobra.Command, _ []string) error {
			_ = cmd.Usage()
			return usageError{}
		},
	}
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return usageError{err}
	})

	pf := root.PersistentFlags()
	pf.StringVar(&opts.config, "config", "", "config file path (required for everything except list)")
	pf.StringVar(&opts.output, "output", "human", "preflight/assert/run output format: human|json")
	pf.StringVar(&opts.state, "state", "", "run-state file: written by up/run (default .scenariotest/<prefix>-<runid>.json), required by drive, assert, and down; an existing still-live file makes `run` resume against the kept topology (a torn-down one is overwritten)")
	pf.StringVar(&opts.report, "report", "", "assert/run report file (default <state>-report.json); survives down")
	pf.BoolVarP(&opts.debug, "debug", "v", false, "show debug-level progress detail (per-resource realize/teardown lines)")
	pf.BoolVar(&opts.trace, "trace", false, "show wire-level detail: one line per OpenStack API call, agent scrape, and VM ssh exec (implies --debug)")

	root.AddCommand(
		newListCmd(),
		newPreflightCmd(opts),
		newUpCmd(opts),
		newDriveCmd(opts),
		newAssertCmd(opts),
		newDownCmd(opts),
		newRunCmd(opts),
	)
	return root
}

// scenarioNameArg validates the single positional <scenario> argument
// every subcommand except list takes.
func scenarioNameArg(_ *cobra.Command, args []string) error {
	switch len(args) {
	case 0:
		return usageError{errors.New("missing scenario name")}
	case 1:
		return nil
	default:
		return usageError{fmt.Errorf("expected one scenario name, got %d", len(args))}
	}
}

// loadConfigAndScenario loads the config file and resolves the named
// scenario.
func loadConfigAndScenario(configPath, name string) (scenariotest.Config, *scenariotest.Scenario, error) {
	if configPath == "" {
		return scenariotest.Config{}, nil, usageError{errors.New("missing required --config")}
	}
	cfg, err := scenariotest.LoadConfig(configPath)
	if err != nil {
		return scenariotest.Config{}, nil, err
	}
	sc, err := scenarios.Get(name)
	if err != nil {
		return scenariotest.Config{}, nil, err
	}
	return cfg, sc, nil
}

// loadRunState loads the run-state file `up` wrote and checks it
// belongs to the named scenario. sub names the calling subcommand for
// error prefixes.
func loadRunState(statePath string, sc *scenariotest.Scenario, sub string) (*scenariotest.RunState, error) {
	if statePath == "" {
		return nil, usageError{errors.New("missing required --state (the file `up` wrote)")}
	}
	rs, err := scenariotest.LoadRunState(statePath)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", sub, err)
	}
	if rs.Scenario != sc.Name {
		return nil, fmt.Errorf("%s: run-state %s is for scenario %q, not %q", sub, statePath, rs.Scenario, sc.Name)
	}
	return rs, nil
}

// newCloud authenticates the live OpenStack client (credential
// resolution happens inside openstack.New).
func newCloud(ctx context.Context, cfg scenariotest.Config, log *slog.Logger) (scenariotest.Cloud, error) {
	return openstack.New(ctx, cfg.OpenStack, log)
}
