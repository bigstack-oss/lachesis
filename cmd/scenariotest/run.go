package main

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/spf13/cobra"
)

func newRunCmd(opts *rootOptions) *cobra.Command {
	var keep bool
	cmd := &cobra.Command{
		Use:   "run <scenario>",
		Short: "preflight → up → the scenario's steps → down, one command.",
		Long: `preflight → up → the scenario's steps → down, one command. --keep skips down.
Plain scenarios run drive → assert; step-scripted scenarios (e.g. mac-reuse)
run their declared step list — deleting VMs mid-run, awaiting the agent's
ghost sweep, booting a deferred VM with a captured MAC, and so on.`,
		Args: scenarioNameArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, sc, err := loadConfigAndScenario(opts.config, args[0])
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

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer stop()
			cloud, err := newCloud(ctx, cfg)
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
				Metrics:    scenariotest.NewHTTPMetrics(nil),
				Exec:       scenariotest.NewSSHExec(cfg.SSH),
				Log:        os.Stderr,
				Keep:       keep,
			})
			if err != nil {
				return fmt.Errorf("run: %w", err)
			}
			if err := res.Emit(os.Stdout, opts.output); err != nil {
				return fmt.Errorf("run: %w", err)
			}
			fmt.Printf("report: %s\n", report)
			if !res.OK {
				return errFailed
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&keep, "keep", false, "leave the topology up after assert")
	return cmd
}
