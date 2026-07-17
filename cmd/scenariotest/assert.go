package main

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/spf13/cobra"
)

func newAssertCmd(opts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "assert <scenario>",
		Short: "Evaluate MinBytes expectations against /metrics deltas; write the report.",
		Args:  scenarioNameArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, sc, err := loadConfigAndScenario(opts.config, args[0])
			if err != nil {
				return err
			}
			rs, err := loadRunState(opts.state, sc, "assert")
			if err != nil {
				return err
			}
			report := opts.report
			if report == "" {
				report = scenariotest.DefaultReportPath(opts.state)
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer stop()
			log := opts.logger()
			res, err := scenariotest.Assert(ctx, scenariotest.AssertOptions{
				Config:     cfg,
				Scenario:   sc,
				State:      rs,
				ReportPath: report,
				Metrics:    newMetrics(log),
				Log:        log,
			})
			if err != nil {
				return fmt.Errorf("assert: %w", err)
			}
			if err := emitAssert(os.Stdout, opts.output, res); err != nil {
				return err
			}
			if !res.OK {
				return errFailed
			}
			return nil
		},
	}
}
