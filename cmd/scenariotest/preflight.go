package main

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/spf13/cobra"
)

func newPreflightCmd(opts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "preflight <scenario>",
		Short: "Check cluster readiness (read-only).",
		Args:  scenarioNameArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, sc, err := loadConfigAndScenario(opts.config, args[0])
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer stop()
			cloud, err := newCloud(ctx, cfg)
			if err != nil {
				return fmt.Errorf("preflight: %w", err)
			}
			report := scenariotest.Preflight(ctx, cfg, sc, cloud, scenariotest.NewHTTPMetrics(nil))
			if err := report.Emit(os.Stdout, opts.output); err != nil {
				return fmt.Errorf("preflight: %w", err)
			}
			if !report.OK {
				return errFailed
			}
			return nil
		},
	}
}
