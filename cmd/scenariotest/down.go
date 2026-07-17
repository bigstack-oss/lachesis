package main

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/spf13/cobra"
)

func newDownCmd(opts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "down <scenario>",
		Short: "Tear down everything in the run-state (idempotent).",
		Long: `Tear down everything in the run-state (idempotent; projects and
report/run-state files are never touched).`,
		Args: scenarioNameArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, sc, err := loadConfigAndScenario(opts.config, args[0])
			if err != nil {
				return err
			}
			rs, err := loadRunState(opts.state, sc, "down")
			if err != nil {
				return err
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer stop()
			log := opts.logger()
			cloud, err := newCloud(ctx, cfg, log)
			if err != nil {
				return fmt.Errorf("down: %w", err)
			}
			if err := scenariotest.Down(ctx, scenariotest.DownOptions{
				Config:    cfg,
				State:     rs,
				StatePath: opts.state,
				Cloud:     cloud,
				Log:       log,
			}); err != nil {
				return fmt.Errorf("down: %w", err)
			}
			fmt.Printf("down ok: scenario=%s run-id=%s (projects kept; state and report files kept)\n", sc.Name, rs.RunID)
			return nil
		},
	}
}
