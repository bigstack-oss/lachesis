package main

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/spf13/cobra"
)

func newDriveCmd(opts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "drive <scenario>",
		Short: "Re-check the attach gate, snapshot the metrics baseline, push declared flows.",
		Args:  scenarioNameArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, sc, err := loadConfigAndScenario(opts.config, args[0])
			if err != nil {
				return err
			}
			rs, err := loadRunState(opts.state, sc, "drive")
			if err != nil {
				return err
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer stop()
			log := opts.logger()
			err = scenariotest.Drive(ctx, scenariotest.DriveOptions{
				Config:    cfg,
				Scenario:  sc,
				State:     rs,
				StatePath: opts.state,
				Metrics:   newMetrics(log),
				Exec:      scenariotest.NewSSHExec(cfg.SSH, log),
				Log:       log,
			})
			if err != nil {
				return fmt.Errorf("drive: %w", err)
			}
			fmt.Printf("drive ok: scenario=%s flows=%d state=%s\n", sc.Name, len(sc.Flows), opts.state)
			return nil
		},
	}
}
