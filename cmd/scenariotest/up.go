package main

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/spf13/cobra"
)

func newUpCmd(opts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "up <scenario>",
		Short: "Realize topology and wait for the agents to attach.",
		Args:  scenarioNameArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, sc, err := loadConfigAndScenario(opts.config, args[0])
			if err != nil {
				return err
			}
			runID, err := scenariotest.NewRunID()
			if err != nil {
				return fmt.Errorf("up: %w", err)
			}
			state := opts.state
			if state == "" {
				state = scenariotest.DefaultStatePath(cfg.Naming.Prefix, runID)
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer stop()
			log := opts.logger()
			cloud, err := newCloud(ctx, cfg, log)
			if err != nil {
				return fmt.Errorf("up: %w", err)
			}

			rs, err := scenariotest.Realize(ctx, scenariotest.RealizeOptions{
				Config:    cfg,
				Scenario:  sc,
				RunID:     runID,
				StatePath: state,
				Cloud:     cloud,
				Metrics:   newMetrics(log),
				Log:       log,
			})
			if err != nil {
				if rs != nil {
					log.Warn("partial run-state written; run `down` to clean up", "state", state)
				}
				return fmt.Errorf("up: %w", err)
			}
			fmt.Printf("up ok: scenario=%s run-id=%s vms=%d fips=%d state=%s\n",
				sc.Name, runID, len(rs.Servers), len(rs.FIPs), state)
			return nil
		},
	}
}
