package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/signal"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/realize"
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
			if err := refuseLiveState(state); err != nil {
				return err
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer stop()
			log := opts.logger()
			cloud, err := newCloud(ctx, cfg, log)
			if err != nil {
				return fmt.Errorf("up: %w", err)
			}

			rs, err := realize.Run(ctx, realize.Options{
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

// refuseLiveState guards `up` against overwriting a run-state that
// still records a live topology: down only ever deletes exact
// recorded IDs, so clobbering the file orphans those resources. A
// torn-down file is a completed run's leftover and fine to overwrite;
// any read error other than not-exist surfaces rather than being
// treated as a green light.
func refuseLiveState(state string) error {
	rs, err := scenariotest.LoadRunState(state)
	switch {
	case err == nil && !rs.TornDown:
		return fmt.Errorf("up: run-state %s records a live topology (run %s, scenario %s) — run `down` first, or delete the file", state, rs.RunID, rs.Scenario)
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("up: %w", err)
	}
	return nil
}
