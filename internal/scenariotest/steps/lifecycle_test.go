package steps

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/fake"
)

func TestSteps_MigrateMovesAndRecords(t *testing.T) {
	env := &fake.Env{BaseAttached: 1}
	cloud := fake.NewCloud(env)
	cloud.Hyps = []string{"compute-0", "compute-1"}
	cloud.Hosts["srv-1"] = "compute-0"
	cfg := fake.Config()
	cfg.Cluster.Agents = append(cfg.Cluster.Agents, scenariotest.AgentConfig{Host: "compute-1", MetricsURL: "http://compute-1:9100/metrics"})
	statePath := t.TempDir() + "/state.json"
	rs := &scenariotest.RunState{RunID: "run1", Scenario: "x", Servers: []scenariotest.ResourceRef{{DSLID: "vm-a", ID: "srv-1", ProjectID: "p1"}}}
	senv := &scenariotest.StepEnv{Config: cfg, State: rs, StatePath: statePath, Cloud: cloud, Metrics: &fake.Metrics{Env: env}, Log: slog.New(slog.DiscardHandler)}

	step := MigrateStep{VM: "vm-a", Target: "node:1", Timeout: time.Second}
	if err := step.Run(context.Background(), senv); err != nil {
		t.Fatalf("MigrateStep: %v", err)
	}
	if got := cloud.Hosts["srv-1"]; got != "compute-1" {
		t.Errorf("server host = %q, want compute-1", got)
	}
	if len(rs.Migrations) != 1 || rs.Migrations[0] != (scenariotest.MigrationRecord{VM: "vm-a", From: "compute-0", To: "compute-1"}) {
		t.Errorf("migrations = %+v", rs.Migrations)
	}
	saved, err := scenariotest.LoadRunState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(saved.Migrations) != 1 {
		t.Errorf("migration not persisted: %+v", saved.Migrations)
	}
}

func TestSteps_MigrateErrors(t *testing.T) {
	env := &fake.Env{BaseAttached: 1}
	cloud := fake.NewCloud(env)
	cloud.Hyps = []string{"compute-0", "compute-1"}
	cloud.Hosts["srv-1"] = "compute-0"
	cfg := fake.Config()
	cfg.Cluster.Agents = append(cfg.Cluster.Agents, scenariotest.AgentConfig{Host: "compute-1", MetricsURL: "http://compute-1:9100/metrics"})
	rs := &scenariotest.RunState{RunID: "run1", Servers: []scenariotest.ResourceRef{{DSLID: "vm-a", ID: "srv-1", ProjectID: "p1"}}}
	senv := &scenariotest.StepEnv{Config: cfg, State: rs, StatePath: t.TempDir() + "/s.json", Cloud: cloud, Metrics: &fake.Metrics{Env: env}, Log: slog.New(slog.DiscardHandler)}

	for name, tc := range map[string]struct {
		step    MigrateStep
		wantErr string
	}{
		"unknown vm":        {MigrateStep{VM: "vm-x", Timeout: time.Second}, "no server for VM"},
		"target is current": {MigrateStep{VM: "vm-a", Target: "node:0", Timeout: time.Second}, "already on"},
		"bad slot":          {MigrateStep{VM: "vm-a", Target: "node:9", Timeout: time.Second}, "config lists 2 agent(s)"},
	} {
		t.Run(name, func(t *testing.T) {
			err := tc.step.Run(context.Background(), senv)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
	if len(rs.Migrations) != 0 {
		t.Errorf("failed steps must record nothing: %+v", rs.Migrations)
	}
}
