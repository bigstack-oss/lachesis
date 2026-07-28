// Package steps is the step vocabulary a scripted scenario is written
// in: an ordered program the run executes between up and down, able to
// express the mid-run lifecycle events the classic drive-all/assert-all
// loop cannot — deleting a VM, waiting out the agent's ghost sweep,
// rebooting a MAC under another tenant, restarting an agent cold.
//
// A step is one type implementing [scenariotest.Step], grouped into
// files by what it acts on: traffic.go drives and captures, lifecycle.go
// boots/deletes/migrates servers, port.go hot-plugs NICs, network.go
// mutates Neutron, agent.go drives the agent host, and the two assert_*
// files hold the assertions — billing-facing and agent-internal.
// Adding a step is one new type in the right file; the executor never
// changes.
package steps

import (
	"time"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
)

const (
	// DefaultSweepTimeout bounds [AwaitSweepStep]. The agent-side
	// pipeline is reconcile notice (Kafka kick, or the 5-minute
	// periodic pass as the ceiling) → 60s ghost grace → 60s sweep
	// tick, so the default must comfortably cover the no-Kafka worst
	// case.
	DefaultSweepTimeout = 8 * time.Minute
	// DefaultPortSeriesTimeout bounds [PortSeriesStep]'s stabilize poll —
	// generously above one scrape interval so a drive's bytes have
	// drained before the row is declared failing.
	DefaultPortSeriesTimeout = 60 * time.Second
	// agentReadyPollInterval is the pause between readiness scrapes.
	agentReadyPollInterval = 2 * time.Second
	// configRestoreTimeout bounds the end-of-run sweep that puts back
	// agent configs a run left modified ([scenariotest.StepEnv.restoreDirtyConfigs]).
	// One restore is a file copy plus a unit restart, so this covers a
	// couple of nodes without letting a wedged host hang the exit.
	configRestoreTimeout = 3 * time.Minute
)

// --- the vocabulary ---

const (
	// DefaultAnomalyTimeout bounds [AssertAnomalyStep]'s poll. The
	// gauge updates when a reconcile pass commits — Kafka-kicked
	// within seconds of the triggering resource event, with the
	// 5-minute periodic pass as the no-Kafka ceiling.
	DefaultAnomalyTimeout = 8 * time.Minute
	// anomalyPollInterval is the pause between AssertAnomalyStep
	// scrapes.
	anomalyPollInterval = 5 * time.Second
)

// Migration timing: live migrations on the target clusters complete
// in well under a minute; five bounds a stuck migration without
// hanging an unattended run.
const (
	DefaultMigrateTimeout = 5 * time.Minute
	migratePollInterval   = 3 * time.Second
)

// Default is the classic linear loop as a script: drive every declared
// flow, assert every declared expectation. A scenario that declares no
// Steps of its own runs this.
func Default(sc *scenariotest.Scenario) []scenariotest.Step {
	return []scenariotest.Step{
		DriveStep{Flows: sc.Flows},
		AssertStep{Expect: sc.Expect},
	}
}

// RequiredMetrics collects the /metrics families a script's steps
// declare through [scenariotest.MetricRequirer], deduplicated. `run`
// checks them against every agent before creating anything, so a
// scenario fails on an under-featured agent before any topology exists.
func RequiredMetrics(steps []scenariotest.Step) []string {
	seen := map[string]bool{}
	var out []string
	for _, st := range steps {
		r, ok := st.(scenariotest.MetricRequirer)
		if !ok {
			continue
		}
		for _, m := range r.RequiredMetrics() {
			if !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	return out
}
