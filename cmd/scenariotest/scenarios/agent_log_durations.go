package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/steps"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// agentLogDurations is the live regression for lachesis#325: slog's JSON
// handler renders a time.Duration as integer nanoseconds, so the
// agent's "serving" line read scrape_interval=10000000000. After a
// restart the new process's own line must carry a human duration.
//
// SKIPs when agent_control is unconfigured — environment, not defect.
func agentLogDurations() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.35.0/24", "10.0.35.1").
		VM("vm-a", "T1", "10.0.35.5")
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").
		Attach("sub-T1", "10.0.35.1").
		ExternalGateway("net-ext")

	return &scenariotest.Scenario{
		Name:      "agent-log-durations",
		Desc:      "The restarted agent logs durations as human strings, not integer nanoseconds (lachesis#325, step-scripted).",
		Builder:   b,
		Placement: scenariotest.Placement{"vm-a": "node:0"},
		Steps: []scenariotest.Step{
			steps.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.ExternalTarget("8.8.8.8"), Bytes: 64 << 10, Proto: scenariotest.TCP},
			}},
			steps.AssertStep{Note: "agent counting before the restart", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 64 << 10},
			}},
			steps.RestartAgentStep{Node: "node:0"},
			steps.AssertAgentLogStep{Node: "node:0", Msg: "serving", Attr: "scrape_interval", Want: "10s"},
		},
	}
}
