package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// walRestartContinuity is the live regression for restart-safe billing
// (docs/architecture/boot-and-recovery.md): a driven VM's counters must
// survive an agent restart — the WAL restores GlobalState, the zombie
// hunter cleans and re-attaches the taps, and no series resets. It is
// the registered exercise for RestartAgentStep (lachesis#184).
//
// The restart is a warm one (WAL intact): the exposed series must stay
// monotone across it, and traffic driven afterwards must still accrue.
// The cold path (WAL destroyed → counters legitimately restart) is a
// separate scenario built on the same step (lachesis#234).
//
// SKIPs when agent_control is unconfigured — restarting an agent needs
// host SSH creds, a property of the environment, not a defect.
func walRestartContinuity() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.28.0/24", "10.0.28.1").
		VM("vm-a", "T1", "10.0.28.5").
		VM("vm-b", "T1", "10.0.28.6")
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").
		Attach("sub-T1", "10.0.28.1").
		ExternalGateway("net-ext")

	return &scenariotest.Scenario{
		Name:    "wal-restart-continuity",
		Desc:    "Restart the agent mid-run; WAL restores counters, taps re-attach, series stay monotone (lachesis#184/#185, step-scripted).",
		Builder: b,
		Steps: []scenariotest.Step{
			scenariotest.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			scenariotest.AssertStep{Note: "pre-restart drive", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "same_tenant", Direction: "tx", MinBytes: 1 << 20},
				{TenantID: "T1", Zone: "same_tenant", Direction: "rx", MinBytes: 1 << 20},
			}},

			// Warm restart: WAL intact. The agent re-reads it, the zombie
			// hunter re-attaches the taps, /metrics comes back.
			scenariotest.CaptureStep{},
			scenariotest.RestartAgentStep{},

			// No reset: the restored counters are at or above capture.
			scenariotest.MonotoneStep{Tenant: "T1", Note: "series monotone across agent restart"},

			// The re-attached taps still count new traffic.
			scenariotest.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			scenariotest.AssertStep{Note: "post-restart drive", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "same_tenant", Direction: "tx", VM: "vm-a", MinBytes: 1 << 20},
			}},
			scenariotest.MonotoneStep{Tenant: "T1", Note: "series intact at scenario end"},
		},
	}
}
