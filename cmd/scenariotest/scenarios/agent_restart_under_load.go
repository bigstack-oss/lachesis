package scenarios

import (
	"time"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/steps"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// agentRestartUnderLoad is the live regression for lachesis#334: an
// agent restart while a transfer is in flight must not lose the bytes
// that cross the restart and the agent's boot. The other restart
// scenarios drive before and after the restart, never during, so they
// pass on a build whose boot strips the taps it is about to re-attach.
//
// Each leg paces one VM-to-VM stream over about 40 seconds and cycles
// the agent 15 seconds in, so the stream spans the restart, the boot
// and some 25 seconds after it. The whole stream lands inside one
// drive baseline, so MinBytes = the stream is the loss check. Leg 1 is
// a systemctl restart; leg 2 is a kill -9 that the unit's Restart=
// brings back.
//
// SKIPs when agent_control is unconfigured — environment, not defect.
func agentRestartUnderLoad() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.35.0/24", "10.0.35.1").
		VM("vm-a", "T1", "10.0.35.5").
		VM("vm-b", "T1", "10.0.35.6")
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").
		Attach("sub-T1", "10.0.35.1").
		ExternalGateway("net-ext")

	const (
		paceMiB     = 32
		chunks      = 40
		streamBytes = chunks * paceMiB << 20
		restartAt   = 15 * time.Second
	)
	leg := func(note string, restart steps.RestartAgentStep) []scenariotest.Step {
		return []scenariotest.Step{
			steps.CaptureStep{},
			steps.DriveStep{
				Flows: []scenariotest.Flow{
					{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: streamBytes, Proto: scenariotest.TCP},
				},
				PaceMiB:     paceMiB,
				During:      []scenariotest.Step{restart},
				DuringAfter: restartAt,
			},
			steps.AssertStep{Note: note, Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "same_tenant", Direction: "tx", VM: "vm-a", MinBytes: streamBytes},
				{TenantID: "T1", Zone: "same_tenant", Direction: "rx", VM: "vm-b", MinBytes: streamBytes},
			}},
			steps.MonotoneStep{Tenant: "T1", Note: note + ": series monotone"},
		}
	}

	return &scenariotest.Scenario{
		Name:    "agent-restart-under-load",
		Desc:    "Restart, then kill -9, the agent mid-transfer; no in-flight bytes are lost across the boot (lachesis#334, step-scripted).",
		Builder: b,
		// Both VMs ride the cycled agent's node, so both taps cross its boot.
		Placement: scenariotest.Placement{
			"vm-a": "node:0",
			"vm-b": "node:0",
		},
		Steps: append(
			leg("restart under load", steps.RestartAgentStep{Node: "node:0"}),
			leg("kill -9 under load", steps.RestartAgentStep{Node: "node:0", Kill: true})...,
		),
	}
}
