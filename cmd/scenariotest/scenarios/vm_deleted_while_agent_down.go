package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/steps"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// vmDeletedWhileAgentDown is the live regression for owner-preserving
// restore (lachesis#317): a VM deleted while its node's agent is
// stopped must keep its history on its tenant. The agent never sees the
// delete, so no ghost or sweep folds it; only the WAL's recorded owner
// and the boot-time fold can.
//
// docs/architecture/data-structures.md#settled-bytes
func vmDeletedWhileAgentDown() *scenariotest.Scenario {
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
		Name:    "vm-deleted-while-agent-down",
		Desc:    "Delete a VM while its node's agent is stopped; its bytes stay on its tenant across the restart (lachesis#317, step-scripted).",
		Builder: b,
		// Both VMs ride the stopped agent's node, so vm-b's rows live
		// on the agent that misses its delete.
		Placement: scenariotest.Placement{
			"vm-a": "node:0",
			"vm-b": "node:0",
		},
		Steps: []scenariotest.Step{
			steps.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			steps.AssertStep{Note: "pre-outage drive", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "same_tenant", Direction: "rx", VM: "vm-b", MinBytes: 1 << 20},
			}},

			steps.CaptureStep{},
			steps.RestartAgentStep{Node: "node:0",
				Down:              []scenariotest.Step{steps.DeleteVMStep{VM: "vm-b"}},
				TapsGoneWhileDown: 1},

			// vm-b's history is still T1's, not re-bucketed to unknown.
			steps.MonotoneStep{Tenant: "T1", Note: "tenant series monotone across the outage"},
			steps.MaxGrowthStep{Tenant: "unknown", Zone: "same_tenant", Budget: 256 << 10,
				Note: "deleted VM's history did not re-bucket to unknown"},
		},
	}
}
