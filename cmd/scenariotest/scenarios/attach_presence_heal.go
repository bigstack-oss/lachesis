package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/steps"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// attachPresenceHeal proves the agent's attach-presence sweep
// (docs/architecture/boot-and-recovery.md#attach-presence-resync): a
// driven VM's tap loses its telemetry filters behind the agent's back —
// the clsact qdisc deleted out-of-band, which no link event reports —
// and the agent's next sweep re-attaches them, so bytes driven
// afterwards bill on that tap again.
//
// Both VMs are pinned to node:0, so the stripped tap and the asserting
// agent are the same host on any cluster size.
func attachPresenceHeal() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.43.0/24", "10.0.43.1").
		VM("vm-a", "T1", "10.0.43.5").
		VM("vm-b", "T1", "10.0.43.6")
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").
		Attach("sub-T1", "10.0.43.1").
		ExternalGateway("net-ext")
	return &scenariotest.Scenario{
		Name:    "attach-presence-heal",
		Desc:    "Strip a driven VM tap's TC filters out-of-band; the agent's sweep re-attaches them and billing resumes (step-scripted).",
		Builder: b,
		Placement: scenariotest.Placement{
			"vm-a": "node:0",
			"vm-b": "node:0",
		},
		Steps: []scenariotest.Step{
			steps.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			steps.AssertStep{Note: "pre-strip drive", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "same_tenant", Direction: "tx", VM: "vm-a", Node: "node:0", MinBytes: 1 << 20},
			}},

			// Remove the filters with no link event, then wait for the
			// sweep to put them back.
			steps.CaptureStep{},
			steps.StripTCStep{VM: "vm-a", Node: "node:0"},
			steps.ReattachHealedStep{Min: 1, Note: "sweep re-attached the stripped tap"},

			// Bytes driven after the heal bill on vm-a's tap again.
			steps.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			steps.AssertStep{Note: "post-heal drive", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "same_tenant", Direction: "tx", VM: "vm-a", Node: "node:0", MinBytes: 1 << 20},
			}},
			steps.MonotoneStep{Tenant: "T1", Note: "series intact across the strip and heal"},
		},
	}
}
