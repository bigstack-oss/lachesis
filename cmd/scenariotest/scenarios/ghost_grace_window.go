package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/steps"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// ghostGraceWindow exercises the INSIDE-grace half of the Lingering
// Ghost lifecycle (Contract 6): for the grace window after a port is
// deleted its MAC stays in mac_tenant_map, so dying FIN/RST packets
// still attribute. mac-reuse covers the after-sweep side.
//
// vm-a keeps sending to the deleted vm-b's fixed IP — its ARP entry
// still resolves the lingering MAC — and those tx bytes must bill the
// tenant with no unknown growth.
//
// Needs a GhostGrace longer than the delete + drive.
//
// docs/architecture/data-structures.md#map-lifecycle-invariants
func ghostGraceWindow() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.50.0/24", "10.0.50.1").
		VM("vm-a", "T1", "10.0.50.5").
		VM("vm-b", "T1", "10.0.50.6")
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").
		Attach("sub-T1", "10.0.50.1").
		ExternalGateway("net-ext")
	return &scenariotest.Scenario{
		Name:    "ghost-grace-window",
		Desc:    "Dying packets inside the 60s lingering-ghost grace still attribute.",
		Builder: b,
		// Pin both VMs to one node so the whole flow — and the lingering
		// ghost — lives on a single agent whose grace we control.
		Placement: scenariotest.Placement{"vm-a": "node:0", "vm-b": "node:0"},
		Steps: []scenariotest.Step{
			// Warm the flow so vm-a learns vm-b's MAC into its ARP cache and
			// the agent attributes the pair to T1.
			steps.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			steps.AssertStep{Note: "warm-up attributes to the tenant", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "same_tenant", Direction: "tx", MinBytes: 1 << 20},
			}},

			steps.CaptureStep{},
			// Delete vm-b. Its MAC leaves Neutron but LINGERS in the kernel
			// map for the grace window (DeleteVMStep records the MAC).
			steps.DeleteVMStep{VM: "vm-b"},
			// vm-a keeps transmitting to vm-b's fixed IP — its ARP entry
			// still resolves vm-b's MAC, so the frames egress vm-a's tap
			// keyed on the lingering MAC. Inside the grace this must still
			// attribute to T1. (vm-b is gone, so nothing replies; the tx
			// count is what the grace protects.)
			steps.DriveStep{SkipAttachRecheck: true, Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.ExternalTarget("10.0.50.6"), Bytes: 2 << 20, Proto: scenariotest.TCP},
			}},

			// The dying-flow tx still bills the tenant inside the grace
			// (measured against the grace drive's own baseline)...
			steps.AssertStep{Note: "in-grace tx still attributes to the tenant", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "same_tenant", Direction: "tx", MinBytes: 64 << 10},
			}},
			// ...and none of it leaked to unknown (growth since the capture
			// taken before the delete).
			steps.MaxGrowthStep{Tenant: "unknown", Zone: "same_tenant",
				Budget: 64 << 10, Note: "no unknown growth inside the grace"},
			steps.MaxGrowthStep{Tenant: "unknown", Zone: "miss",
				Budget: 64 << 10, Note: "no miss growth inside the grace"},
		},
	}
}
