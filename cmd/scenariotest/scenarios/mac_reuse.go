package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// rebornNoiseBudget separates background chatter from mis-attributed
// history in the bounded-growth checks: ARP/DHCP/neighbour noise over
// the reuse window is a few KiB, an inherited or re-bucketed flow is
// the full driven MiB+. 256 KiB clears both margins comfortably.
const rebornNoiseBudget = 256 << 10

// macReuse is the live regression for the ghost-sweep settled-bytes
// fold (docs/architecture/data-structures.md#settled-bytes) and its hardest consequence, MAC reuse: tenant A
// drives traffic and its VM is deleted; after the agent's ghost sweep,
// tenant A's series must hold — monotone, nothing re-bucketed to
// "unknown" — and when the VM's MAC is reborn on tenant B's port,
// B must inherit nothing and A must lose nothing.
//
// It is a step-scripted scenario: vm-d is declared in the topology but
// Deferred (not booted by `up`), and the Steps list runs the phases the
// classic linear loop cannot express. A plain `run mac-reuse` executes
// the whole script.
func macReuse() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.7.0/24", "10.0.7.1").
		VM("vm-a", "T1", "10.0.7.5").
		VM("vm-b", "T1", "10.0.7.6")
	b.Network("net-T2", "T2").
		Subnet("sub-T2", "10.0.8.0/24", "10.0.8.1").
		VM("vm-c", "T2", "10.0.8.5").
		VM("vm-d", "T2", "10.0.8.6") // deferred: born mid-script with vm-a's MAC
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").Attach("sub-T1", "10.0.7.1").ExternalGateway("net-ext")
	b.Router("r-T2", "T2").Attach("sub-T2", "10.0.8.1").ExternalGateway("net-ext")

	return &scenariotest.Scenario{
		Name:     "mac-reuse",
		Desc:     "Ghost-sweep + MAC-reuse billing regression (step-scripted).",
		Builder:  b,
		Deferred: []string{"vm-d"},
		Steps: []scenariotest.Step{
			// Tenant A's traffic attributes normally.
			scenariotest.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			scenariotest.AssertStep{Note: "tenant A drive", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "same_tenant", Direction: "tx", MinBytes: 1 << 20},
				{TenantID: "T1", Zone: "same_tenant", Direction: "rx", MinBytes: 1 << 20},
			}},

			// Delete the VM and let the agent's ghost sweep fold it.
			scenariotest.CaptureStep{},
			scenariotest.DeleteVMStep{VM: "vm-a"},
			scenariotest.AwaitSweepStep{},

			// Contract 7, live: the sweep moved nothing off the books.
			scenariotest.MonotoneStep{Tenant: "T1", Note: "monotone across ghost sweep"},
			scenariotest.MaxGrowthStep{Tenant: "unknown", Zone: "same_tenant",
				Budget: rebornNoiseBudget, Note: "no re-bucket to unknown"},

			// The MAC comes back on the other tenant's port — clean.
			scenariotest.BootVMStep{VM: "vm-d", MACFrom: "vm-a"},
			scenariotest.MaxGrowthStep{Tenant: "T2", Zone: "same_tenant",
				Budget: rebornNoiseBudget, Note: "reborn MAC starts from zero"},

			// Tenant B's own traffic attributes normally, and tenant
			// A's series still holds.
			scenariotest.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-d", To: scenariotest.VMTarget("vm-c"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			scenariotest.AssertStep{Note: "tenant B drive", Expect: []scenariotest.Expect{
				{TenantID: "T2", Zone: "same_tenant", Direction: "tx", MinBytes: 1 << 20},
				{TenantID: "T2", Zone: "same_tenant", Direction: "rx", MinBytes: 1 << 20},
			}},
			scenariotest.MonotoneStep{Tenant: "T1", Note: "old tenant unchanged after reuse"},
		},
	}
}
