package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// twoVMsSameTenant is the baseline closing the loop end to end:
// realize → drive → scrape → assert. Two VMs, one project, one subnet,
// one TCP stream. Both are T1, so the tenant totals must carry A's send
// and B's receive.
//
// Placement is left to the scheduler; on a multi-node cluster this row
// only means something when both VMs land on one hypervisor.
//
// The router and gateway exist purely for FIP reachability — Neutron
// requires them to associate one. The asserted traffic is L2-adjacent,
// so they do not affect the classification.
func twoVMsSameTenant() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.1.0/24", "10.0.1.1").
		VM("vm-a", "T1", "10.0.1.5").
		VM("vm-b", "T1", "10.0.1.6")
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").
		Attach("sub-T1", "10.0.1.1").
		ExternalGateway("net-ext")
	return &scenariotest.Scenario{
		Name:    "twovms-same-tenant",
		Desc:    "Two VMs, same tenant, same subnet. Baseline that closes the loop.",
		Builder: b,
		Flows: []scenariotest.Flow{
			{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP},
		},
		Expect: []scenariotest.Expect{
			{TenantID: "T1", Zone: "same_tenant", Direction: "tx", MinBytes: 1 << 20},
			{TenantID: "T1", Zone: "same_tenant", Direction: "rx", MinBytes: 1 << 20},
		},
	}
}
