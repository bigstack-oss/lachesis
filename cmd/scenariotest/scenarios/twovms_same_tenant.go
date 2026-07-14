package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// twoVMsSameTenant is the baseline that closes the scenariotest loop
// end to end: realize → drive → scrape → assert. Two VMs in one
// project on one subnet; a single TCP stream from A to B. The bytes
// must increment for {T1, same_tenant, tx} (A sending) and
// {T1, same_tenant, rx} (B receiving) — both VMs are T1, so the
// per-tenant totals carry A's send and B's receive.
//
// Placement is left empty so the scheduler decides — on single-node
// dev-cmp that is the only host; on multi-node clusters this is only
// meaningful when both VMs land on the same hypervisor (a Placement
// pin, added once the baseline passes).
//
// The router + external gateway exist purely for floating-IP
// reachability: Neutron only associates a FIP when a router with a
// gateway on the external network also has an interface on the VM's
// subnet. The asserted traffic is L2-adjacent (MAC-classified), so
// the router does not change the same_tenant classification.
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
