package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// vmToSubnetInfra drives the infra addresses inside the VM's own subnet:
// the router-interface gateway (.1) and the OVN distributed
// metadata/DHCP port (.2, the first address Neutron allocates after the
// gateway). Both are infra /32s inside the tenant's SAME_TENANT /24. The
// kernel reads tenant rows before global ones, so they bill infra only
// while the builder repeats the subnet's infra /32s under the tenant
// (docs/architecture/trie-construction.md#the-five-step-algorithm).
// [vmToGateway] cannot catch a regression here: its metadata target has
// no tenant row covering it.
//
// tx only: OVN answers echoes to both addresses itself and drops the
// driver's fragmented 60 KB ones, so no rx is generatable (the kernel
// test in internal/kernelwriter pins the return direction). The bound
// needs both targets in infra; either one leaking to same_tenant drops
// the delta below it, and it sits well above background infra (DHCP,
// metadata).
func vmToSubnetInfra() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.1.0/24", "10.0.1.1").
		VM("vm-a", "T1", "10.0.1.5")
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").
		Attach("sub-T1", "10.0.1.1").
		ExternalGateway("net-ext")
	return &scenariotest.Scenario{
		Name:    "vm-to-subnet-infra",
		Desc:    "VM pinging its own subnet's gateway and OVN metadata/DHCP port. Infra zone, not same_tenant.",
		Builder: b,
		Flows: []scenariotest.Flow{
			{From: "vm-a", To: scenariotest.ExternalTarget("10.0.1.1"), Bytes: 2 << 20, Proto: scenariotest.TCP},
			{From: "vm-a", To: scenariotest.ExternalTarget("10.0.1.2"), Bytes: 2 << 20, Proto: scenariotest.TCP},
		},
		Expect: []scenariotest.Expect{
			{TenantID: "T1", Zone: "infra", Direction: "tx", MinBytes: 3 << 20},
		},
	}
}
