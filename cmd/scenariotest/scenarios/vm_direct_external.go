package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// vmDirectExternal is the live regression for a VM whose only NIC sits
// directly on the provider external network: no router, no FIP, so
// neither the router-MAC nor the FIP/gateway-IP tier attributes it.
// Its egress must still bill under that network's ID, never under
// "none" (lachesis#339, docs/architecture/billing.md).
//
// The VM takes its address from the provider subnet's DHCP, and the
// harness host reaches it on that fixed IP rather than through a FIP.
func vmDirectExternal() *scenariotest.Scenario {
	b := scenario.New()
	b.ExternalNetwork("net-ext", "admin").DHCPVM("vm-a", "T1")
	return &scenariotest.Scenario{
		Name:    "vm-direct-external",
		Desc:    "VM directly on the provider external network, no FIP. External zone labelled with that network.",
		Builder: b,
		Flows: []scenariotest.Flow{
			{From: "vm-a", To: scenariotest.ExternalTarget("8.8.8.8"), Bytes: 1 << 20, Proto: scenariotest.TCP},
		},
		Expect: []scenariotest.Expect{
			{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 1 << 20,
				ExternalNetwork: "net-ext"},
			{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 1 << 20,
				ExternalNetwork: "net-ext", VM: "vm-a"},
			// The pre-fix label: the driven bytes must not land here.
			{TenantID: "T1", Zone: "external", Direction: "tx", MaxBytes: 64 << 10,
				ExternalNetwork: "none", VM: "vm-a"},
		},
	}
}
