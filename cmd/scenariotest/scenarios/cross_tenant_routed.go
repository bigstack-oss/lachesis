package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// crossTenantRouted exercises the other_tenant zone. T1 and T2 each
// own a subnet and a router; the routers meet on an admin transit
// subnet, and a static route on each carries traffic to the other
// tenant's CIDR (docs/architecture/trie-construction.md#the-five-step-algorithm Step 5, scenarios_test.go Scenario G).
// The cold-start resolver walks T1's static route to T2's router,
// finds T2 owns 10.50.0.0/24, and bakes (T1, 10.50.0.0/24) →
// OTHER_TENANT (and symmetrically for T2). So vm-a (T1) → vm-b (T2)
// classifies as other_tenant at both taps.
func crossTenantRouted() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.0.0/24", "10.0.0.1").
		VM("vm-a", "T1", "10.0.0.5")
	b.Network("net-T2", "T2").
		Subnet("sub-T2", "10.50.0.0/24", "10.50.0.1").
		VM("vm-b", "T2", "10.50.0.5")
	b.SharedNetwork("net-transit", "admin").
		Subnet("sub-transit", "192.168.100.0/24", "192.168.100.1")
	// Each router carries an external gateway for its own tenant's
	// floating-IP reachability (Neutron associates a FIP through the
	// gatewayed router on the VM's subnet); the asserted east-west
	// path still flows over the transit static routes.
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").
		Attach("sub-T1", "10.0.0.1").
		Attach("sub-transit", "192.168.100.10").
		ExtraRoute("10.50.0.0/24", "192.168.100.20").
		ExternalGateway("net-ext")
	b.Router("r-T2", "T2").
		Attach("sub-T2", "10.50.0.1").
		Attach("sub-transit", "192.168.100.20").
		ExtraRoute("10.0.0.0/24", "192.168.100.10").
		ExternalGateway("net-ext")
	return &scenariotest.Scenario{
		Name:    "cross-tenant-routed",
		Desc:    "Two tenants routed via a transit subnet. Other-tenant zone.",
		Builder: b,
		Flows: []scenariotest.Flow{
			{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP},
		},
		Expect: []scenariotest.Expect{
			{TenantID: "T1", Zone: "other_tenant", Direction: "tx", MinBytes: 1 << 20},
			{TenantID: "T2", Zone: "other_tenant", Direction: "rx", MinBytes: 1 << 20},
		},
	}
}
