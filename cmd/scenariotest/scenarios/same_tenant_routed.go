package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// sameTenantRouted exercises the routed leg of the same_tenant zone:
// one tenant, two subnets, joined by the tenant's own router — so the
// peer MAC at each tap is a router interface, not the other VM, and
// classification must resolve same_tenant through the hybrid lookup's
// router path rather than the direct L2 compare
// (docs/architecture/packet-classification.md#the-hybrid-lookup-explained,
// primer scenario B). twovms-same-tenant covers the L2-adjacent leg;
// without this scenario the routed leg — the one an off-by-one in the
// router handling would break — has no live regression.
func sameTenantRouted() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1a", "T1").
		Subnet("sub-T1a", "10.0.17.0/24", "10.0.17.1").
		VM("vm-a", "T1", "10.0.17.5")
	b.Network("net-T1b", "T1").
		Subnet("sub-T1b", "10.0.18.0/24", "10.0.18.1").
		VM("vm-b", "T1", "10.0.18.5")
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").
		Attach("sub-T1a", "10.0.17.1").
		Attach("sub-T1b", "10.0.18.1").
		ExternalGateway("net-ext")
	return &scenariotest.Scenario{
		Name:    "same-tenant-routed",
		Desc:    "One tenant, two subnets via its own router. Same-tenant zone, routed leg.",
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
