package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// multiHopChain exercises the resolver's iterative graph walk
// (docs/architecture/trie-construction.md#the-static-route-resolver)
// past the single-hop shape every other routed scenario uses: vm-a's
// route to T2's subnet crosses THREE routers — T1's, an admin transit
// router, T2's — so resolution requires following the intermediate
// router's own extraroute (Step D) before bottoming out on the
// destination owner. Classification must still be other_tenant at
// both ends.
func multiHopChain() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.26.0/24", "10.0.26.1").
		VM("vm-a", "T1", "10.0.26.5")
	b.Network("net-T2", "T2").
		Subnet("sub-T2", "10.0.27.0/24", "10.0.27.1").
		VM("vm-b", "T2", "10.0.27.5")
	// Separate transit networks so each inter-router leg is its own L2.
	b.SharedNetwork("net-transitA", "admin").
		Subnet("sub-transitA", "192.168.103.0/24", "192.168.103.1")
	b.SharedNetwork("net-transitB", "admin").
		Subnet("sub-transitB", "192.168.104.0/24", "192.168.104.1")
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-1", "T1").
		Attach("sub-T1", "10.0.26.1").
		Attach("sub-transitA", "192.168.103.10").
		ExtraRoute("10.0.27.0/24", "192.168.103.20").
		ExternalGateway("net-ext")
	b.Router("r-2", "admin").
		Attach("sub-transitA", "192.168.103.20").
		Attach("sub-transitB", "192.168.104.10").
		ExtraRoute("10.0.27.0/24", "192.168.104.20").
		ExtraRoute("10.0.26.0/24", "192.168.103.10")
	b.Router("r-3", "T2").
		Attach("sub-T2", "10.0.27.1").
		Attach("sub-transitB", "192.168.104.20").
		ExtraRoute("10.0.26.0/24", "192.168.104.10").
		ExternalGateway("net-ext")
	return &scenariotest.Scenario{
		Name:    "multi-hop-chain",
		Desc:    "A three-router static-route chain resolves other_tenant end to end.",
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
