package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// crossTenantShared exercises the shared zone. vm-a (T1) sits on its
// own subnet; vm-b (T2) sits on an admin-owned shared network. T1's
// router routes vm-a's traffic onto the shared subnet. Because the hop
// is L3 (the peer MAC is the router, not vm-b), the classifier falls
// back to the LPM trie, which carries one global ("", 10.10.0.0/24) →
// SHARED row for the shared subnet (docs/architecture/trie-construction.md#the-five-step-algorithm Step 3,
// scenarios_test.go Scenario C). So vm-a → vm-b classifies as shared.
//
// This is the subtlest zone to drive deterministically (it depends on
// the routed, not L2-adjacent, path); the precise drive/assert lands
// with those slices.
func crossTenantShared() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.1.0/24", "10.0.1.1").
		VM("vm-a", "T1", "10.0.1.5")
	b.SharedNetwork("net-shared", "admin").
		Subnet("sub-shared", "10.10.0.0/24", "10.10.0.1").
		VM("vm-b", "T2", "10.10.0.5")
	// T1's router bridges T1's subnet and the shared subnet, so vm-a
	// reaches the shared subnet over L3. It sits on sub-shared's
	// declared gateway (10.10.0.1) so vm-b's DHCP default route points
	// at a live interface — attaching anywhere else leaves the gateway
	// unbound and vm-b's replies to vm-a die. The external gateway is
	// for floating-IP reachability on both subnets.
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").
		Attach("sub-T1", "10.0.1.1").
		Attach("sub-shared", "10.10.0.1").
		ExternalGateway("net-ext")
	return &scenariotest.Scenario{
		Name:    "cross-tenant-shared",
		Desc:    "VM routed onto an admin shared subnet. Shared zone.",
		Builder: b,
		Flows: []scenariotest.Flow{
			{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP},
		},
		Expect: []scenariotest.Expect{
			{TenantID: "T1", Zone: "shared", Direction: "tx", MinBytes: 1 << 20},
		},
	}
}
