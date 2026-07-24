package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// extrarouteSameTenant exercises the resolver's SAME arm
// (docs/architecture/trie-construction.md#the-static-route-resolver):
// a tenant reaches its own second subnet through a transit hop, so the
// static-route trace bottoms out on a subnet the SOURCE tenant owns
// and must classify same_tenant — cross-tenant-routed covers only the
// OTHER arm. The tenant's own-subnet trie row resolves to the same
// zone, so the live failure this guards is precedence: a resolver bug
// that overwrote the pair with its fallback (external/other) would
// flip both assertions.
func extrarouteSameTenant() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1a", "T1").
		Subnet("sub-T1a", "10.0.24.0/24", "10.0.24.1").
		VM("vm-a", "T1", "10.0.24.5")
	b.Network("net-T1b", "T1").
		Subnet("sub-T1b", "10.0.25.0/24", "10.0.25.1").
		VM("vm-b", "T1", "10.0.25.5")
	b.SharedNetwork("net-transit", "admin").
		Subnet("sub-transit", "192.168.102.0/24", "192.168.102.1")
	b.ExternalNetwork("net-ext", "admin")
	// Two routers of the SAME tenant meet on the transit; each carries
	// a static route to the peer subnet — the same shape as
	// cross-tenant-routed with the ownership collapsed onto one tenant.
	b.Router("r-a", "T1").
		Attach("sub-T1a", "10.0.24.1").
		Attach("sub-transit", "192.168.102.10").
		ExtraRoute("10.0.25.0/24", "192.168.102.20").
		ExternalGateway("net-ext")
	b.Router("r-b", "T1").
		Attach("sub-T1b", "10.0.25.1").
		Attach("sub-transit", "192.168.102.20").
		ExtraRoute("10.0.24.0/24", "192.168.102.10").
		ExternalGateway("net-ext")
	return &scenariotest.Scenario{
		Name:    "extraroute-same-tenant",
		Desc:    "Static route to the tenant's own subnet resolves same_tenant, not other.",
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
