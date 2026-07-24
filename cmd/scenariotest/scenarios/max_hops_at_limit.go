package scenarios

import (
	"fmt"
	"strings"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// resolverMaxHops mirrors internal/neutron's maxStaticRouteHops (16):
// the resolver follows at most this many router-interface nexthops per
// route. The two max-hops scenarios pin the boundary from both sides
// against the live resolver — an off-by-one encoded identically in
// code and unit test would only surface here.
const resolverMaxHops = 16

// chainedRouteTopology builds the boundary probe: vm-a behind r-0,
// then `hops` intermediate routers r-1…r-N daisy-chained over per-leg
// transit subnets (one shared admin network), with dstCIDR — owned by
// tenant "T2" — attached on the LAST router. Resolving vm-a's route to
// dstCIDR consumes exactly `hops` nexthop follows, so hops =
// [resolverMaxHops] still resolves other_tenant and one more falls
// back to external. Transit CIDRs live in 172.30.<i>.0/24 to stay
// clear of every other scenario.
func chainedRouteTopology(hops int, dstCIDR string) *scenario.Builder {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-src", "10.0.28.0/24", "10.0.28.1").
		VM("vm-a", "T1", "10.0.28.5")
	transit := b.SharedNetwork("net-transit", "admin")
	for i := 1; i <= hops; i++ {
		transit.Subnet(fmt.Sprintf("t%d", i), fmt.Sprintf("172.30.%d.0/24", i), fmt.Sprintf("172.30.%d.1", i))
	}
	b.Network("net-T2", "T2").
		Subnet("sub-dst", dstCIDR, gatewayOf(dstCIDR))
	b.ExternalNetwork("net-ext", "admin")

	b.Router("r-0", "T1").
		Attach("sub-src", "10.0.28.1").
		Attach("t1", "172.30.1.10").
		ExtraRoute(dstCIDR, "172.30.1.20").
		ExternalGateway("net-ext")
	for i := 1; i < hops; i++ {
		b.Router(fmt.Sprintf("r-%d", i), "admin").
			Attach(fmt.Sprintf("t%d", i), fmt.Sprintf("172.30.%d.20", i)).
			Attach(fmt.Sprintf("t%d", i+1), fmt.Sprintf("172.30.%d.10", i+1)).
			ExtraRoute(dstCIDR, fmt.Sprintf("172.30.%d.20", i+1))
	}
	b.Router(fmt.Sprintf("r-%d", hops), "T2").
		Attach(fmt.Sprintf("t%d", hops), fmt.Sprintf("172.30.%d.20", hops)).
		Attach("sub-dst", gatewayOf(dstCIDR))
	return b
}

// gatewayOf returns the .1 gateway of a ".0/24" CIDR — the only shape
// the chain topologies use.
func gatewayOf(cidr string) string {
	return strings.TrimSuffix(cidr, "0/24") + "1"
}

// maxHopsAtLimit: a chain at exactly the resolver's hop limit must
// still resolve to the true owner's zone (other_tenant), NOT the
// external fallback — pinning the `for hop < maxStaticRouteHops`
// semantics against reality from the inside.
func maxHopsAtLimit() *scenariotest.Scenario {
	const dstCIDR = "10.0.29.0/24"
	return &scenariotest.Scenario{
		Name:    "max-hops-at-limit",
		Desc:    "A static-route chain at exactly MAX_HOPS still resolves other_tenant.",
		Builder: chainedRouteTopology(resolverMaxHops, dstCIDR),
		Flows: []scenariotest.Flow{
			{From: "vm-a", To: scenariotest.ExternalTarget("10.0.29.5"), Bytes: 1 << 20, Proto: scenariotest.TCP},
		},
		Expect: []scenariotest.Expect{
			{TenantID: "T1", Zone: "other_tenant", Direction: "tx", MinBytes: 1 << 20},
		},
	}
}
