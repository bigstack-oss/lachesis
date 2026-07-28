package scenarios

import (
	"fmt"
	"strings"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/steps"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// resolverMaxHops is the hop limit the two max-hops scenarios IMPOSE
// on the agent under test via the hot `neutron.max_static_route_hops`
// knob — deliberately small, not the 16 default.
//
// Why not probe the default: a 16-hop boundary needs a ~17-router
// chain per scenario, which only fits under raised Neutron
// router/subnet/network/port quotas. Retuning the limit makes these
// explicit boundary tests (the harness picks the boundary and builds a
// chain sized to it) instead of mirrors of a compile-time constant,
// and keeps them inside default quotas.
const resolverMaxHops = 4

// maxHopsSteps brackets a max-hops probe with the agent-side knob
// change: back up node:0's config while shortening its reconcile so the
// hot change lands promptly, retune the hop limit with a SIGHUP (no
// restart — the knob is hot), let one reconcile rebuild the trie at the
// new limit, then drive and assert, and finally restore the config.
//
// The restart is what creates the config backup [steps.ReloadAgentStep]
// deliberately does not take, so the final RestoreConfig is the way home.
func maxHopsSteps(dstIP, zone string) []scenariotest.Step {
	return []scenariotest.Step{
		steps.RestartAgentStep{Node: "node:0", SetConfig: map[string]string{
			"reconcile.interval": "15s",
		}},
		// HOT: retune resolver depth without cycling the process. The
		// reload also kicks the reconciler, so the re-resolve is seconds
		// away rather than a full interval.
		steps.ReloadAgentStep{Node: "node:0", SetConfig: map[string]string{
			"neutron.max_static_route_hops": fmt.Sprint(resolverMaxHops),
		}},
		steps.SleepStep{Duration: reconcileSettle},
		steps.DriveStep{Flows: []scenariotest.Flow{
			{From: "vm-a", To: scenariotest.ExternalTarget(dstIP), Bytes: 1 << 20, Proto: scenariotest.TCP},
		}},
		steps.AssertStep{Expect: []scenariotest.Expect{
			{TenantID: "T1", Zone: zone, Direction: "tx", MinBytes: 1 << 20},
		}},
		steps.RestartAgentStep{Node: "node:0", RestoreConfig: true},
	}
}

// chainedRouteTopology builds the boundary probe: vm-a behind r-0,
// then `hops` intermediate routers r-1…r-N daisy-chained over per-leg
// transit subnets (one shared admin network), with dstCIDR — owned by
// tenant "T2" — attached on the LAST router. Resolving vm-a's route to
// dstCIDR consumes exactly `hops` nexthop follows, so with the agent
// limited to [resolverMaxHops] a chain of that length still resolves
// other_tenant and one more falls back to external. Transit CIDRs live
// in 172.30.<i>.0/24 to stay clear of every other scenario.
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
// external fallback — pinning the `for hop < ri.maxHops` semantics
// against reality from the inside. The limit is imposed at run time
// (see [resolverMaxHops]) and the chain is built to match it.
func maxHopsAtLimit() *scenariotest.Scenario {
	const dstCIDR = "10.0.29.0/24"
	return &scenariotest.Scenario{
		Name:    "max-hops-at-limit",
		Desc:    "A static-route chain at exactly MAX_HOPS still resolves other_tenant.",
		Builder: chainedRouteTopology(resolverMaxHops, dstCIDR),
		// The knob is per-agent, so the billing agent must be the one
		// retuned: pin vm-a to the node whose config the steps edit.
		Placement: scenariotest.Placement{"vm-a": "node:0"},
		Steps:     maxHopsSteps("10.0.29.5", "other_tenant"),
	}
}
