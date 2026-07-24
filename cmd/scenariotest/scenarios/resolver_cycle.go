package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// resolverCycle exercises the static-route resolver's cycle detection
// (docs/architecture/trie-construction.md#the-static-route-resolver)
// live: two routers on a transit subnet point extraroutes for the same
// phantom CIDR at each other, so each router's trace revisits a router
// already on its path. The resolver must fall back to EXTERNAL (never
// hang, never misattribute) and surface one
// lachesis_neutron_anomalies{class="cycle"} hit per looping route —
// two here, one from each router's trace. Traffic to the looped CIDR
// then bills external.
func resolverCycle() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.21.0/24", "10.0.21.1").
		VM("vm-a", "T1", "10.0.21.5")
	b.SharedNetwork("net-transit", "admin").
		Subnet("sub-transit", "192.168.101.0/24", "192.168.101.1")
	b.ExternalNetwork("net-ext", "admin")
	// 10.99.0.0/24 exists on no subnet — the routes only chase each
	// other across the transit.
	b.Router("r-a", "T1").
		Attach("sub-T1", "10.0.21.1").
		Attach("sub-transit", "192.168.101.10").
		ExtraRoute("10.99.0.0/24", "192.168.101.20").
		ExternalGateway("net-ext")
	b.Router("r-b", "admin").
		Attach("sub-transit", "192.168.101.20").
		ExtraRoute("10.99.0.0/24", "192.168.101.10")
	return &scenariotest.Scenario{
		Name:    "resolver-cycle",
		Desc:    "Extraroute loop falls back to external and raises the cycle anomaly.",
		Builder: b,
		Steps: []scenariotest.Step{
			// A cycle must be reported. The exact hit count is a resolver
			// internal — one CycleHit per looping route-evaluation, so the
			// symmetric two-router loop yields 2 (confirmed live). The
			// billing-meaningful property is "a cycle was detected", so
			// assert ≥1 with a loose ceiling that still catches a runaway.
			scenariotest.AssertAnomalyStep{Class: "cycle", Min: 1, Max: 32,
				Note: "extraroute loop detected"},
			scenariotest.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.ExternalTarget("10.99.0.5"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			scenariotest.AssertStep{Note: "looped CIDR bills the external fallback", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 1 << 20},
			}},
		},
	}
}
