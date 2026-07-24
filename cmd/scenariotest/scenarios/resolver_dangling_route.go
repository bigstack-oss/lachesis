package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// resolverDanglingRoute exercises the dangling-extraroute anomaly
// (docs/architecture/trie-construction.md#the-static-route-resolver):
// an extraroute whose nexthop is an address inside an attached subnet
// but carried by NO port — Neutron accepts it (the nexthop only has to
// be on a connected subnet), yet the resolver's Step B finds no device
// there and must fall back to EXTERNAL, and the snapshot health check
// must surface lachesis_neutron_anomalies{class="dangling_route"}.
func resolverDanglingRoute() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.22.0/24", "10.0.22.1").
		VM("vm-a", "T1", "10.0.22.5")
	b.ExternalNetwork("net-ext", "admin")
	// .99 is inside sub-T1 but no port sits there: a black-hole nexthop.
	b.Router("r-T1", "T1").
		Attach("sub-T1", "10.0.22.1").
		ExtraRoute("10.98.0.0/24", "10.0.22.99").
		ExternalGateway("net-ext")
	return &scenariotest.Scenario{
		Name:    "resolver-dangling-route",
		Desc:    "Off-port nexthop raises the dangling_route anomaly; bytes fall back to external.",
		Builder: b,
		Steps: []scenariotest.Step{
			scenariotest.AssertAnomalyStep{Class: "dangling_route", Min: 1, Max: 1,
				Note: "the black-hole nexthop is reported"},
			scenariotest.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.ExternalTarget("10.98.0.5"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			scenariotest.AssertStep{Note: "dangling-routed CIDR bills the external fallback", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 1 << 20},
			}},
		},
	}
}
