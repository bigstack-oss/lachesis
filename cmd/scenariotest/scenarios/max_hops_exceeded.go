package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
)

// maxHopsExceeded: one hop past the resolver's limit must fall back to
// external (internal/neutron/resolve.go's MAX_HOPS warn path) — the
// outside face of the boundary max-hops-at-limit pins from within.
// Today the fallback is invisible on /metrics; this scenario is the
// live-validation vehicle for the deferred
// lachesis_neutron_static_route_fallback_total{reason} counter
// (docs/architecture/contracts.md#deferred-work), per the
// validate-before-billing-changes rule.
func maxHopsExceeded() *scenariotest.Scenario {
	const dstCIDR = "10.0.30.0/24"
	return &scenariotest.Scenario{
		Name:    "max-hops-exceeded",
		Desc:    "One hop past MAX_HOPS falls back to external.",
		Builder: chainedRouteTopology(resolverMaxHops+1, dstCIDR),
		Flows: []scenariotest.Flow{
			{From: "vm-a", To: scenariotest.ExternalTarget("10.0.30.5"), Bytes: 1 << 20, Proto: scenariotest.TCP},
		},
		Expect: []scenariotest.Expect{
			{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 1 << 20},
		},
	}
}
