package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
)

// maxHopsExceeded: one hop past the resolver's limit must fall back to
// external (internal/neutron/resolve.go's MAX_HOPS warn path) — the
// outside face of the boundary max-hops-at-limit pins from within.
//
// This is also the pair's proof that `neutron.max_static_route_hops`
// really reached the resolver: the chain is [resolverMaxHops]+1 long,
// which the stock 16-hop default would resolve happily as other_tenant.
// Seeing external here means the retuned limit took effect.
//
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
		// The knob is per-agent, so the billing agent must be the one
		// retuned: pin vm-a to the node whose config the steps edit.
		Placement: scenariotest.Placement{"vm-a": "node:0"},
		Steps:     maxHopsSteps("10.0.30.5", "external"),
	}
}
