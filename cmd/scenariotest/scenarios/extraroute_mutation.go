package scenarios

import (
	"time"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/steps"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// reconcileSettle is a pause long enough for a Neutron topology change
// (route or gateway) to reach the agents and rebuild the trie: Kafka
// kicks the reconciler within seconds, with the periodic pass as the
// ceiling. Sized above the c36 30s reconcile interval.
const reconcileSettle = 60 * time.Second

// extrarouteMutation exercises the trie's insert-then-delete route
// update: vm-a and vm-b start with no cross-tenant route, so the flow
// falls to the external catchall; the harness then adds the transit
// routes and the same flow must classify other_tenant.
//
// Scope: traffic is driven before and after the reconcile, never
// concurrently with the rebuild, so this proves the post-rebuild steady
// state rather than the atomicity of the swap — a sub-second transient
// is out of reach at this tier. The miss max-growth check is the proxy
// for "the swap left no lasting MISS".
//
// docs/architecture/trie-construction.md
func extrarouteMutation() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.40.0/24", "10.0.40.1").
		VM("vm-a", "T1", "10.0.40.5")
	b.Network("net-T2", "T2").
		Subnet("sub-T2", "10.0.41.0/24", "10.0.41.1").
		VM("vm-b", "T2", "10.0.41.5")
	b.SharedNetwork("net-transit", "admin").
		Subnet("sub-transit", "192.168.110.0/24", "192.168.110.1")
	b.ExternalNetwork("net-ext", "admin")
	// No ExtraRoute yet — added live by SetRouterRoutesStep.
	b.Router("r-T1", "T1").
		Attach("sub-T1", "10.0.40.1").
		Attach("sub-transit", "192.168.110.10").
		ExternalGateway("net-ext")
	b.Router("r-T2", "T2").
		Attach("sub-T2", "10.0.41.1").
		Attach("sub-transit", "192.168.110.20").
		ExternalGateway("net-ext")
	return &scenariotest.Scenario{
		Name:    "extraroute-mutation",
		Desc:    "Live route change reclassifies new traffic with no MISS blip.",
		Builder: b,
		Steps: []scenariotest.Step{
			steps.CaptureStep{},
			// Before the route exists, vm-a's default route sends the packet
			// to r-T1, which has no path to 10.0.41.0/24 and SNATs it out —
			// external catchall. (The peer never replies; tx is what counts.)
			steps.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.ExternalTarget("10.0.41.5"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			steps.AssertStep{Note: "pre-route: external catchall", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 1 << 20},
			}},

			// Add the transit routes on both routers, live.
			steps.SetRouterRoutesStep{Router: "r-T1", Routes: []scenariotest.RouteSpec{
				{Destination: "10.0.41.0/24", Nexthop: "192.168.110.20"},
			}},
			steps.SetRouterRoutesStep{Router: "r-T2", Routes: []scenariotest.RouteSpec{
				{Destination: "10.0.40.0/24", Nexthop: "192.168.110.10"},
			}},
			steps.SleepStep{Duration: reconcileSettle},

			// Same flow, now routed: the rebuilt trie resolves other_tenant.
			steps.CaptureStep{},
			steps.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			steps.AssertStep{Note: "post-route: zone flipped to other_tenant", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "other_tenant", Direction: "tx", MinBytes: 1 << 20},
			}},
			// The insert-then-delete trie update must open no MISS window:
			// unknown/miss did not absorb the flow during the swap.
			steps.MaxGrowthStep{Tenant: "unknown", Zone: "miss",
				Budget: 256 << 10, Note: "no MISS blip across the route change"},
		},
	}
}
