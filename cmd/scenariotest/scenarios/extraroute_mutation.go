package scenarios

import (
	"time"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// reconcileSettle is a pause long enough for a Neutron topology change
// (route or gateway) to reach the agents and rebuild the trie: Kafka
// kicks the reconciler within seconds, with the periodic pass as the
// ceiling. Sized above the c36 30s reconcile interval.
const reconcileSettle = 60 * time.Second

// extrarouteMutation exercises the trie's insert-then-delete route
// update (docs/architecture/trie-construction.md): a live extraroute
// change must reclassify NEW traffic to the routed zone. vm-a (T1) and
// vm-b (T2) meet over a transit subnet with NO cross-tenant route
// initially, so vm-a→vm-b's CIDR falls to the external catchall.
// Mid-run the harness adds the transit routes via the Neutron API;
// after the agents reconcile, the same flow must classify
// other_tenant, and the post-route drive must not spill into MISS.
//
// Scope note: traffic is driven BEFORE and AFTER the reconcile, not
// concurrently with the trie rebuild, so this proves the post-rebuild
// steady state (routed, not miss) rather than the atomicity of the
// insert-then-delete swap itself — a sub-second transient window is
// out of reach at the live-cluster tier. The miss max-growth check is
// the steady-state proxy for "the swap left no lasting MISS".
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
			scenariotest.CaptureStep{},
			// Before the route exists, vm-a's default route sends the packet
			// to r-T1, which has no path to 10.0.41.0/24 and SNATs it out —
			// external catchall. (The peer never replies; tx is what counts.)
			scenariotest.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.ExternalTarget("10.0.41.5"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			scenariotest.AssertStep{Note: "pre-route: external catchall", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 1 << 20},
			}},

			// Add the transit routes on both routers, live.
			scenariotest.SetRouterRoutesStep{Router: "r-T1", Routes: []scenariotest.RouteSpec{
				{Destination: "10.0.41.0/24", Nexthop: "192.168.110.20"},
			}},
			scenariotest.SetRouterRoutesStep{Router: "r-T2", Routes: []scenariotest.RouteSpec{
				{Destination: "10.0.40.0/24", Nexthop: "192.168.110.10"},
			}},
			scenariotest.SleepStep{Duration: reconcileSettle},

			// Same flow, now routed: the rebuilt trie resolves other_tenant.
			scenariotest.CaptureStep{},
			scenariotest.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			scenariotest.AssertStep{Note: "post-route: zone flipped to other_tenant", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "other_tenant", Direction: "tx", MinBytes: 1 << 20},
			}},
			// The insert-then-delete trie update must open no MISS window:
			// unknown/miss did not absorb the flow during the swap.
			scenariotest.MaxGrowthStep{Tenant: "unknown", Zone: "miss",
				Budget: 256 << 10, Note: "no MISS blip across the route change"},
		},
	}
}
