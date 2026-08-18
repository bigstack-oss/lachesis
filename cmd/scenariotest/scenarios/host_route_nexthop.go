package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/steps"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

const (
	// hostRouteDriveBytes is the transfer this scenario pushes.
	hostRouteDriveBytes = 1 << 20
	// hostRouteNoiseBudget bounds the external zone, which is where the
	// asserted bytes land if the MAC-first arm does NOT win.
	hostRouteNoiseBudget = 256 << 10
)

// hostRouteNexthop pins the MAC-first arm of the hybrid zone lookup
// (docs/architecture/packet-classification.md#the-hybrid-lookup-explained).
// A host route steers vm-a at an L2-adjacent VM, so the peer MAC and
// the destination IP disagree: the MAC arm answers same_tenant, while
// the trie would answer external for a prefix absent from the topology
// (docs/architecture/trie-construction.md#the-five-step-algorithm step 1).
// Asserting that one grew while the other stayed flat is what makes
// this shape discriminating where twovms-same-tenant is not.
//
//	vm-a (T1, .5) ──host route 10.0.82.0/24 via .50──> vm-nh (T1, .50)
//
// vm-nh only has to own a MAC and answer ARP for it: the drive is a
// sized-ping push at a dead address, so nothing needs to forward. The
// in-guest route stands in for a Neutron host_routes entry, and the rx
// side is deliberately unasserted — rationale in lachesis#302.
func hostRouteNexthop() *scenariotest.Scenario {
	const (
		dstCIDR    = "10.0.82.0/24"
		dstProbeIP = "10.0.82.5"
		nexthopIP  = "10.0.80.50"
	)
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.80.0/24", "10.0.80.1").
		VM("vm-a", "T1", "10.0.80.5").
		VM("vm-nh", "T1", nexthopIP)
	// Router + external gateway exist only so both VMs can hold an SSH
	// floating IP; the asserted hop never reaches the router.
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").
		Attach("sub-T1", "10.0.80.1").
		ExternalGateway("net-ext")

	return &scenariotest.Scenario{
		Name:    "host-route-nexthop",
		Desc:    "A host route at an L2-adjacent VM bills that peer's tenant, not the destination prefix's catchall.",
		Builder: b,
		Steps: []scenariotest.Step{
			steps.AddRouteStep{VM: "vm-a", CIDR: dstCIDR, Via: nexthopIP},

			steps.CaptureStep{},
			steps.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.ExternalTarget(dstProbeIP), Bytes: hostRouteDriveBytes, Proto: scenariotest.TCP},
			}},

			steps.AssertStep{Note: "the peer MAC decided the zone, not the destination prefix",
				Expect: []scenariotest.Expect{
					{TenantID: "T1", Zone: "same_tenant", Direction: "tx", MinBytes: hostRouteDriveBytes},
				}},
			// The counterfactual. This also catches a silently-failed
			// AddRouteStep: without the route the pings go to r-T1's MAC,
			// the trie resolves 10.0.82.5 to the catchall, and the bytes
			// land here instead.
			steps.MaxGrowthStep{Tenant: "T1", Zone: "external",
				Budget: hostRouteNoiseBudget, Note: "MAC-first arm won — not the trie catchall"},
		},
	}
}
