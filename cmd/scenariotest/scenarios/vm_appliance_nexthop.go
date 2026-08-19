package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/steps"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

const (
	// applianceDriveBytes is the transfer this scenario pushes.
	applianceDriveBytes = 1 << 20
	// applianceNoiseBudget bounds the zones this scenario asserts traffic
	// did NOT land in.
	applianceNoiseBudget = 256 << 10
	// applianceForwardedFloor is the floor for the SECOND count, at the
	// appliance's tap. Deliberately looser than the source-side floor:
	// that tap sees payload plus headers, this one sees whatever
	// survived an extra hop, which can lose leading fragments while ARP
	// warms up. Live pass-through was 98%, so two thirds is slack, not a
	// fudge — this row is a presence test, and the double-count either
	// happens at roughly the transfer size or not at all.
	applianceForwardedFloor = applianceDriveBytes * 2 / 3
)

// vmApplianceNexthop exercises the resolver's Step B compute-nexthop
// case: an extraroute whose nexthop is a VM port classifies by that
// appliance's port — the trace STOPS there — and the same bytes bill
// again at the appliance's own tap when it forwards them.
//
// The zone is `shared`, not `other_tenant`, because zone_for tests
// Shared above the owner comparison. `other_tenant` is unreachable on
// this path: it needs a non-shared network whose owner differs, and a
// cross-tenant appliance can only meet T1's router on a shared one.
//
// Without Step B the peer type is unknown and the row falls to the
// `external` catchall, so `shared` present + `external` flat proves the
// appliance path fired. The appliance forwards back out the SAME NIC:
// only that one has port security off, and a forwarded packet keeps the
// original source IP.
//
// docs/architecture/edge-cases.md#tier-4--subtle-correctness
func vmApplianceNexthop() *scenariotest.Scenario {
	const dstCIDR = "10.0.62.0/24"
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.60.0/24", "10.0.60.1").
		VM("vm-a", "T1", "10.0.60.5")
	// The appliance boots in its own T2 network: it needs an SSH FIP to
	// be configured, and its boot NIC must stay clear of the forwarding
	// path (port security stays on there).
	b.Network("net-appl", "T2").
		Subnet("sub-appl", "10.0.61.0/24", "10.0.61.1").
		VM("vm-appl", "T2", "10.0.61.5")
	b.SharedNetwork("net-transit", "admin").
		Subnet("sub-transit", "192.168.120.0/24", "192.168.120.1")
	// The destination network beyond the appliance. No VM needed — the
	// bytes that matter are counted on vm-a's and the appliance's taps,
	// and an unanswered destination is exactly the "opaque beyond the
	// appliance" case the resolver models.
	b.Network("net-T2", "T2").
		Subnet("sub-T2", dstCIDR, "10.0.62.1")
	b.ExternalNetwork("net-ext", "admin")

	b.Router("r-T1", "T1").
		Attach("sub-T1", "10.0.60.1").
		Attach("sub-transit", "192.168.120.10").
		ExtraRoute(dstCIDR, "192.168.120.50"). // the appliance's transit IP
		ExternalGateway("net-ext")
	// Gives the appliance its SSH FIP path.
	b.Router("r-appl", "T2").
		Attach("sub-appl", "10.0.61.1").
		ExternalGateway("net-ext")
	// The appliance's own next hop onward to the destination subnet.
	b.Router("r-T2", "T2").
		Attach("sub-transit", "192.168.120.20").
		Attach("sub-T2", "10.0.62.1")

	return &scenariotest.Scenario{
		Name:    "vm-appliance-nexthop",
		Desc:    "A compute:* extraroute nexthop bills the appliance's shared segment, and again at its own tap.",
		Builder: b,
		Steps: []scenariotest.Step{
			// The forwarding NIC: port security OFF so the appliance may
			// receive traffic addressed past it and re-emit it with vm-a's
			// source IP intact.
			steps.AttachPortStep{VM: "vm-appl", ID: "vm-appl-transit",
				Network: "net-transit", Subnet: "sub-transit", IP: "192.168.120.50",
				PortSecurityOff: true},
			steps.ConfigureNICStep{VM: "vm-appl", Dev: "eth1", CIDR: "192.168.120.50/24"},
			steps.EnableForwardingStep{VM: "vm-appl"},
			// Steer the forwarded traffic at r-T2 rather than the
			// appliance's default gateway, so it leaves by the transit NIC.
			steps.AddRouteStep{VM: "vm-appl", CIDR: dstCIDR, Via: "192.168.120.20"},

			steps.CaptureStep{},
			steps.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.ExternalTarget("10.0.62.5"), Bytes: applianceDriveBytes, Proto: scenariotest.TCP},
			}},

			// Source side: the appliance nexthop resolved, and resolved to
			// the shared transit it was met on.
			steps.AssertStep{Note: "compute nexthop resolves to the appliance's shared segment",
				Expect: []scenariotest.Expect{
					{TenantID: "T1", Zone: "shared", Direction: "tx", MinBytes: applianceDriveBytes},
				}},
			// ...and NOT to the catchall, which is what an unhandled peer
			// device type would have produced.
			steps.MaxGrowthStep{Tenant: "T1", Zone: "external",
				Budget: applianceNoiseBudget, Note: "Step B fired — not the external catchall"},

			// The documented double-count: the appliance's own tap bills the
			// forwarded egress. Its peer there is r-T2 (a router MAC, so the
			// trie decides) and the destination is T2's own subnet, so the
			// appliance's tenant sees the same bytes as same_tenant/tx.
			steps.ZoneGrowthStep{Tenant: "T2", Zone: "same_tenant", Direction: "tx",
				MinBytes: applianceForwardedFloor,
				Note:     "case 21 double-count: the same bytes billed again at the appliance's tap"},
		},
	}
}
