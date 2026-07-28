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
	// appliance's own tap. It is deliberately looser than the source-side
	// floor, because the two measure different things: vm-a's tap sees the
	// drive payload PLUS Ethernet/IP headers, so it always reads above
	// applianceDriveBytes, while the appliance's tap sees a DERIVED
	// quantity — whatever survived one extra hop, which can lose the
	// leading fragments while ARP and routes warm up.
	//
	// Live on c36 the pass-through was 98% (1,084,710 forwarded of
	// 1,106,460 counted at the source), so two thirds is generous slack,
	// not a fudge. Generous is right: this row is a presence test — the
	// double-count either happens at roughly the transfer size or not at
	// all (0, as it read before rp_filter was handled). Byte accuracy is
	// the byte-accuracy-bounds scenario's job, not this one's.
	applianceForwardedFloor = applianceDriveBytes * 2 / 3
)

// vmApplianceNexthop exercises the static-route resolver's Step B
// compute-nexthop case (docs/architecture/trie-construction.md#the-static-route-resolver):
// an extraroute whose nexthop is a VM port (`device_owner compute:*`)
// classifies by that appliance's port — the trace STOPS there, because
// what lies beyond the appliance is opaque to Neutron — and the same
// bytes are billed a second time at the appliance's own tap when it
// forwards them (docs/architecture/edge-cases.md#tier-4--subtle-correctness case 21).
//
// # The zone this asserts, and why it is not other_tenant
//
// `zone_for` tests `network.Shared` ABOVE the owner comparison, so the
// zone here is `shared`, not `other_tenant`. That is deliberate: it is
// the canonical honest-label rule (trie-construction.md step 3 — "the
// same ordering governs zone_for in step 5's resolver"), which exists
// because the LPM trie cannot resolve per-VM ownership inside a shared
// subnet and guessing SAME/OTHER would systematically mis-bill one
// direction. `other_tenant` is in fact unreachable on this path: it
// needs a non-shared network whose owner differs from the source
// tenant, and a cross-tenant appliance can only meet T1's router on a
// shared one.
//
// Worth knowing, since the rationale above does not quite fit this
// case: ownership is NOT ambiguous at a compute nexthop — the resolver
// holds the port's exact ProjectID. `shared` here is a consistency
// choice (one shared segment bills one way, whoever the peer is)
// rather than one forced by missing information.
//
// The assertion still discriminates: without Step B's compute branch
// the peer device type is unknown and the row falls to the `external`
// catchall, so `shared` present + `external` flat proves the appliance
// path fired.
//
// # Shape
//
// vm-a (T1) sends to a CIDR only reachable through the appliance:
//
//	vm-a ──> r-T1 ──(extraroute 10.0.62.0/24 via .50)──> vm-appl (T2, .50 on the
//	                                                     shared transit)
//	                                                        │ forwards
//	                                                        ▼
//	                                              r-T2 (.20) ──> sub-T2
//
// The appliance forwards back out the SAME transit NIC it received on.
// That is deliberate: only that NIC is hot-plugged with port security
// off, and a forwarded packet keeps vm-a's source IP, which OVN
// anti-spoofing would drop on any port still enforcing it. Routing it
// out the boot NIC instead would need a port-security-off boot port,
// which the DSL cannot express.
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
