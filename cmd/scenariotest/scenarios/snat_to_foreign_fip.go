package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/steps"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// snatNoiseBudget bounds the FIP side's infra growth over one drive:
// DHCP and metadata chatter is a few KiB, a stream whose SNAT peer
// classifies infra is the full driven MiBs.
const snatNoiseBudget = 256 << 10

// snatToForeignFIP is the live regression for lachesis#338: a client
// leaving through its router's SNAT reaches another tenant's FIP on
// the same external network. At the FIP side's tap the peer is the
// client router's gateway (network:router_gateway) address, which
// must bill external on that network in both directions, never infra.
//
// Every harness VM has a provider SSH FIP, and a VM with a FIP egresses
// from it, not through SNAT. So the client's subnet gets a second T1
// router (at a NON-gateway IP, as in multi-external-path) gatewayed on
// the same external network, and an in-guest /32 steers only the
// server's FIP through it: that router has no FIP for the client and
// SNATs it to its gateway address.
//
// docs/architecture/trie-construction.md#port-classification-device_owner
func snatToForeignFIP() *scenariotest.Scenario {
	const n = 4 << 20
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.70.0/24", "10.0.70.1").
		VM("vm-cli", "T1", "10.0.70.5")
	b.Network("net-T2", "T2").
		Subnet("sub-T2", "10.0.71.0/24", "10.0.71.1").
		VM("vm-srv", "T2", "10.0.71.5")
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").Attach("sub-T1", "10.0.70.1").ExternalGateway("net-ext")
	b.Router("r-T1-snat", "T1").Attach("sub-T1", "10.0.70.254").ExternalGateway("net-ext")
	b.Router("r-T2", "T2").Attach("sub-T2", "10.0.71.1").ExternalGateway("net-ext")

	return &scenariotest.Scenario{
		Name:    "snat-to-foreign-fip",
		Desc:    "A SNAT client and another tenant's FIP on one external network bill the FIP side external both ways (lachesis#338, step-scripted).",
		Builder: b,
		Steps: []scenariotest.Step{
			steps.AddRouteStep{VM: "vm-cli", FIPOf: "vm-srv", Via: "10.0.70.254"},

			steps.CaptureStep{},
			steps.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-cli", To: scenariotest.FIPTarget("vm-srv"), Bytes: n, Proto: scenariotest.TCP},
			}},
			steps.AssertStep{Note: "inbound from a foreign SNAT address bills external", Expect: []scenariotest.Expect{
				{TenantID: "T2", Zone: "external", Direction: "rx", MinBytes: n, ExternalNetwork: "net-ext"},
				{TenantID: "T2", Zone: "external", Direction: "rx", MinBytes: n, ExternalNetwork: "net-ext", VM: "vm-srv"},
			}},
			steps.MaxGrowthStep{Tenant: "T2", Zone: "infra", Budget: snatNoiseBudget,
				Note: "the router_gateway peer must not classify infra"},
			// Without this the stream could have left from the client's
			// own FIP, and the FIP side would bill external even with
			// the bug.
			steps.AssertFlowPeerStep{Router: "r-T1-snat", Via: "10.0.70.254", Zone: "external",
				MinBytes: n, Note: "client bytes rode the SNAT router"},

			steps.CaptureStep{},
			steps.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-cli", To: scenariotest.FIPTarget("vm-srv"), Bytes: n, Proto: scenariotest.TCP, Pull: true},
			}},
			steps.AssertStep{Note: "outbound to a foreign SNAT address bills external", Expect: []scenariotest.Expect{
				{TenantID: "T2", Zone: "external", Direction: "tx", MinBytes: n, ExternalNetwork: "net-ext"},
				{TenantID: "T2", Zone: "external", Direction: "tx", MinBytes: n, ExternalNetwork: "net-ext", VM: "vm-srv"},
			}},
			steps.MaxGrowthStep{Tenant: "T2", Zone: "infra", Budget: snatNoiseBudget,
				Note: "the download to the router_gateway peer must not classify infra"},
		},
	}
}
