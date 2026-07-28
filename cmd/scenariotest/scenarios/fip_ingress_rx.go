package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/steps"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// fipIngressRx exercises the one zone/direction pair no other scenario
// asserts: external/rx — and with it the directional swap
// (docs/architecture/packet-classification.md#the-directional-swap-explained):
// a large inbound transfer must key vm_mac from the RECEIVING side and
// the remote address from the sender, or the download miskeys off the
// VM's own subnet. The harness itself is the outside-the-cluster
// sender: [steps.IngressFlowStep] streams the byte budget into
// the VM through its floating IP (DNAT path), so at the tap the peer
// is the harness's provider-net address — no tenant prefix matches and
// the bytes must bill external/rx.
func fipIngressRx() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.16.0/24", "10.0.16.1").
		VM("vm-a", "T1", "10.0.16.5")
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").
		Attach("sub-T1", "10.0.16.1").
		ExternalGateway("net-ext")
	return &scenariotest.Scenario{
		Name:    "fip-ingress-rx",
		Desc:    "Inbound internet traffic via FIP bills external/rx.",
		Builder: b,
		Steps: []scenariotest.Step{
			steps.IngressFlowStep{To: "vm-a", Bytes: 4 << 20},
			steps.AssertStep{Note: "FIP ingress bills external/rx", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "external", Direction: "rx", MinBytes: 4 << 20},
			}},
		},
	}
}
