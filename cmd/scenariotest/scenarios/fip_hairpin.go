package scenarios

import (
	"time"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/steps"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// hairpinNoiseBudget bounds same_tenant growth over the hairpin drive:
// ARP/DHCP/neighbour chatter between the two subnet-adjacent VMs is a
// few KiB, a hairpin stream misclassified as same_tenant is the full
// driven MiB.
const hairpinNoiseBudget = 256 << 10

// fipHairpin pins the OVN hairpin-SNAT posture
// (docs/architecture/edge-cases.md#tier-3--misclassification case 14c):
// a VM addressing a same-tenant, same-subnet peer through the peer's
// FLOATING IP must bill external at both taps — OVN DNATs the target
// and SNATs the source to an external-net address, so neither side
// sees a tenant address — and must NOT bill same_tenant, even though
// both VMs sit L2-adjacent. [scenariotest.FIPTarget] makes the stream
// dial the peer's FIP instead of its fixed IP.
func fipHairpin() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.19.0/24", "10.0.19.1").
		VM("vm-a", "T1", "10.0.19.5").
		VM("vm-b", "T1", "10.0.19.6")
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").
		Attach("sub-T1", "10.0.19.1").
		ExternalGateway("net-ext")
	return &scenariotest.Scenario{
		Name:    "fip-hairpin",
		Desc:    "Same-tenant peer addressed via its FIP bills external on both taps.",
		Builder: b,
		Steps: []scenariotest.Step{
			steps.CaptureStep{},
			steps.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.FIPTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			steps.AssertStep{Note: "hairpin bills external both ways", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 1 << 20},
				{TenantID: "T1", Zone: "external", Direction: "rx", MinBytes: 1 << 20},
			}},
			steps.SleepStep{Duration: 15 * time.Second},
			steps.MaxGrowthStep{Tenant: "T1", Zone: "same_tenant",
				Budget: hairpinNoiseBudget, Note: "hairpin must not classify as same_tenant"},
		},
	}
}
