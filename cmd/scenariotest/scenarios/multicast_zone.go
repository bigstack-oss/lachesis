package scenarios

import (
	"time"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/steps"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// multicastNoiseBudget bounds what the billable zones may grow while
// the multicast drive runs. Background chatter (ARP/DHCP/neighbour
// plus the KiB-scale SSH exec sessions that ride the external zone
// via the FIP) is well under it; the driven MiB landing in a billable
// zone blows it.
const multicastNoiseBudget = 256 << 10

// multicastZone exercises the non-billable multicast zone: the BPF
// classifier's group-MAC branch (I/G bit set → multicast, checked
// BEFORE the trie; docs/architecture/packet-classification.md#the-zone-vocabulary). The VM
// pings the all-hosts group 224.0.0.1 — an IP-multicast destination
// maps algorithmically to a group MAC (01:00:5e:…), no ARP involved —
// and the frames must land in multicast/tx. The guarded regression:
// without the group-MAC branch these frames would miss every trie
// prefix and fall into the external catchall, silently billing
// broadcast noise as internet egress, so external (and the other
// billable zones) are bounded for the same window.
func multicastZone() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.15.0/24", "10.0.15.1").
		VM("vm-a", "T1", "10.0.15.5")
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").
		Attach("sub-T1", "10.0.15.1").
		ExternalGateway("net-ext")
	return &scenariotest.Scenario{
		Name:    "multicast-zone",
		Desc:    "Group-MAC traffic lands in the non-billable multicast zone.",
		Builder: b,
		Steps: []scenariotest.Step{
			steps.CaptureStep{},
			steps.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.ExternalTarget("224.0.0.1"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			steps.AssertStep{Note: "group-MAC frames bill multicast", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "multicast", Direction: "tx", MinBytes: 1 << 20},
			}},
			// One scrape interval so stragglers drain before the
			// bounded-growth reads.
			steps.SleepStep{Duration: 15 * time.Second},
			steps.MaxGrowthStep{Tenant: "T1", Zone: "external",
				Budget: multicastNoiseBudget, Note: "multicast must not fall into the external catchall"},
			steps.MaxGrowthStep{Tenant: "T1", Zone: "same_tenant",
				Budget: multicastNoiseBudget, Note: "multicast is not same_tenant"},
			steps.MaxGrowthStep{Tenant: "T1", Zone: "other_tenant",
				Budget: multicastNoiseBudget, Note: "multicast is not other_tenant"},
		},
	}
}
