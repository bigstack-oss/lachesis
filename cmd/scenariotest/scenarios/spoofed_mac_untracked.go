package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// spoofedMACUntracked pins the classifier's L2 trust boundary
// (docs/architecture/edge-cases.md#tier-3--misclassification case 10): frames sourced from a MAC
// Neutron never allocated must land in the unknown/miss bucket and
// bill no real tenant. It is also the first scenario to drive the miss
// zone deliberately.
//
// Shape: vm-a (T1) hot-plugs a second NIC with port security OFF onto
// an admin shared subnet, forges that NIC's MAC in-guest, and pings
// vm-b (T2) across the shared L2. The forged tx must accrue to
// unknown/miss; T1's own tuples on the shared subnet must stay at
// noise level (its only legitimate MAC there never transmits). vm-b's
// echo replies belong to T2's ledger and are deliberately unasserted —
// receiver-side counting is classified by the remote ADDRESS and is
// inherently remote-controlled.
func spoofedMACUntracked() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.31.0/24", "10.0.31.1").
		VM("vm-a", "T1", "10.0.31.5")
	b.SharedNetwork("net-iso", "admin").
		Subnet("sub-iso", "10.0.32.0/24", "10.0.32.1").
		VM("vm-b", "T2", "10.0.32.6")
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").
		Attach("sub-T1", "10.0.31.1").
		ExternalGateway("net-ext")
	// Gateway-attached router on the shared subnet so vm-b's default
	// FIP can associate.
	b.Router("r-iso", "admin").
		Attach("sub-iso", "10.0.32.1").
		ExternalGateway("net-ext")
	return &scenariotest.Scenario{
		Name:    "spoofed-mac-untracked",
		Desc:    "Forged source MAC on a port-security-off port lands in unknown/miss.",
		Builder: b,
		Steps: []scenariotest.Step{
			scenariotest.AttachPortStep{VM: "vm-a", ID: "vm-a-forge",
				Network: "net-iso", Subnet: "sub-iso", IP: "10.0.32.9",
				PortSecurityOff: true},
			scenariotest.ConfigureNICStep{VM: "vm-a", Dev: "eth1", CIDR: "10.0.32.9/24"},
			scenariotest.CaptureStep{},
			scenariotest.SetNICMACStep{VM: "vm-a", Dev: "eth1", MAC: "02:de:ad:be:ef:01"},
			// The subnet route installed by configure-nic sends this out
			// eth1 — now sourcing the forged MAC.
			scenariotest.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.ExternalTarget("10.0.32.6"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			scenariotest.ZoneGrowthStep{Tenant: "unknown", Zone: "miss", Direction: "tx",
				MinBytes: 1 << 20, Note: "forged frames park in unknown/miss"},
			scenariotest.ZoneGrowthStep{Tenant: "T1", Zone: "shared", Direction: "tx",
				MaxBytes: 256 << 10, Note: "no shared-zone attribution to the spoofing tenant"},
			scenariotest.ZoneGrowthStep{Tenant: "T1", Zone: "same_tenant", Direction: "tx",
				MaxBytes: 256 << 10, Note: "no same-tenant attribution to the spoofing tenant"},
		},
	}
}
