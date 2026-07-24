package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// vrrpVMACLeak pins TODAY'S allowed-address-pairs behavior — the
// documented revenue leak of docs/architecture/contracts.md#deferred-work
// item 9: a guest sourcing traffic from a VRRP virtual MAC declared in
// allowed_address_pairs (port security ON — the pairs are what admit
// it) is invisible to mac_tenant_map, so its bytes park in
// unknown/miss instead of billing the owning tenant.
//
// THIS IS THE PRE-FIX BASELINE. When AAP MACs are mapped (deferred
// item 9 ships), the MinBytes row below must FLIP — move the 1 MiB
// floor from unknown/miss/tx to T1's tuple and drop the leak framing.
//
// Shape: vm-a (T1) hot-plugs a NIC on the tenant's second subnet with
// AAP entries for the vMAC (against both the VIP and the NIC's fixed
// IP, so plain pings pass the (IP, MAC) anti-spoof check), assumes the
// vMAC in-guest like a VRRP master, and pings vm-b (T1).
func vrrpVMACLeak() *scenariotest.Scenario {
	const vmac = "00:00:5e:00:01:2a" // VRRP vMAC, VRID 42
	b := scenario.New()
	b.Network("net-T1a", "T1").
		Subnet("sub-T1a", "10.0.33.0/24", "10.0.33.1").
		VM("vm-a", "T1", "10.0.33.5")
	b.Network("net-T1b", "T1").
		Subnet("sub-T1b", "10.0.34.0/24", "10.0.34.1").
		VM("vm-b", "T1", "10.0.34.6")
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").
		Attach("sub-T1a", "10.0.33.1").
		Attach("sub-T1b", "10.0.34.1").
		ExternalGateway("net-ext")
	return &scenariotest.Scenario{
		Name:    "vrrp-vmac-leak",
		Desc:    "AAP vMAC traffic parks in unknown/miss — the pre-fix baseline for deferred item 9.",
		Builder: b,
		Steps: []scenariotest.Step{
			scenariotest.AttachPortStep{VM: "vm-a", ID: "vm-a-vrrp",
				Network: "net-T1b", Subnet: "sub-T1b", IP: "10.0.34.9",
				AllowedPairs: []scenariotest.AddressPair{
					{IP: "10.0.34.100", MAC: vmac}, // the VIP a real VRRP group shares
					{IP: "10.0.34.9", MAC: vmac},   // fixed IP under the vMAC — lets plain pings source it
				}},
			scenariotest.ConfigureNICStep{VM: "vm-a", Dev: "eth1", CIDR: "10.0.34.9/24"},
			scenariotest.CaptureStep{},
			scenariotest.SetNICMACStep{VM: "vm-a", Dev: "eth1", MAC: vmac},
			scenariotest.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.ExternalTarget("10.0.34.6"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			scenariotest.ZoneGrowthStep{Tenant: "unknown", Zone: "miss", Direction: "tx",
				MinBytes: 1 << 20, Note: "PRE-FIX baseline: vMAC bytes leak to unknown (deferred item 9)"},
			// vm-b's echo replies (~1.07 MiB with headers) legitimately
			// bill T1 same_tenant/tx; the forged MiB ALSO landing there
			// would read ≈2.1 MiB. The ceiling separates the two.
			scenariotest.ZoneGrowthStep{Tenant: "T1", Zone: "same_tenant", Direction: "tx",
				MaxBytes: 1600 << 10, Note: "vMAC bytes do not double-bill the owner today"},
		},
	}
}
