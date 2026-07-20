package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// portRecreateSameServer reproduces same-tuple rebirth (lachesis#227):
// a server's same_tenant series tuple is fed solely by a hot-plugged
// NIC; deleting that NIC's port ends the tuple (ghost fold), and a NEW
// port — auto-generated MAC, deliberately NOT MAC reuse: the label
// tuple, not the MAC, is the series identity — on the same server
// rebirths the tuple. Without the per-tuple carry the reborn series
// restarts below its own history, which the billing ETL's day-window
// clamp reads as zero usage.
//
// Evidence-first: against today's agent the final server-monotone
// assertion is expected RED (reborn 1 MiB < captured 2 MiB) — the live
// proof of the rebirth-lower hazard. Green once lachesis#227 lands.
//
// The 2 MiB first drive vs 1 MiB rebirth drive keeps the red case far
// from the noise margin: the reborn tuple cannot accidentally reach
// its captured value.
func portRecreateSameServer() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.23.0/24", "10.0.23.1").
		VM("vm-a", "T1", "10.0.23.5")
	b.Network("net-T1b", "T1").
		Subnet("sub-T1b", "10.0.24.0/24", "10.0.24.1").
		VM("vm-b", "T1", "10.0.24.5")
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").
		Attach("sub-T1", "10.0.23.1").
		Attach("sub-T1b", "10.0.24.1").
		ExternalGateway("net-ext")

	return &scenariotest.Scenario{
		Name:    "port-recreate-same-server",
		Desc:    "Delete a NIC's port, sweep, recreate on the same server (new MAC); the reborn series must continue (lachesis#227, step-scripted).",
		Builder: b,
		Steps: []scenariotest.Step{
			// vm-a's same_tenant traffic rides ONLY the hot-plugged NIC
			// (eth0 carries just the external SSH path), so the tuple
			// ends cleanly when that NIC's port dies.
			scenariotest.AttachPortStep{VM: "vm-a", ID: "vm-a-nic2",
				Network: "net-T1b", Subnet: "sub-T1b", IP: "10.0.24.9"},
			scenariotest.ConfigureNICStep{VM: "vm-a", Dev: "eth1", CIDR: "10.0.24.9/24"},
			scenariotest.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 2 << 20, Proto: scenariotest.TCP},
			}},
			scenariotest.AssertStep{Note: "pre-delete drive", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "same_tenant", Direction: "tx", VM: "vm-a", MinBytes: 2 << 20},
			}},

			// End the tuple: delete the port, let the sweep fold it.
			scenariotest.CaptureStep{},
			scenariotest.DetachPortStep{VM: "vm-a", Port: "vm-a-nic2", Delete: true},
			scenariotest.AwaitSweepStep{},
			scenariotest.MonotoneStep{Tenant: "T1",
				Note: "tenant plane invariant across the fold"},

			// Rebirth: a NEW port (fresh MAC) on the same server and
			// subnet — the same label tuple, no shared Neutron identity.
			scenariotest.AttachPortStep{VM: "vm-a", ID: "vm-a-nic3",
				Network: "net-T1b", Subnet: "sub-T1b", IP: "10.0.24.9"},
			scenariotest.ConfigureNICStep{VM: "vm-a", Dev: "eth1", CIDR: "10.0.24.9/24"},
			scenariotest.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			scenariotest.AssertStep{Note: "post-rebirth drive", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "same_tenant", Direction: "tx", VM: "vm-a", MinBytes: 1 << 20},
			}},

			// THE reproduction row: the reborn tuple must continue from
			// its carried value, never restart below it. RED on today's
			// agent (reborn ~1 MiB < captured ~2 MiB).
			scenariotest.ServerMonotoneStep{VM: "vm-a",
				Note: "reborn tuple continues from the carried value (lachesis#227)"},
			scenariotest.MonotoneStep{Tenant: "T1",
				Note: "tenant plane invariant at scenario end"},
		},
	}
}
