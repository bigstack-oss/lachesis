package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/steps"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// portRecreateSameServer reproduces same-tuple rebirth: a server's
// series tuple fed solely by a hot-plugged NIC ends when that port is
// deleted, and a NEW port on the same server rebirths it. Deliberately
// NOT MAC reuse — the label tuple, not the MAC, is the series identity.
// Without the per-tuple carry the reborn series restarts below its own
// history, which the ETL's day-window clamp reads as zero usage.
//
// Evidence-first: expected RED today (reborn 1 MiB < captured 2 MiB).
// The 2:1 drive ratio keeps that case clear of the noise margin.
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
			steps.AttachPortStep{VM: "vm-a", ID: "vm-a-nic2",
				Network: "net-T1b", Subnet: "sub-T1b", IP: "10.0.24.9"},
			steps.ConfigureNICStep{VM: "vm-a", Dev: "eth1", CIDR: "10.0.24.9/24"},
			steps.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 2 << 20, Proto: scenariotest.TCP},
			}},
			steps.AssertStep{Note: "pre-delete drive", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "same_tenant", Direction: "tx", VM: "vm-a", MinBytes: 2 << 20},
			}},

			// End the tuple: delete the port, let the sweep fold it.
			steps.CaptureStep{},
			steps.DetachPortStep{VM: "vm-a", Port: "vm-a-nic2", Delete: true},
			steps.AwaitSweepStep{ForMACOf: "vm-a-nic2"},
			steps.MonotoneStep{Tenant: "T1",
				Note: "tenant plane invariant across the fold"},

			// Rebirth: a NEW port (fresh MAC) on the same server and
			// subnet — the same label tuple, no shared Neutron identity.
			steps.AttachPortStep{VM: "vm-a", ID: "vm-a-nic3",
				Network: "net-T1b", Subnet: "sub-T1b", IP: "10.0.24.9"},
			steps.ConfigureNICStep{VM: "vm-a", Dev: "eth1", CIDR: "10.0.24.9/24"},
			steps.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			steps.AssertStep{Note: "post-rebirth drive", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "same_tenant", Direction: "tx", VM: "vm-a", MinBytes: 1 << 20},
			}},

			// THE reproduction row: the reborn tuple must continue from
			// its carried value, never restart below it. RED on today's
			// agent (reborn ~1 MiB < captured ~2 MiB).
			steps.ServerMonotoneStep{VM: "vm-a",
				Note: "reborn tuple continues from the carried value (lachesis#227)"},
			steps.MonotoneStep{Tenant: "T1",
				Note: "tenant plane invariant at scenario end"},
		},
	}
}
