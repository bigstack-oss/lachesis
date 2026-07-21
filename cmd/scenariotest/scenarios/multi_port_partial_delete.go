package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// multiPortPartialDelete reproduces the partial-fold regression
// (lachesis#226): a server with two NICs feeds ONE per-server series
// tuple {server_id, same_tenant, tx} from both ports; deleting one
// port ghost-folds that NIC's rows into tenant settled while the other
// NIC keeps the tuple alive — and the still-live series drops by the
// folded amount. The tenant plane must hold throughout (the settled
// fold absorbs it there); the defect is exclusive to the mortal
// per-server family.
//
// Evidence-first: against today's agent the server-monotone assertion
// is expected RED in exactly this way — that run is the live proof for
// lachesis#226. It flips to a green regression when the per-tuple
// carry (lachesis#227) lands.
//
// vm-a's second NIC is hot-plugged (not a DSL VM — a DSL "VM" is one
// port with its own server; the whole point here is one server_id
// behind two ports). Both drives land in the same tuple because zone
// classification is per-peer, not per-NIC: vm-b and vm-c are the same
// tenant, so eth0's and eth1's flows are both same_tenant.
func multiPortPartialDelete() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.21.0/24", "10.0.21.1").
		VM("vm-a", "T1", "10.0.21.5").
		VM("vm-b", "T1", "10.0.21.6")
	b.Network("net-T1b", "T1").
		Subnet("sub-T1b", "10.0.22.0/24", "10.0.22.1").
		VM("vm-c", "T1", "10.0.22.5")
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").
		Attach("sub-T1", "10.0.21.1").
		Attach("sub-T1b", "10.0.22.1").
		ExternalGateway("net-ext")

	return &scenariotest.Scenario{
		Name:    "multi-port-partial-delete",
		Desc:    "Delete one NIC of a two-NIC VM; the per-server series must not dip (lachesis#226/#227, step-scripted).",
		Builder: b,
		Steps: []scenariotest.Step{
			// Second NIC onto vm-a, then bring it up in the guest.
			scenariotest.AttachPortStep{VM: "vm-a", ID: "vm-a-nic2",
				Network: "net-T1b", Subnet: "sub-T1b", IP: "10.0.22.9"},
			scenariotest.ConfigureNICStep{VM: "vm-a", Dev: "eth1", CIDR: "10.0.22.9/24"},

			// Both NICs feed the same {vm-a, same_tenant, tx} tuple:
			// eth0 to vm-b (connected subnet), eth1 to vm-c (connected
			// subnet after configure-nic).
			scenariotest.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP},
				{From: "vm-a", To: scenariotest.VMTarget("vm-c"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			scenariotest.AssertStep{Note: "two-NIC drive", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "same_tenant", Direction: "tx", MinBytes: 2 << 20},
				{TenantID: "T1", Zone: "same_tenant", Direction: "tx", VM: "vm-a", MinBytes: 2 << 20},
			}},

			// Delete NIC2's port outright and let the ghost sweep fold it.
			scenariotest.CaptureStep{},
			scenariotest.DetachPortStep{VM: "vm-a", Port: "vm-a-nic2", Delete: true},
			scenariotest.AwaitSweepStep{ForMACOf: "vm-a-nic2"},

			// THE reproduction row: the server's tuple still has live
			// rows (eth0), so its series must not have dipped. RED on
			// today's agent — the folded eth1 bytes leave the series.
			scenariotest.ServerMonotoneStep{VM: "vm-a",
				Note: "per-server series survives a partial fold (lachesis#226)"},
			// The contrast row: the tenant plane absorbs the fold.
			scenariotest.MonotoneStep{Tenant: "T1",
				Note: "tenant plane invariant across the fold"},

			// The surviving NIC keeps accruing normally.
			scenariotest.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			scenariotest.AssertStep{Note: "surviving NIC accrues", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "same_tenant", Direction: "tx", VM: "vm-a", MinBytes: 1 << 20},
			}},
		},
	}
}
