package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// portMoveAcrossServers closes the last hole in the {MAC × port ×
// server} lifecycle matrix (lachesis#254): the SAME Neutron port — same
// MAC, same port_id — detached from server X and reattached to server Y
// (a Nova os-interface move; only device_id changes). The four-layer
// billing behavior under test:
//
//   - X's server series never dips and holds its pre-move value: the
//     device_id change settles the port's rows into X's server-settled
//     bucket, so X flat-lines (until X itself dies) instead of losing
//     its history.
//   - Y's series carries the post-move traffic: the stabilizing
//     AssertStep on vm-b is the discriminating row — if the reconcile
//     failed to re-bind the server attribution, Y's series never shows
//     the driven bytes and the assert times out red. (Y inheriting X's
//     HISTORY — re-labeling without the settle — is pinned at the state
//     layer by the settleAttributionChange unit tests; no cheap live
//     upper-bound exists in the vocabulary yet.)
//   - The port-tier series re-homes with the port: post-move traffic
//     appears under the same port_id, now in Y's tuple.
//
// Expected GREEN on the four-layer agent — this is a regression lock,
// not a reproduction.
func portMoveAcrossServers() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.32.0/24", "10.0.32.1").
		VM("vm-a", "T1", "10.0.32.5").
		VM("vm-b", "T1", "10.0.32.6")
	b.Network("net-T1b", "T1").
		Subnet("sub-T1b", "10.0.33.0/24", "10.0.33.1").
		VM("vm-c", "T1", "10.0.33.5")
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").
		Attach("sub-T1", "10.0.32.1").
		Attach("sub-T1b", "10.0.33.1").
		ExternalGateway("net-ext")

	return &scenariotest.Scenario{
		Name:    "port-move-across-servers",
		Desc:    "Move a NIC (same port, same MAC) from one server to another; X keeps its history flat, Y counts from zero, the port series re-homes (lachesis#254, step-scripted).",
		Builder: b,
		Steps: []scenariotest.Step{
			// The mobile NIC on donor vm-a; drive through it to vm-c.
			scenariotest.AttachPortStep{VM: "vm-a", ID: "vm-a-nic2",
				Network: "net-T1b", Subnet: "sub-T1b", IP: "10.0.33.9"},
			scenariotest.ConfigureNICStep{VM: "vm-a", Dev: "eth1", CIDR: "10.0.33.9/24"},
			scenariotest.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.VMTarget("vm-c"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			scenariotest.AssertStep{Note: "pre-move drive lands on the donor", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "same_tenant", Direction: "tx", VM: "vm-a", MinBytes: 1 << 20},
			}},
			scenariotest.PortSeriesStep{VM: "vm-a", Port: "vm-a-nic2", MinBytes: 1 << 20,
				Note: "pre-move traffic attributes to the mobile port"},

			// The move: detach from vm-a (port kept), reattach to vm-b.
			scenariotest.CaptureStep{},
			scenariotest.DetachPortStep{VM: "vm-a", Port: "vm-a-nic2"},
			scenariotest.ReattachPortStep{VM: "vm-b", Port: "vm-a-nic2"},
			scenariotest.ConfigureNICStep{VM: "vm-b", Dev: "eth1", CIDR: "10.0.33.9/24"},

			// Post-move drive from the recipient through the moved NIC.
			scenariotest.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-b", To: scenariotest.VMTarget("vm-c"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},

			// THE discriminating rows: Y carries the post-move bytes
			// (stabilizes until the re-bind + drain have landed) …
			scenariotest.AssertStep{Note: "post-move drive lands on the recipient", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "same_tenant", Direction: "tx", VM: "vm-b", MinBytes: 1 << 20},
			}},
			// … X's series held (absorber flat-line, no dip) …
			scenariotest.ServerMonotoneStep{VM: "vm-a",
				Note: "donor's series holds across the move (server-settled flat line)"},
			// … and the port-tier series moved home with the port. Only
			// the POST-move bytes: the device_id change SettleRebases the
			// rows (pre-move bytes park in X's server bucket), and the
			// mortal leaf restarts under Y's tuple — by design.
			scenariotest.PortSeriesStep{VM: "vm-b", Port: "vm-a-nic2", MinBytes: 1 << 20,
				Note: "port series re-homes with the port (post-move bytes under Y)"},
			scenariotest.MonotoneStep{Tenant: "T1", Note: "tenant plane invariant across the outbound move"},

			// RETURN LEG: the port comes home to vm-a and traffic must
			// grow correctly on top of the parked history. Three 1 MiB
			// drives ride ONE tenant tuple (a→c, b→c, a→c are all
			// same_tenant tx), so the three per-leg ≥1 MiB deltas below,
			// stitched by the monotone rows, compose to the 3 MiB end
			// total — a leg swallowed by the rebase/reset arithmetic
			// (double-fold, lost watermark, missed re-bind) breaks its
			// delta and fails its row.
			scenariotest.CaptureStep{},
			scenariotest.DetachPortStep{VM: "vm-b", Port: "vm-a-nic2"},
			scenariotest.ReattachPortStep{VM: "vm-a", Port: "vm-a-nic2"},
			scenariotest.ConfigureNICStep{VM: "vm-a", Dev: "eth1", CIDR: "10.0.33.9/24"},
			scenariotest.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.VMTarget("vm-c"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			scenariotest.AssertStep{Note: "return leg — the homecoming port counts fresh traffic", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "same_tenant", Direction: "tx", VM: "vm-a", MinBytes: 1 << 20},
				{TenantID: "T1", Zone: "same_tenant", Direction: "tx", MinBytes: 1 << 20},
			}},
			// Y's series now flat-lines in turn (its bucket holds the
			// middle leg), and the port leaf follows the port home.
			scenariotest.ServerMonotoneStep{VM: "vm-b",
				Note: "recipient's series holds after the port leaves (server-settled flat line)"},
			scenariotest.PortSeriesStep{VM: "vm-a", Port: "vm-a-nic2", MinBytes: 1 << 20,
				Note: "port series re-homes back (post-return bytes under X)"},

			scenariotest.MonotoneStep{Tenant: "T1", Note: "tenant plane invariant throughout"},
		},
	}
}
