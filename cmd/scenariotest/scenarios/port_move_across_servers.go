package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/steps"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// portMoveAcrossServers covers the {MAC × port × server} case where
// the SAME port moves from server X to server Y — only device_id
// changes. Three billing properties:
//
//   - X's series never dips and holds its pre-move value: the
//     device_id change settles the rows into X's absorber, so X
//     flat-lines instead of losing its history.
//   - Y's series carries the post-move traffic. The stabilizing assert
//     on vm-b is the discriminating row — a failed re-bind never shows
//     the bytes and times out red.
//   - The port tier re-homes with the port, under Y's tuple.
//
// A regression lock, not a reproduction: expected GREEN.
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
			steps.AttachPortStep{VM: "vm-a", ID: "vm-a-nic2",
				Network: "net-T1b", Subnet: "sub-T1b", IP: "10.0.33.9"},
			steps.ConfigureNICStep{VM: "vm-a", Dev: "eth1", CIDR: "10.0.33.9/24"},
			steps.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.VMTarget("vm-c"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			steps.AssertStep{Note: "pre-move drive lands on the donor", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "same_tenant", Direction: "tx", VM: "vm-a", MinBytes: 1 << 20},
			}},
			steps.PortSeriesStep{VM: "vm-a", Port: "vm-a-nic2", MinBytes: 1 << 20,
				Note: "pre-move traffic attributes to the mobile port"},

			// The move: detach from vm-a (port kept), reattach to vm-b.
			steps.CaptureStep{},
			steps.DetachPortStep{VM: "vm-a", Port: "vm-a-nic2"},
			steps.ReattachPortStep{VM: "vm-b", Port: "vm-a-nic2"},
			steps.ConfigureNICStep{VM: "vm-b", Dev: "eth1", CIDR: "10.0.33.9/24"},

			// Post-move drive from the recipient through the moved NIC.
			steps.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-b", To: scenariotest.VMTarget("vm-c"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},

			// THE discriminating rows: Y carries the post-move bytes
			// (stabilizes until the re-bind + drain have landed) …
			steps.AssertStep{Note: "post-move drive lands on the recipient", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "same_tenant", Direction: "tx", VM: "vm-b", MinBytes: 1 << 20},
			}},
			// … X's series held (absorber flat-line, no dip) …
			steps.ServerMonotoneStep{VM: "vm-a",
				Note: "donor's series holds across the move (server-settled flat line)"},
			// … and the port-tier series moved home with the port. Only
			// the POST-move bytes: the device_id change SettleRebases the
			// rows (pre-move bytes park in X's server bucket), and the
			// mortal leaf restarts under Y's tuple — by design.
			steps.PortSeriesStep{VM: "vm-b", Port: "vm-a-nic2", MinBytes: 1 << 20,
				Note: "port series re-homes with the port (post-move bytes under Y)"},
			steps.MonotoneStep{Tenant: "T1", Note: "tenant plane invariant across the outbound move"},

			// RETURN LEG. Three 1 MiB drives ride ONE tenant tuple, so
			// the three per-leg deltas stitched by the monotone rows must
			// compose to 3 MiB — a leg swallowed by the rebase
			// arithmetic breaks its own delta and fails its row.
			steps.CaptureStep{},
			steps.DetachPortStep{VM: "vm-b", Port: "vm-a-nic2"},
			steps.ReattachPortStep{VM: "vm-a", Port: "vm-a-nic2"},
			steps.ConfigureNICStep{VM: "vm-a", Dev: "eth1", CIDR: "10.0.33.9/24"},
			steps.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.VMTarget("vm-c"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			steps.AssertStep{Note: "return leg — the homecoming port counts fresh traffic", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "same_tenant", Direction: "tx", VM: "vm-a", MinBytes: 1 << 20},
				{TenantID: "T1", Zone: "same_tenant", Direction: "tx", MinBytes: 1 << 20},
			}},
			// Y's series now flat-lines in turn (its bucket holds the
			// middle leg), and the port leaf follows the port home.
			steps.ServerMonotoneStep{VM: "vm-b",
				Note: "recipient's series holds after the port leaves (server-settled flat line)"},
			steps.PortSeriesStep{VM: "vm-a", Port: "vm-a-nic2", MinBytes: 1 << 20,
				Note: "port series re-homes back (post-return bytes under X)"},

			steps.MonotoneStep{Tenant: "T1", Note: "tenant plane invariant throughout"},
		},
	}
}
