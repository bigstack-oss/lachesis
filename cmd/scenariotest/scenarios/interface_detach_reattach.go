package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/steps"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// interfaceDetachReattach pins both halves of the detach lifecycle —
// the same Neutron port throughout, so it is the one recreate shape
// with NO new identity anywhere. Which path fires is decided purely by
// whether the reattach beats the grace window:
//
//   - FAST (inside grace): the ghost resurrects with identical
//     attribution, no fold, so the series must not dip. Expected GREEN
//     — running it live validates the resurrection semantics rather
//     than assuming them.
//   - SLOW (after the sweep): same-tuple rebirth. Expected RED today,
//     green once the per-tuple carry lands.
func interfaceDetachReattach() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.25.0/24", "10.0.25.1").
		VM("vm-a", "T1", "10.0.25.5")
	b.Network("net-T1b", "T1").
		Subnet("sub-T1b", "10.0.26.0/24", "10.0.26.1").
		VM("vm-b", "T1", "10.0.26.5")
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").
		Attach("sub-T1", "10.0.25.1").
		Attach("sub-T1b", "10.0.26.1").
		ExternalGateway("net-ext")

	return &scenariotest.Scenario{
		Name:    "interface-detach-reattach",
		Desc:    "Detach/reattach a NIC fast (no fold — no dip) and slow (post-sweep rebirth must carry) (lachesis#227, step-scripted).",
		Builder: b,
		Steps: []scenariotest.Step{
			steps.AttachPortStep{VM: "vm-a", ID: "vm-a-nic2",
				Network: "net-T1b", Subnet: "sub-T1b", IP: "10.0.26.9"},
			steps.ConfigureNICStep{VM: "vm-a", Dev: "eth1", CIDR: "10.0.26.9/24"},
			steps.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 2 << 20, Proto: scenariotest.TCP},
			}},
			steps.AssertStep{Note: "pre-detach drive", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "same_tenant", Direction: "tx", VM: "vm-a", MinBytes: 2 << 20},
			}},

			// FAST: back before the grace elapses — resurrection, no fold.
			steps.CaptureStep{},
			steps.DetachPortStep{VM: "vm-a", Port: "vm-a-nic2"},
			steps.ReattachPortStep{VM: "vm-a", Port: "vm-a-nic2"},
			steps.ConfigureNICStep{VM: "vm-a", Dev: "eth1", CIDR: "10.0.26.9/24"},
			// No explicit fold-gate here: within the grace an immediate
			// settled-counter check is blind to a not-yet-registered fold
			// (lachesis#243), and a fast detach transiently marks then
			// un-marks a ghost — so the no-dip server-monotone below IS the
			// proof that the resurrection folded nothing.
			steps.ServerMonotoneStep{VM: "vm-a",
				Note: "fast reattach within grace — no dip"},
			steps.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			steps.AssertStep{Note: "post-fast-reattach drive (no double-count is the tenant monotone below)", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "same_tenant", Direction: "tx", VM: "vm-a", MinBytes: 1 << 20},
			}},
			steps.MonotoneStep{Tenant: "T1", Note: "tenant plane intact across fast cycle"},

			// SLOW: wait out the sweep, then bring the same port back.
			steps.CaptureStep{},
			steps.DetachPortStep{VM: "vm-a", Port: "vm-a-nic2"},
			steps.AwaitSweepStep{ForMACOf: "vm-a-nic2"},
			steps.ReattachPortStep{VM: "vm-a", Port: "vm-a-nic2"},
			steps.ConfigureNICStep{VM: "vm-a", Dev: "eth1", CIDR: "10.0.26.9/24"},
			steps.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			// THE reproduction row: RED on today's agent — the post-sweep
			// reattach rebirths the tuple below its captured value.
			steps.ServerMonotoneStep{VM: "vm-a",
				Note: "reattach after sweep continues from the carried value (lachesis#227)"},
			steps.MonotoneStep{Tenant: "T1", Note: "tenant plane invariant at scenario end"},
		},
	}
}
