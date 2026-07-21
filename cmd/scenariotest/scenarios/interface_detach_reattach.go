package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// interfaceDetachReattach pins both halves of the detach lifecycle
// (lachesis#227's attribution edge — same Neutron port throughout, so
// this is the one recreate shape with NO new identity anywhere):
//
//   - FAST: detach and reattach within the lingering-ghost grace. The
//     ghost resurrects with identical attribution — no fold, so the
//     per-server series must not dip. Expected GREEN on today's agent;
//     running it live VALIDATES the resurrection semantics rather than
//     assuming them.
//   - SLOW: detach, wait out the sweep (the tuple's rows fold), then
//     reattach the SAME port and drive again. Same-tuple rebirth:
//     expected RED on today's agent (the reborn series restarts below
//     its history), green once the per-tuple carry (lachesis#227)
//     lands.
//
// A detached port loses its device binding, so the agent's reconcile
// treats the MAC as gone — which of the two paths fires is decided
// purely by whether the reattach beats the grace window.
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
			scenariotest.AttachPortStep{VM: "vm-a", ID: "vm-a-nic2",
				Network: "net-T1b", Subnet: "sub-T1b", IP: "10.0.26.9"},
			scenariotest.ConfigureNICStep{VM: "vm-a", Dev: "eth1", CIDR: "10.0.26.9/24"},
			scenariotest.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 2 << 20, Proto: scenariotest.TCP},
			}},
			scenariotest.AssertStep{Note: "pre-detach drive", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "same_tenant", Direction: "tx", VM: "vm-a", MinBytes: 2 << 20},
			}},

			// FAST: back before the grace elapses — resurrection, no fold.
			scenariotest.CaptureStep{},
			scenariotest.DetachPortStep{VM: "vm-a", Port: "vm-a-nic2"},
			scenariotest.ReattachPortStep{VM: "vm-a", Port: "vm-a-nic2"},
			scenariotest.ConfigureNICStep{VM: "vm-a", Dev: "eth1", CIDR: "10.0.26.9/24"},
			scenariotest.MaxSettledStep{Note: "fast reattach folds nothing"},
			scenariotest.ServerMonotoneStep{VM: "vm-a",
				Note: "fast reattach within grace — no dip"},
			scenariotest.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			scenariotest.AssertStep{Note: "post-fast-reattach drive (no double-count is the tenant monotone below)", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "same_tenant", Direction: "tx", VM: "vm-a", MinBytes: 1 << 20},
			}},
			scenariotest.MonotoneStep{Tenant: "T1", Note: "tenant plane intact across fast cycle"},

			// SLOW: wait out the sweep, then bring the same port back.
			scenariotest.CaptureStep{},
			scenariotest.DetachPortStep{VM: "vm-a", Port: "vm-a-nic2"},
			scenariotest.AwaitSweepStep{ForMACOf: "vm-a-nic2"},
			scenariotest.ReattachPortStep{VM: "vm-a", Port: "vm-a-nic2"},
			scenariotest.ConfigureNICStep{VM: "vm-a", Dev: "eth1", CIDR: "10.0.26.9/24"},
			scenariotest.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			// THE reproduction row: RED on today's agent — the post-sweep
			// reattach rebirths the tuple below its captured value.
			scenariotest.ServerMonotoneStep{VM: "vm-a",
				Note: "reattach after sweep continues from the carried value (lachesis#227)"},
			scenariotest.MonotoneStep{Tenant: "T1", Note: "tenant plane invariant at scenario end"},
		},
	}
}
