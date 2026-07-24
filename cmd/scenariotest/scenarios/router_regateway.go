package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// routerRegateway exercises the router-external-network SettleRebase
// (docs/architecture/billing.md, reconcile/routers.go): re-gatewaying a
// router to a different external network folds every flow riding that
// router's interface MAC under the OLD external_network label before
// the map swaps, so the exposed per-external-network series stay
// monotone across the move.
//
// vm-a egresses via r-T1; the per-flow external label is r-T1's gateway
// net (the peer MAC on the flow key is r-T1's interface, not the FIP).
// The move sequence dodges Neutron's FIP↔gateway coupling
// (RouterExternalGatewayInUseByFloatingIp: a gateway can't change while
// a FIP on the old external net needs it): the VM's FIP is first
// reassociated to net-ext2, then r-T1 is re-gatewayed to net-ext2.
//
// Asserted (A→B): the old-label (net-ext) series is frozen and monotone
// through the fold, and the fold actually fired (a settled tuple was
// added). The post-move "new bytes under net-ext2" drive is out of
// scope at this tier — net-ext2 is a created segmentless external net
// with no uplink, so a FIP on it is unreachable and the VM can't be
// driven after the move; the per-flow router-MAC labeling that would
// carry the new label is already live-proven by the multi-external-path
// scenario.
//
// Then the ROUND TRIP (B→A): re-gateway back to net-ext. This fires a
// SECOND SettleRebase — on rows already rebased once — and the point is
// that it must leave the original net-ext accumulation whole: the ~1 MiB
// folded at A→B lives in the settled accumulator and must be neither
// dropped (series dips) nor re-folded on top of itself (series inflates)
// when the label swaps back. Monotone + a tight max-growth box it.
func routerRegateway() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.42.0/24", "10.0.42.1").
		VM("vm-a", "T1", "10.0.42.5")
	b.ExternalNetwork("net-ext", "admin") // provider "public"
	// Created second external net — needs its own IPv4 subnet so a FIP
	// (and the router gateway) can allocate on it.
	b.ExternalNetwork("net-ext2", "admin").
		Subnet("sub-ext2", "172.24.98.0/24", "172.24.98.1")
	b.Router("r-T1", "T1").
		Attach("sub-T1", "10.0.42.1").
		ExternalGateway("net-ext")
	return &scenariotest.Scenario{
		Name:               "router-regateway",
		Desc:               "Gateway move folds history under the old external-network label.",
		Builder:            b,
		CreateExternalNets: []string{"net-ext2"},
		Steps: []scenariotest.Step{
			scenariotest.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.ExternalTarget("8.8.8.8"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			scenariotest.AssertStep{Note: "egress under the provider external net", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 1 << 20, ExternalNetwork: "net-ext"},
			}},

			scenariotest.CaptureStep{},
			// Free the provider gateway (Neutron refuses a gateway change
			// while a FIP on the old external net needs it), then re-gateway
			// r-T1 to net-ext2. reconcile/routers.go folds the
			// net-ext-labeled flows under their old label first. SSH dies
			// with the FIP — deliberate; nothing is driven after.
			scenariotest.DeleteFIPStep{VM: "vm-a", Provider: true},
			scenariotest.SetRouterGatewayStep{Router: "r-T1", ExternalNet: "net-ext2"},
			scenariotest.SleepStep{Duration: reconcileSettle},

			// The fold fired (a settled tuple was added for the old label)...
			scenariotest.SettledTuplesGrewStep{Min: 1,
				Note: "A→B re-gateway folded the old-label flows"},
			// ...and the old external-net series is frozen and monotone —
			// the fold preserved every byte it had emitted (totals conserved).
			scenariotest.MonotoneStep{Tenant: "T1",
				Note: "net-ext series frozen and monotone after A→B"},

			// Round trip: re-gateway back to the provider net. The
			// net-ext2-labeled rows fold again; the settled net-ext bytes
			// from A→B must be left untouched.
			scenariotest.SetRouterGatewayStep{Router: "r-T1", ExternalNet: "net-ext"},
			scenariotest.SleepStep{Duration: reconcileSettle},
			// Still whole — the round trip neither dropped the original
			// accumulation (monotone, no dip)...
			scenariotest.MonotoneStep{Tenant: "T1",
				Note: "net-ext series still whole after B→A"},
			// ...nor re-counted it (no traffic drove during the folds, so
			// external growth since the pre-move capture must stay at noise
			// level — a double-count on the fold-back would show ~1 MiB).
			scenariotest.MaxGrowthStep{Tenant: "T1", Zone: "external", Budget: 256 << 10,
				Note: "round trip conserved the accumulation — no double-count on fold-back"},

			// Now the end-to-end proof: with the router back on net-ext,
			// restore a provider FIP (the round trip deleted it) and drive
			// 2 MiB more. This must ADD to the 1 MiB settled at A→B — the
			// LastEbpfRaw watermark has to resume, not reset to zero. Keep
			// the first drive's baseline so the assert reads the CUMULATIVE
			// net-ext total: settled 1 MiB + live 2 MiB = 3 MiB on A.
			scenariotest.AssociateFIPStep{VM: "vm-a", Network: "net-ext"},
			scenariotest.DriveStep{KeepBaseline: true, Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.ExternalTarget("8.8.8.8"), Bytes: 2 << 20, Proto: scenariotest.TCP},
			}},
			scenariotest.AssertStep{Note: "live traffic resumes on top of the settled total (1 MiB settled + 2 MiB live = 3 MiB)", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 3 << 20, ExternalNetwork: "net-ext"},
			}},
		},
	}
}
