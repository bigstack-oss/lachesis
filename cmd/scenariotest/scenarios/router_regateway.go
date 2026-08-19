package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/steps"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// routerRegateway exercises the router-external SettleRebase:
// re-gatewaying folds every flow on that router's interface MAC under
// the OLD external_network label before the map swaps, so the exposed
// per-network series stay monotone across the move.
//
// The move order dodges Neutron's FIP↔gateway coupling — the FIP moves
// to net-ext2 first, then the router. Driving AFTER the move is out of
// scope here: net-ext2 is segmentless, so a FIP on it is unreachable.
//
// The ROUND TRIP is the real assertion: a second rebase, on rows
// already rebased once, must leave the original accumulation whole —
// neither dropped (series dips) nor re-folded onto itself (inflates).
//
// docs/architecture/billing.md
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
			steps.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.ExternalTarget("8.8.8.8"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			steps.AssertStep{Note: "egress under the provider external net", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 1 << 20, ExternalNetwork: "net-ext"},
			}},

			steps.CaptureStep{},
			// Free the provider gateway (Neutron refuses a gateway change
			// while a FIP on the old external net needs it), then re-gateway
			// r-T1 to net-ext2. reconcile/routers.go folds the
			// net-ext-labeled flows under their old label first. SSH dies
			// with the FIP — deliberate; nothing is driven after.
			steps.DeleteFIPStep{VM: "vm-a", Provider: true},
			steps.SetRouterGatewayStep{Router: "r-T1", ExternalNet: "net-ext2"},
			steps.SleepStep{Duration: reconcileSettle},

			// The fold fired (a settled tuple was added for the old label)...
			steps.SettledTuplesGrewStep{Min: 1,
				Note: "A→B re-gateway folded the old-label flows"},
			// ...and the old external-net series is frozen and monotone —
			// the fold preserved every byte it had emitted (totals conserved).
			steps.MonotoneStep{Tenant: "T1",
				Note: "net-ext series frozen and monotone after A→B"},

			// Round trip: re-gateway back to the provider net. The
			// net-ext2-labeled rows fold again; the settled net-ext bytes
			// from A→B must be left untouched.
			steps.SetRouterGatewayStep{Router: "r-T1", ExternalNet: "net-ext"},
			steps.SleepStep{Duration: reconcileSettle},
			// Still whole — the round trip neither dropped the original
			// accumulation (monotone, no dip)...
			steps.MonotoneStep{Tenant: "T1",
				Note: "net-ext series still whole after B→A"},
			// ...nor re-counted it (no traffic drove during the folds, so
			// external growth since the pre-move capture must stay at noise
			// level — a double-count on the fold-back would show ~1 MiB).
			steps.MaxGrowthStep{Tenant: "T1", Zone: "external", Budget: 256 << 10,
				Note: "round trip conserved the accumulation — no double-count on fold-back"},

			// Now the end-to-end proof: with the router back on net-ext,
			// restore a provider FIP (the round trip deleted it) and drive
			// 2 MiB more. This must ADD to the 1 MiB settled at A→B — the
			// LastEbpfRaw watermark has to resume, not reset to zero. Keep
			// the first drive's baseline so the assert reads the CUMULATIVE
			// net-ext total: settled 1 MiB + live 2 MiB = 3 MiB on A.
			steps.AssociateFIPStep{VM: "vm-a", Network: "net-ext"},
			steps.DriveStep{KeepBaseline: true, Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.ExternalTarget("8.8.8.8"), Bytes: 2 << 20, Proto: scenariotest.TCP},
			}},
			steps.AssertStep{Note: "live traffic resumes on top of the settled total (1 MiB settled + 2 MiB live = 3 MiB)", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 3 << 20, ExternalNetwork: "net-ext"},
			}},
		},
	}
}
