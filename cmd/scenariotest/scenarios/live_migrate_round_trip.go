package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/steps"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// liveMigrateRoundTrip locks in as tested fact what the design argues
// (lachesis#235): a live migration never settles anything — the port
// never leaves the Neutron snapshot, so no ghost, no fold — and a
// round trip A→B→A resumes the SOURCE node's flat-lined series
// monotonically (same flow keys; the reset guard absorbs any
// pressure-evicted kernel entries). Where live-migration-continuity
// proves one hop's re-attach, this proves the return leg: the node the
// VM left and came back to.
//
// Expected GREEN on today's agent — a red row here falsifies the
// migration-safety analysis, which is exactly why it runs first in the
// evidence pass.
func liveMigrateRoundTrip() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.27.0/24", "10.0.27.1").
		VM("vm-a", "T1", "10.0.27.5").
		VM("vm-b", "T1", "10.0.27.6")
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").
		Attach("sub-T1", "10.0.27.1").
		ExternalGateway("net-ext")

	return &scenariotest.Scenario{
		Name:    "live-migrate-round-trip",
		Desc:    "Live-migrate a VM away and back; nothing folds, and the source node's series resume monotonically (lachesis#235, step-scripted).",
		Builder: b,
		Placement: scenariotest.Placement{
			"vm-a": "node:0",
			"vm-b": "node:1",
		},
		Steps: []scenariotest.Step{
			// Baseline drive: the cross-host split attributes normally.
			steps.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			steps.AssertStep{Note: "pre-migration drive", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "same_tenant", Direction: "tx", Node: "node:0", MinBytes: 1 << 20},
				{TenantID: "T1", Zone: "same_tenant", Direction: "rx", Node: "node:1", MinBytes: 1 << 20},
			}},

			// Outbound leg: nothing folds, nothing dips, nothing re-buckets.
			steps.CaptureStep{},
			steps.MigrateStep{VM: "vm-a", Target: "node:1"},
			steps.MaxGhostsStep{Note: "outbound migration marks no ghost"},
			steps.ServerMonotoneStep{VM: "vm-a", Note: "per-server series monotone across outbound leg"},
			steps.MonotoneStep{Tenant: "T1", Note: "tenant monotone across outbound leg"},
			steps.MaxGrowthStep{Tenant: "unknown", Zone: "same_tenant",
				Budget: migrationNoiseBudget, Note: "no re-bucket to unknown (outbound)"},
			steps.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			steps.AssertStep{Note: "drive while away", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "same_tenant", Direction: "tx", VM: "vm-a", Node: "node:1", MinBytes: 1 << 20},
			}},

			// Return leg: back onto the node whose series flat-lined —
			// they must RESUME, not restart.
			steps.CaptureStep{},
			steps.MigrateStep{VM: "vm-a", Target: "node:0"},
			steps.MaxGhostsStep{Note: "return migration marks no ghost"},
			steps.ServerMonotoneStep{VM: "vm-a", Note: "per-server series monotone across return leg"},
			steps.MonotoneStep{Tenant: "T1", Note: "tenant monotone across return leg"},
			steps.MaxGrowthStep{Tenant: "unknown", Zone: "same_tenant",
				Budget: migrationNoiseBudget, Note: "no re-bucket to unknown (return)"},
			steps.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			steps.AssertStep{Note: "post-return drive — home node observes new bytes", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "same_tenant", Direction: "tx", VM: "vm-a", Node: "node:0", MinBytes: 1 << 20},
				{TenantID: "T1", Zone: "same_tenant", Direction: "rx", Node: "node:1", MinBytes: 1 << 20},
			}},
			steps.MonotoneStep{Tenant: "T1", Note: "series intact at scenario end"},
		},
	}
}
