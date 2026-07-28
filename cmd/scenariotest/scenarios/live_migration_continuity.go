package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/steps"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// migrationNoiseBudget bounds background chatter in the no-re-bucket
// check across the migration window, same margin logic as
// rebornNoiseBudget: noise is KiB, a lost-and-rebucketed flow is the
// driven MiB.
const migrationNoiseBudget = 256 << 10

// liveMigrationContinuity proves billing survives a live migration
// (docs/architecture/edge-cases.md case 16): the source tap disappears (DELLINK), the
// destination tap appears (NEWLINK) and the agent there re-attaches —
// and through all of it the tenant's series stays monotone, nothing
// re-buckets to "unknown", and bytes driven AFTER the move are
// observed by the destination node's agent. Node identity in the
// per-node assertions follows the observing agent, so the
// post-migration drive asserting on node:1 is precisely the proof the
// re-attach worked.
//
// vm-a starts on node:0 and is live-migrated to node:1 (where vm-b
// already lives — post-migration the flow is host-local, which is
// irrelevant to what this scenario proves about the re-attach).
func liveMigrationContinuity() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.15.0/24", "10.0.15.1").
		VM("vm-a", "T1", "10.0.15.5").
		VM("vm-b", "T1", "10.0.15.6")
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").
		Attach("sub-T1", "10.0.15.1").
		ExternalGateway("net-ext")
	return &scenariotest.Scenario{
		Name:    "live-migration-continuity",
		Desc:    "Live-migrate a driven VM; billing stays monotone and new bytes surface on the destination's agent (step-scripted).",
		Builder: b,
		Placement: scenariotest.Placement{
			"vm-a": "node:0",
			"vm-b": "node:1",
		},
		Steps: []scenariotest.Step{
			// Pre-migration: the cross-host split attributes normally.
			steps.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			steps.AssertStep{Note: "pre-migration drive", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "same_tenant", Direction: "tx", Node: "node:0", MinBytes: 1 << 20},
				{TenantID: "T1", Zone: "same_tenant", Direction: "rx", Node: "node:1", MinBytes: 1 << 20},
			}},

			// Move the sender across the cluster.
			steps.CaptureStep{},
			steps.MigrateStep{VM: "vm-a", Target: "node:1"},

			// The move itself billed nothing and lost nothing.
			steps.MonotoneStep{Tenant: "T1", Note: "monotone across live migration"},
			steps.MaxGrowthStep{Tenant: "unknown", Zone: "same_tenant",
				Budget: migrationNoiseBudget, Note: "no re-bucket to unknown"},

			// Post-migration bytes are observed by the DESTINATION's
			// agent — the re-attach proof.
			steps.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			steps.AssertStep{Note: "post-migration drive", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "same_tenant", Direction: "tx", VM: "vm-a", Node: "node:1", MinBytes: 1 << 20},
				{TenantID: "T1", Zone: "same_tenant", Direction: "rx", Node: "node:1", MinBytes: 1 << 20},
			}},
			steps.MonotoneStep{Tenant: "T1", Note: "series intact at scenario end"},
		},
	}
}
