package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/steps"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// gcPressureRelief exercises pressure-relief GC end to end: crossing
// the fill watermark, evicting the oldest flows, and the "flush before
// evict" ordering that keeps a tenant's bytes intact across it.
//
// The real 80% watermark needs >52,000 concurrent flows, which one VM
// cannot produce, so the trigger moves to the traffic: the agent
// restarts under watermarks of a few entries, derived from the node's
// own config and restored at the end.
//
// Debugging note: if exposed bytes come up short, check
// unresolved_buffer_evictions_total{reason="lru"} before suspecting the
// GC. That buffer also DELETES kernel entries when it evicts.
//
// docs/architecture/data-structures.md#kernel-side-bpf-maps
func gcPressureRelief() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.53.0/24", "10.0.53.1").
		VM("vm-g", "T1", "10.0.53.5")
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").
		Attach("sub-T1", "10.0.53.1").
		ExternalGateway("net-ext")
	return &scenariotest.Scenario{
		Name:      "gc-pressure-relief",
		Desc:      "Pressure-relief GC evicts above the fill watermark without losing a tenant's bytes.",
		Builder:   b,
		Placement: scenariotest.Placement{"vm-g": "node:0"},
		Steps: []scenariotest.Step{
			// Both ratios TRUNCATE TO ZERO entries against max_entries
			// 65,536, because the reliever computes int(ratio * max).
			// Validation still holds (0 < low < high < 1).
			//
			// Zero bounds make eviction UNCONDITIONAL: with low = 0 the
			// victim count is the whole map, including the flow carrying
			// the driven traffic. DO NOT raise these above zero entries.
			// With a nonzero low watermark the active flow survives on a
			// quiet node, nothing is lost, and this scenario passes green
			// against an agent that still has the defect — which is
			// exactly what it did for five runs before lachesis#287.
			steps.RestartAgentStep{Node: "node:0", SetConfig: map[string]string{
				"gc.pressure_high_watermark": "0.000002",
				"gc.pressure_low_watermark":  "0.000001",
			}},
			steps.CaptureStep{},
			// Real traffic on a learned MAC: enough flows to sit above the
			// lowered high watermark, and enough bytes for the assertions
			// below to be meaningful.
			steps.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-g", To: scenariotest.ExternalTarget("8.8.8.8"), Bytes: 4 << 20, Proto: scenariotest.TCP},
			}},

			// The GC actually ran (pressure_relief reason only).
			steps.EvictionsGrewStep{Min: 1,
				Note: "fill crossed the lowered high watermark and the oldest flows were evicted"},
			// The bytes survived it: every evicted entry was flushed into
			// GlobalState before the kernel delete, so the tenant's total
			// still reflects the traffic.
			steps.AssertStep{Note: "bytes intact across eviction (flush before evict)",
				Expect: []scenariotest.Expect{
					{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 3 << 20},
				}},
			// ...and counted once. A flow re-created after its eviction
			// re-baselines from a fresh kernel counter; the delta math's
			// current<lastRaw branch must not re-add the flushed bytes.
			// The budget sits between one transfer and two: comfortably
			// above the ~4 MiB driven, well below the ~8.2 MiB a full
			// double-count would produce.
			steps.MaxGrowthStep{Tenant: "T1", Zone: "external",
				Budget: 6 << 20, Note: "evict-then-recreate counted once, not twice"},

			// Restore the node's real watermarks.
			steps.RestartAgentStep{Node: "node:0", RestoreConfig: true},
		},
	}
}
