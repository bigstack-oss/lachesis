package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// gcPressureRelief exercises pressure-relief GC end to end: the
// telemetry_map crossing its fill high watermark, the eviction of the
// oldest flows, and — the property that matters for billing — the
// "flush before evict" ordering that keeps a tenant's bytes intact
// across the eviction (docs/architecture/data-structures.md#kernel-side-bpf-maps).
//
// Reaching the real 80% watermark would need >52,000 concurrent flows
// (max_entries 65,536), which no single VM can produce — one VM is one
// (MAC-pair, direction, zone) key. Rather than manufacture flows, this
// scenario moves the trigger to the traffic: the watermarks are
// hot-reloadable tunables (docs/operations/runtime.md), so node:0's
// agent is restarted under an alt config whose watermarks are a few
// entries, and the VM's own handful of real flows then exceeds them.
// That drives the genuine code path on genuine resolved flows.
//
// PRE-STAGED on node:0's agent host: /root/agent-c36-gclow.yaml — the
// node's normal config with tiny gc watermarks, e.g.
//
//	gc:
//	  pressure_high_watermark: 0.0001   # ~6 of 65,536 entries
//	  pressure_low_watermark:  0.00005  # ~3 entries
//
// The opening RestartAgentStep backs up the real config, and the closing
// one restores it, so the node is left as found.
//
// Debugging note: if the exposed bytes come up short, check
// lachesis_unresolved_buffer_evictions_total{reason="lru"} before
// suspecting the GC. Flows whose VM MAC the agent has not learned park
// in the UnresolvedBuffer, which is capped at 10,000 and DELETES the
// kernel telemetry_map entry when it evicts — a second, unrelated path
// that removes map entries and is easily mistaken for GC eviction.
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
			// Lower the watermarks so real flows trip the trigger. This
			// backs up the node's real config for the final restore.
			scenariotest.RestartAgentStep{Node: "node:0", AltConfig: "/root/agent-c36-gclow.yaml"},
			scenariotest.CaptureStep{},
			// Real traffic on a learned MAC: enough flows to sit above the
			// lowered high watermark, and enough bytes for the assertions
			// below to be meaningful.
			scenariotest.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-g", To: scenariotest.ExternalTarget("8.8.8.8"), Bytes: 4 << 20, Proto: scenariotest.TCP},
			}},

			// The GC actually ran (pressure_relief reason only).
			scenariotest.EvictionsGrewStep{Min: 1,
				Note: "fill crossed the lowered high watermark and the oldest flows were evicted"},
			// The bytes survived it: every evicted entry was flushed into
			// GlobalState before the kernel delete, so the tenant's total
			// still reflects the traffic.
			scenariotest.AssertStep{Note: "bytes intact across eviction (flush before evict)",
				Expect: []scenariotest.Expect{
					{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 3 << 20},
				}},
			// ...and counted once. A flow re-created after its eviction
			// re-baselines from a fresh kernel counter; the delta math's
			// current<lastRaw branch must not re-add the flushed bytes.
			scenariotest.MaxGrowthStep{Tenant: "T1", Zone: "external",
				Budget: 8 << 20, Note: "evict-then-recreate counted once, not twice"},

			// Restore the node's real watermarks.
			scenariotest.RestartAgentStep{Node: "node:0", RestoreConfig: true},
		},
	}
}
