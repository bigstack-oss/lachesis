package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/steps"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// unresolvedLatebind exercises the UnresolvedBuffer's head-of-life: a
// flow whose VM MAC is not yet known parks in the buffer, then
// late-binds to the right tenant with the write-back that stops the
// bytes counting twice.
//
// Staging that window needs agent control: the node's agent restarts
// with Kafka off and a long reconcile interval, so a VM booted after is
// NOT learned and its traffic parks. A SIGHUP with a short interval
// then resumes the feed WITHOUT restarting — a restart would discard
// the in-memory buffer. The whole park→resolve must fit inside the TTL.
//
// docs/architecture/data-structures.md#userspace-structures
func unresolvedLatebind() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.51.0/24", "10.0.51.1").
		VM("vm-x", "T1", "10.0.51.5")
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").
		Attach("sub-T1", "10.0.51.1").
		ExternalGateway("net-ext")
	return &scenariotest.Scenario{
		Name:      "unresolved-latebind",
		Desc:      "Unknown attribution then late-bind when metadata arrives (no double-count).",
		Builder:   b,
		Deferred:  []string{"vm-x"},
		Placement: scenariotest.Placement{"vm-x": "node:0"},
		Steps: []scenariotest.Step{
			// Suppress metadata on node:0: kafka off + long reconcile, so a
			// VM booted next is not learned.
			steps.RestartAgentStep{Node: "node:0", SetConfig: map[string]string{
				"kafka.enabled":      "false",
				"reconcile.interval": "600s",
			}},
			// Boot vm-x — its MAC won't enter node:0's map (no kafka kick,
			// reconcile far off).
			steps.BootVMStep{VM: "vm-x"},
			steps.CaptureStep{},
			// Drive without the MAC-learn gate (the MAC is deliberately
			// unlearned): first bytes park in the UnresolvedBuffer.
			steps.DriveStep{SkipMACLearn: true, Flows: []scenariotest.Flow{
				{From: "vm-x", To: scenariotest.ExternalTarget("8.8.8.8"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			// Resume metadata: SIGHUP a short reconcile interval in. The
			// running agent's next reconcile learns vm-x; the buffer stays
			// intact (no restart).
			// Only the interval changes; kafka stays off from the restart
			// above, because SetConfig patches the config now in force.
			steps.ReloadAgentStep{Node: "node:0", SetConfig: map[string]string{
				"reconcile.interval": "15s",
			}},

			// The buffered flow late-bound (was parked unresolved, then
			// re-attributed) — you cannot resolve what was never buffered.
			steps.ResolvedGrewStep{Min: 1,
				Note: "buffered flow late-bound to its tenant within the TTL"},
			// The zone is `miss`, not `external`: the kernel bakes
			// dst_zone at packet time from the SOURCE tenant, and while
			// vm-x's MAC is unlearned that is unknown. Late-binding
			// re-attributes the TENANT only; the zone stays as recorded.
			// What this proves is that the bytes reach the right tenant
			// instead of being lost to "unknown".
			steps.AssertStep{Note: "parked bytes re-attributed to the tenant", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "miss", Direction: "tx", MinBytes: 900 << 10},
			}},
			// ...exactly once: the write-back kept the same bytes from being
			// counted twice (growth since the pre-drive capture is ~one
			// transfer, not two).
			steps.MaxGrowthStep{Tenant: "T1", Zone: "miss",
				Budget: 1500 << 10, Note: "re-attributed once — write-back prevented a double-count"},

			// Restore node:0's normal config (kafka on) for later runs.
			steps.RestartAgentStep{Node: "node:0", RestoreConfig: true},
		},
	}
}
