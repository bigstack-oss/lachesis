package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// unresolvedLatebind exercises the UnresolvedBuffer's head-of-life
// (docs/architecture/data-structures.md#userspace-structures): a flow
// whose VM-side MAC the agent has not learned yet parks in the buffer
// (billed to no real tenant), and when the metadata later arrives it
// late-binds to the right tenant with a write-back that prevents the
// bytes being counted twice.
//
// Staging the "metadata not yet arrived" window deterministically needs
// agent control. vm-x is pinned to node:0 and deferred; the agent there
// is restarted under an alt config with Kafka OFF and a very long
// reconcile interval, so a VM booted afterward is NOT learned. vm-x's
// traffic then parks unresolved. A SIGHUP reload with a short reconcile
// interval resumes the metadata feed WITHOUT restarting (the buffer is
// in-memory — a restart would discard it); the next periodic reconcile
// learns vm-x and the following scrape late-binds. The whole
// park→resolve must fit inside the buffer TTL, so the resume config
// uses a short interval and the assertions poll.
//
// Nothing is pre-staged on that host: each phase names the keys it
// changes and the step derives the config from what the node already
// runs, so the final RestoreConfig returns the node's own original.
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
			scenariotest.RestartAgentStep{Node: "node:0", SetConfig: map[string]string{
				"kafka.enabled":      "false",
				"reconcile.interval": "600s",
			}},
			// Boot vm-x — its MAC won't enter node:0's map (no kafka kick,
			// reconcile far off).
			scenariotest.BootVMStep{VM: "vm-x"},
			scenariotest.CaptureStep{},
			// Drive without the MAC-learn gate (the MAC is deliberately
			// unlearned): first bytes park in the UnresolvedBuffer.
			scenariotest.DriveStep{SkipMACLearn: true, Flows: []scenariotest.Flow{
				{From: "vm-x", To: scenariotest.ExternalTarget("8.8.8.8"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			// Resume metadata: SIGHUP a short reconcile interval in. The
			// running agent's next reconcile learns vm-x; the buffer stays
			// intact (no restart).
			// Only the interval changes; kafka stays off from the restart
			// above, because SetConfig patches the config now in force.
			scenariotest.ReloadAgentStep{Node: "node:0", SetConfig: map[string]string{
				"reconcile.interval": "15s",
			}},

			// The buffered flow late-bound (was parked unresolved, then
			// re-attributed) — you cannot resolve what was never buffered.
			scenariotest.ResolvedGrewStep{Min: 1,
				Note: "buffered flow late-bound to its tenant within the TTL"},
			// It attributed to T1 (lower bound, polled against the drive's
			// baseline — the bytes surface only once the late-bind lands).
			// The zone is `miss`, not `external`: the kernel bakes dst_zone
			// at packet time from the SOURCE tenant, and while vm-x's MAC is
			// unlearned the source tenant is unknown, so the packet keys
			// miss. Late-binding re-attributes the TENANT (unknown→T1); the
			// zone stays whatever the kernel recorded. The billing property
			// this proves is that the bytes reach the right tenant instead
			// of being lost to "unknown".
			scenariotest.AssertStep{Note: "parked bytes re-attributed to the tenant", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "miss", Direction: "tx", MinBytes: 900 << 10},
			}},
			// ...exactly once: the write-back kept the same bytes from being
			// counted twice (growth since the pre-drive capture is ~one
			// transfer, not two).
			scenariotest.MaxGrowthStep{Tenant: "T1", Zone: "miss",
				Budget: 1500 << 10, Note: "re-attributed once — write-back prevented a double-count"},

			// Restore node:0's normal config (kafka on) for later runs.
			scenariotest.RestartAgentStep{Node: "node:0", RestoreConfig: true},
		},
	}
}
