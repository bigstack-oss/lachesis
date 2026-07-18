package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// crossHostSameTenant is the canonical two-node scenario (DESIGN §7
// case J): the same twovms topology, but the VMs are pinned to
// different hypervisors via placement slots, so the flow crosses the
// Geneve overlay. Each side is asserted on its own node's agent —
// tx at the sender's tap (pre-encap), rx at the receiver's tap
// (post-decap) — which the cluster-wide sum could never distinguish
// from a same-host run. On a single-node cluster the scenario reports
// SKIPPED, the first live exercise of the node-count gate.
//
// The router + external gateway exist purely for floating-IP
// reachability, exactly as in twovms-same-tenant.
func crossHostSameTenant() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.14.0/24", "10.0.14.1").
		VM("vm-a", "T1", "10.0.14.5").
		VM("vm-b", "T1", "10.0.14.6")
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").
		Attach("sub-T1", "10.0.14.1").
		ExternalGateway("net-ext")
	return &scenariotest.Scenario{
		Name:    "cross-host-same-tenant",
		Desc:    "Two VMs, same tenant, pinned to different nodes; per-node tx/rx across the Geneve overlay.",
		Builder: b,
		Placement: scenariotest.Placement{
			"vm-a": "node:0",
			"vm-b": "node:1",
		},
		Flows: []scenariotest.Flow{
			{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP},
		},
		Expect: []scenariotest.Expect{
			{TenantID: "T1", Zone: "same_tenant", Direction: "tx", Node: "node:0", MinBytes: 1 << 20},
			{TenantID: "T1", Zone: "same_tenant", Direction: "rx", Node: "node:1", MinBytes: 1 << 20},
		},
	}
}
