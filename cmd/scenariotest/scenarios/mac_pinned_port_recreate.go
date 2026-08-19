package scenarios

import (
	"time"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/steps"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// macPinnedPortRecreate reproduces the stale-port_id reconcile miss: a
// port is replaced by a NEW one with the SAME MAC and identical
// attribution while Kafka is off, so the next reconcile diff sees
// old-live vs new-desired directly. Change detection must treat the
// port_id change as an attribution change; an agent comparing only
// tenant/server/ext keeps the DEAD port's metadata and mislabels
// everything after.
//
// The Kafka outage is modelled honestly — with events flowing the
// delete ghost-marks and the recreate resurrects, refreshing the
// binding, so the miss is reachable only via the reconcile-diff path.
//
// Timing caveat: a reconcile landing in the ~2s between delete and
// recreate makes the run pass without exercising the miss. Re-run on a
// suspiciously green first row.
func macPinnedPortRecreate() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.28.0/24", "10.0.28.1").
		VM("vm-a", "T1", "10.0.28.5")
	b.Network("net-T1b", "T1").
		Subnet("sub-T1b", "10.0.29.0/24", "10.0.29.1").
		VM("vm-b", "T1", "10.0.29.5")
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").
		Attach("sub-T1", "10.0.28.1").
		Attach("sub-T1b", "10.0.29.1").
		ExternalGateway("net-ext")

	return &scenariotest.Scenario{
		Name:    "mac-pinned-port-recreate",
		Desc:    "Delete a NIC and recreate it with the SAME MAC under a Kafka outage; the binding and port tier must move to the new port_id (step-scripted).",
		Builder: b,
		Placement: scenariotest.Placement{
			"vm-a": "node:0",
			"vm-b": "node:0",
		},
		Steps: []scenariotest.Step{
			// Model the Kafka outage for the node under test. The kafka-off
			// config is derived from the node's own — nothing is staged on
			// the agent hosts — and the closing RestoreConfig puts the
			// original back.
			steps.RestartAgentStep{Node: "node:0", SetConfig: map[string]string{
				"kafka.enabled": "false",
			}},

			// Baseline NIC: fresh port, traffic, and the port tier
			// attributes it to nic2's id (sanity — green everywhere).
			steps.AttachPortStep{VM: "vm-a", ID: "vm-a-nic2",
				Network: "net-T1b", Subnet: "sub-T1b", IP: "10.0.29.9"},
			steps.ConfigureNICStep{VM: "vm-a", Dev: "eth1", CIDR: "10.0.29.9/24"},
			steps.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			steps.AssertStep{Note: "baseline drive", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "same_tenant", Direction: "tx", VM: "vm-a", MinBytes: 1 << 20},
			}},
			steps.PortSeriesStep{VM: "vm-a", Port: "vm-a-nic2", MinBytes: 1 << 20,
				Note: "baseline traffic attributes to nic2's port_id"},

			// The swap the agent can't see: delete nic2 (its MAC is
			// recorded), immediately recreate as nic3 pinning the SAME
			// MAC — same server, same tenant, same network.
			steps.DetachPortStep{VM: "vm-a", Port: "vm-a-nic2", Delete: true},
			steps.AttachPortStep{VM: "vm-a", ID: "vm-a-nic3",
				Network: "net-T1b", Subnet: "sub-T1b", IP: "10.0.29.9", MACFrom: "vm-a-nic2"},
			steps.ConfigureNICStep{VM: "vm-a", Dev: "eth1", CIDR: "10.0.29.9/24"},

			// THE reproduction row: the reconcile must rebind the MAC to
			// nic3's port id. An agent missing the port_id comparison
			// keeps the dead port's binding forever — timeout = RED.
			steps.AwaitPortBindingStep{VM: "vm-a", Port: "vm-a-nic3", Timeout: 2 * time.Minute,
				Note: "reconcile rebinds the reused MAC to the reborn port"},

			// And the observable consequence at the metric layer: driven
			// traffic lands under nic3's port_id, not the dead nic2's.
			steps.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			steps.PortSeriesStep{VM: "vm-a", Port: "vm-a-nic3", MinBytes: 1 << 20,
				Note: "rebirth traffic attributes to the NEW port_id"},

			// The coarser tiers never flinch either way — contrast rows.
			steps.MonotoneStep{Tenant: "T1", Note: "tenant plane invariant throughout"},

			// Restore the node's real config (RestartAgentStep backed it
			// up beside the config on the swap above).
			steps.RestartAgentStep{Node: "node:0", RestoreConfig: true},
		},
	}
}
