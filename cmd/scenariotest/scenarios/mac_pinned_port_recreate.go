package scenarios

import (
	"time"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// macPinnedPortRecreate reproduces the stale-port_id reconcile miss: a
// port is deleted and a NEW port with the SAME MAC and identical
// attribution (tenant, server, external network) replaces it while the
// agent is not receiving Kafka events — so the next reconcile diff sees
// old-live vs new-desired directly. The change detection must treat the
// port_id change as an attribution change and rebind; an agent that
// compares only tenant/server/ext keeps the DEAD port's metadata and
// the port tier mislabels all subsequent traffic under it.
//
// The Kafka outage is modeled honestly: with events flowing, a delete
// is ghost-marked and the recreate takes the resurrection path, which
// refreshes the binding — the miss is only reachable in the
// reconcile-diff path, i.e. when events were lost (a first-class
// degraded mode: "metadata staleness bounded by the periodic
// reconcile"). RestartAgentStep derives a kafka-off config for the
// scenario and restores the original at the end, so it SKIPs cleanly on
// clusters without agent_control configured.
//
// Timing caveat: if a reconcile pass lands in the ~2s between the
// delete and the recreate, the MAC is ghost-marked and the recreate
// resurrects with a refreshed binding — the run then passes without
// exercising the miss. With the test configs' 30s reconcile interval
// that window is small; re-run on a suspiciously green first row.
//
// Expected RED on an agent without the port_id change detection (both
// the binding row and the port-series row), GREEN with it.
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
			// Model the Kafka outage for the node under test. The
			// kafka-off config is staged beside the agent config on the
			// agent hosts (operator contract, like agent_control itself).
			scenariotest.RestartAgentStep{Node: "node:0", SetConfig: map[string]string{
				"kafka.enabled": "false",
			}},

			// Baseline NIC: fresh port, traffic, and the port tier
			// attributes it to nic2's id (sanity — green everywhere).
			scenariotest.AttachPortStep{VM: "vm-a", ID: "vm-a-nic2",
				Network: "net-T1b", Subnet: "sub-T1b", IP: "10.0.29.9"},
			scenariotest.ConfigureNICStep{VM: "vm-a", Dev: "eth1", CIDR: "10.0.29.9/24"},
			scenariotest.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			scenariotest.AssertStep{Note: "baseline drive", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "same_tenant", Direction: "tx", VM: "vm-a", MinBytes: 1 << 20},
			}},
			scenariotest.PortSeriesStep{VM: "vm-a", Port: "vm-a-nic2", MinBytes: 1 << 20,
				Note: "baseline traffic attributes to nic2's port_id"},

			// The swap the agent can't see: delete nic2 (its MAC is
			// recorded), immediately recreate as nic3 pinning the SAME
			// MAC — same server, same tenant, same network.
			scenariotest.DetachPortStep{VM: "vm-a", Port: "vm-a-nic2", Delete: true},
			scenariotest.AttachPortStep{VM: "vm-a", ID: "vm-a-nic3",
				Network: "net-T1b", Subnet: "sub-T1b", IP: "10.0.29.9", MACFrom: "vm-a-nic2"},
			scenariotest.ConfigureNICStep{VM: "vm-a", Dev: "eth1", CIDR: "10.0.29.9/24"},

			// THE reproduction row: the reconcile must rebind the MAC to
			// nic3's port id. An agent missing the port_id comparison
			// keeps the dead port's binding forever — timeout = RED.
			scenariotest.AwaitPortBindingStep{VM: "vm-a", Port: "vm-a-nic3", Timeout: 2 * time.Minute,
				Note: "reconcile rebinds the reused MAC to the reborn port"},

			// And the observable consequence at the metric layer: driven
			// traffic lands under nic3's port_id, not the dead nic2's.
			scenariotest.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			scenariotest.PortSeriesStep{VM: "vm-a", Port: "vm-a-nic3", MinBytes: 1 << 20,
				Note: "rebirth traffic attributes to the NEW port_id"},

			// The coarser tiers never flinch either way — contrast rows.
			scenariotest.MonotoneStep{Tenant: "T1", Note: "tenant plane invariant throughout"},

			// Restore the node's real config (RestartAgentStep backed it
			// up beside the config on the swap above).
			scenariotest.RestartAgentStep{Node: "node:0", RestoreConfig: true},
		},
	}
}
