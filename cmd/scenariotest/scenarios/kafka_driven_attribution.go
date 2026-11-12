package scenarios

import (
	"time"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/steps"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// kafkaDrivenAttribution is the live regression for lachesis#327: a new
// VM's port event must kick a reconcile, so the agent learns the VM's
// MAC before its first traffic and that traffic bills to the VM's
// tenant instead of "unknown".
//
// The other scenarios cannot catch a dead kick: their MAC-learn gate
// waits up to 8 minutes, which the periodic reconcile also satisfies.
// Here node:0 restarts with a 600s reconcile interval and Kafka left
// on, so for the rest of the run only a Kafka kick can learn a VM
// booted there. The reconciler makes no pass at start (cold start
// already loaded Neutron) and Kafka is its only kicker besides SIGHUP.
//
// The unresolved-latebind scenario is the contrast: it turns Kafka off
// on purpose to make the first bytes park.
//
// SKIPs when agent_control is unconfigured — environment, not defect.
func kafkaDrivenAttribution() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.36.0/24", "10.0.36.1").
		VM("vm-x", "T1", "10.0.36.5")
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").
		Attach("sub-T1", "10.0.36.1").
		ExternalGateway("net-ext")

	const (
		flowBytes = 2 << 20
		// learnBound is half the 60s UnresolvedBuffer TTL and far
		// under the 600s interval: a kick learns the MAC in seconds,
		// and only a missed kick takes this long.
		learnBound = 30 * time.Second
		// ttlWait outlasts the 60s TTL plus a scrape, so anything vm-x
		// parked unresolved has folded to "unknown" before it is read.
		ttlWait = 90 * time.Second
	)
	return &scenariotest.Scenario{
		Name:      "kafka-driven-attribution",
		Desc:      "With the periodic reconcile 10 minutes off, only the Kafka port event can learn a new VM; its first traffic must bill to its tenant, not unknown (lachesis#327, step-scripted).",
		Builder:   b,
		Deferred:  []string{"vm-x"},
		Placement: scenariotest.Placement{"vm-x": "node:0"},
		Steps: []scenariotest.Step{
			steps.RestartAgentStep{Node: "node:0", SetConfig: map[string]string{
				"kafka.enabled":      "true",
				"reconcile.interval": "600s",
			}},
			steps.BootVMStep{VM: "vm-x"},
			// The reproduction row. BootVMStep returns after ACTIVE and the
			// tap attach; a kicked reconcile has bound the MAC by then.
			steps.AwaitPortBindingStep{VM: "vm-x", Port: "vm-x", Timeout: learnBound,
				Note: "Kafka port event kicked a reconcile that learned the new VM"},

			steps.CaptureStep{},
			// No MAC-learn gate: its 8-minute wait would hide a missed
			// kick. If the row above failed, these bytes park and expire,
			// which the next two checks show.
			steps.DriveStep{SkipMACLearn: true, Flows: []scenariotest.Flow{
				{From: "vm-x", To: scenariotest.ExternalTarget("8.8.8.8"), Bytes: flowBytes, Proto: scenariotest.TCP},
			}},
			// zone=external, not miss, proves the MAC was in
			// mac_tenant_map when the kernel keyed the packets.
			steps.AssertStep{Note: "first traffic billed to the tenant", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: flowBytes},
			}},
			steps.SleepStep{Duration: ttlWait},
			steps.MaxGrowthStep{Tenant: "unknown", Zone: "miss", Budget: flowBytes / 2,
				Note: "no first-traffic bytes parked and expired to unknown"},

			steps.RestartAgentStep{Node: "node:0", RestoreConfig: true},
		},
	}
}
