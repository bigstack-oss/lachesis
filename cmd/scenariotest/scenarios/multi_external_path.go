package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// multiExternalPath is the live regression for external-network
// attribution under the genuinely-ambiguous OpenStack shape: one VM
// port holding floating IPs from TWO external networks (DESIGN §11.5's
// documented first-cut limitation). The agent must (a) surface the
// condition on lachesis_neutron_anomalies{class="multi_external_path"},
// (b) keep billing the VM's real egress under the deterministic pick —
// which here is the provider network, both lexicographically and in
// fact — on the tenant AND per-server families, and (c) clear the
// anomaly without disturbing the series once the second path is
// removed.
//
// The second external network is CREATED (segmentless
// router:external): it allocates FIPs and takes a router gateway but
// carries no wire traffic — attribution is about Neutron topology, not
// packets. Its router attaches to the VM subnet at a NON-gateway IP,
// so the gateway-IP rule keeps SNAT attribution deterministic and the
// only ambiguity is the two FIPs, exactly the case under test.
//
// The deterministic pick is the lexicographically smallest label:
// the provider network's name (e.g. "Public") sorts before the created
// network's mangled "scenariotest-…" name on any case-sensitive
// comparison of an uppercase-initial provider name — and if a
// deployment's provider net sorted after, the assert below would fail
// loudly rather than silently, which is the point of pinning it.
func multiExternalPath() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.11.0/24", "10.0.11.1").
		VM("vm-a", "T1", "10.0.11.5")
	b.ExternalNetwork("net-ext", "admin")
	// The created second external path: segmentless router:external
	// network + its FIP-allocation subnet.
	b.ExternalNetwork("net-ext2", "T1").
		Subnet("sub-ext2", "172.24.99.0/24", "172.24.99.1")
	b.Router("r-T1", "T1").Attach("sub-T1", "10.0.11.1").ExternalGateway("net-ext")
	// Second router: gateway on the created external, interface on the
	// VM subnet at a NON-gateway IP (r-T1 owns 10.0.11.1) — required by
	// Neutron for FIP reachability, invisible to SNAT attribution.
	b.Router("r-ext2", "T1").Attach("sub-T1", "10.0.11.254").ExternalGateway("net-ext2")

	return &scenariotest.Scenario{
		Name:               "multi-external-path",
		Desc:               "Multi-FIP external attribution: anomaly surfaced, billing pinned to the deterministic pick (step-scripted).",
		Builder:            b,
		CreateExternalNets: []string{"net-ext2"},
		Steps: []scenariotest.Step{
			// Unambiguous baseline: one FIP (the provider SSH path).
			scenariotest.AssertAnomalyStep{Class: "multi_external_path", Min: 0, Max: 0,
				Note: "single external path — no anomaly"},

			// Second FIP from the created external → genuinely ambiguous.
			scenariotest.AssociateFIPStep{VM: "vm-a", Network: "net-ext2"},
			scenariotest.AssertAnomalyStep{Class: "multi_external_path", Min: 1, Max: 1,
				Note: "second FIP surfaces the ambiguity"},

			// Real egress still bills, on the deterministic pick, on
			// both families.
			scenariotest.CaptureStep{},
			scenariotest.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.ExternalTarget("8.8.8.8"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			scenariotest.AssertStep{Note: "billing under the deterministic pick", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 1 << 20,
					ExternalNetwork: "net-ext"},
				{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 1 << 20,
					ExternalNetwork: "net-ext", VM: "vm-a"},
			}},

			// Remove the second path: anomaly clears, series undisturbed.
			scenariotest.DeleteFIPStep{VM: "vm-a", Network: "net-ext2"},
			scenariotest.AssertAnomalyStep{Class: "multi_external_path", Min: 0, Max: 0,
				Note: "ambiguity clears after FIP removal"},
			scenariotest.MonotoneStep{Tenant: "T1", Note: "series stable through FIP churn"},
		},
	}
}
