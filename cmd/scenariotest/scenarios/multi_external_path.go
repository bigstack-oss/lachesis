package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// multiExternalPath is the live regression for external-network
// attribution under the multi-path OpenStack shape: one VM port with
// TWO external paths (a second FIP, a second gatewayed router). The
// agent must (a) surface the topology on
// lachesis_neutron_anomalies{class="multi_external_path"} — retained
// as a cross-check even though per-flow attribution resolves it
// exactly, (b) bill each flow under the network that ACTUALLY carried
// it, resolved per flow from the peer router-interface MAC
// (docs/architecture/billing.md) — asserted separately for the default route AND for an
// in-guest route riding the second router — on the tenant AND
// per-server families, and (c) clear the anomaly without disturbing
// the series once the second path is removed.
//
// The second external network is CREATED (segmentless
// router:external): it allocates FIPs and takes a router gateway but
// carries no wire traffic — attribution is about Neutron topology, not
// packets. Its router attaches to the VM subnet at a NON-gateway IP,
// so the gateway-IP rule keeps SNAT attribution deterministic and the
// only ambiguity is the two FIPs, exactly the case under test.
//
// The second-router drive works even though the created network is
// segmentless: the ping payloads transmit at the tap (tx bytes count
// whether or not anything answers — the external-flow contract), and
// the peer MAC on those frames is r-ext2's interface, which is all the
// per-flow attribution needs.
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
	// Third router: NO external gateway — its interface MAC is
	// deliberately absent from the router map, so flows riding it are
	// the per-VM fallback tier's live case.
	b.Router("r-nogw", "T1").Attach("sub-T1", "10.0.11.253")

	return &scenariotest.Scenario{
		Name:               "multi-external-path",
		Desc:               "External attribution ladder: per-flow router-MAC, per-VM fallback, anomaly lifecycle (step-scripted).",
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

			// Default-route egress bills under the network that ACTUALLY
			// carried it — per flow, via r-T1's interface MAC — on both
			// families. (The pre-per-flow behavior happened to agree
			// here because the deterministic pick was the same network;
			// the second drive below is where the two models diverge.)
			scenariotest.CaptureStep{},
			scenariotest.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.ExternalTarget("8.8.8.8"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			scenariotest.AssertStep{Note: "default route bills under the carrying network", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 1 << 20,
					ExternalNetwork: "net-ext"},
				{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 1 << 20,
					ExternalNetwork: "net-ext", VM: "vm-a"},
			}},

			// Ride the SECOND router: an in-guest route steers a distinct
			// external prefix through r-ext2's interface — the platform
			// can't see the route, but the per-flow router-MAC
			// attribution must still bill these bytes under the created
			// network. This is the assertion the per-VM deterministic
			// pick could never pass: one VM, one window, two external
			// networks, each holding exactly its own flow's bytes.
			scenariotest.AddRouteStep{VM: "vm-a", CIDR: "8.8.9.0/24", Via: "10.0.11.254"},
			scenariotest.CaptureStep{},
			scenariotest.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.ExternalTarget("8.8.9.9"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			scenariotest.AssertStep{Note: "second-router flow bills under ITS carrying network", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 1 << 20,
					ExternalNetwork: "net-ext2"},
				{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 1 << 20,
					ExternalNetwork: "net-ext2", VM: "vm-a"},
			}},
			// Flow-granular gate: the driven bytes demonstrably sit on
			// a flow whose peer IS r-ext2's interface — labels alone
			// can't prove which router carried them.
			scenariotest.AssertFlowPeerStep{Router: "r-ext2", Via: "10.0.11.254", Zone: "external",
				MinBytes: 1 << 20, Note: "steered bytes observed on r-ext2's interface"},

			// Tier-2 fallback: ride the gateway-less router. Its
			// interface MAC misses the router map (no gateway →
			// nothing to attribute per flow), so these external-zone
			// bytes must fall back to the VM's OWN attribution — the
			// provider network, via its FIP / the gateway-IP rule.
			// Catches a broken fallback (label "none") and a router map
			// that wrongly includes gateway-less interfaces.
			scenariotest.AddRouteStep{VM: "vm-a", CIDR: "8.8.10.0/24", Via: "10.0.11.253"},
			scenariotest.CaptureStep{},
			scenariotest.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.ExternalTarget("8.8.10.9"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			scenariotest.AssertStep{Note: "gateway-less router falls back to the per-VM attribution", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 1 << 20,
					ExternalNetwork: "net-ext"},
				{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 1 << 20,
					ExternalNetwork: "net-ext", VM: "vm-a"},
			}},
			// The tier-2 discrimination gate: the fallback-labeled bytes
			// sit on a flow whose peer is the GATEWAY-LESS interface —
			// tier 1 could produce the same label for default-route
			// traffic, so only this peer check proves the fallback ran.
			scenariotest.AssertFlowPeerStep{Router: "r-nogw", Via: "10.0.11.253", Zone: "external",
				MinBytes: 1 << 20, Note: "fallback bytes observed on the gateway-less interface"},

			// Remove the second path: anomaly clears, series undisturbed.
			scenariotest.DeleteFIPStep{VM: "vm-a", Network: "net-ext2"},
			scenariotest.AssertAnomalyStep{Class: "multi_external_path", Min: 0, Max: 0,
				Note: "ambiguity clears after FIP removal"},
			scenariotest.MonotoneStep{Tenant: "T1", Note: "series stable through FIP churn"},
		},
	}
}
