package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// octaviaLBAttribution proves the Octavia billing model end to end
// (docs/architecture/octavia.md, Scenario F): an Amphora's bytes bill the
// load balancer's owner rather than the Octavia service project, Segment 2
// zones infra, and Segment 1 keeps classifying by the client's location.
//
// Topology — T1 owns the load balancer, T2 provides a cross-tenant client:
//
//	                      ┌── vm-back-a  10.0.1.11  (VIP subnet)
//	vm-client-t1 ─┐       ├── vm-back-b  10.0.1.12  (VIP subnet)
//	              ├─ VIP ─┤
//	vm-client-t2 ─┘       └── vm-back-c  10.0.2.10  (OTHER subnet)
//
// Three deliberate shapes:
//
//   - MULTI-BACKEND across two subnets. vm-back-c forces Octavia to plug
//     every Amphora into net-back — a port Nova mints with no Octavia
//     marker and no allowed-address pair, which is exactly why the
//     attribution join keys on the Nova instance UUID rather than the
//     Amphora's vrrp_port_id. Its address enters amphora_base_ip too, so
//     Segment 2 to a routed member still zones infra.
//   - MULTI-AMPHORA. ACTIVE_STANDBY yields a MASTER/BACKUP pair, each with
//     its own base address. Whichever one VRRP makes active, Segment 2 must
//     still zone infra and Segment 1 must still not. Needs an Octavia flavor
//     carrying loadbalancer_topology=ACTIVE_STANDBY; a cluster without
//     prerequisites.lb_flavor_name staged reports SKIPPED, never a failure.
//   - INTERNAL CLIENTS FROM TWO TENANTS. Both dial the VIP, so both drive
//     Segment 1 — and the zones must differ: same_tenant for T1's client,
//     other_tenant for T2's. That asymmetry is the regression this scenario
//     exists to hold. An earlier build zoned any L2-adjacent flow touching
//     an Amphora as infra, which made a cross-tenant client's request free
//     in both directions; the base-address test is what separates them.
//
// Byte expectations are MinBytes, not equalities. HAProxy terminates the
// client's connection and opens a fresh one to a member, so one declared
// flow legitimately appears on two connections — the payload is counted
// once per segment, not once in total.
//
//   - AN EXTERNAL CLIENT. The third flow dials the load balancer's FLOATING
//     address rather than its VIP. OVN DNATs it before the Amphora's tap, so
//     the Amphora's peer on the wire is a router interface — absent from
//     mac_tenant_map — and the flow never reaches the Amphora branch at all,
//     classifying EXTERNAL through the trie catchall. A different code path
//     from the two internal clients, and the one that actually bills.
func octaviaLBAttribution() *scenariotest.Scenario {
	b := scenario.New()
	// The member subnet is declared first: LoadBalancer().Member() resolves
	// the subnet it plugs the Amphorae into.
	b.Network("net-back", "T1").
		Subnet("sub-back", "10.0.2.0/24", "10.0.2.1").
		VM("vm-back-c", "T1", "10.0.2.10")
	// The VIP network is SHARED so T2 can legitimately place a client on
	// it — Neutron refuses a boot on another tenant's private network.
	// Sharing does not blur the assertion: client-to-VIP is direct L2
	// (the Amphora's MAC is in mac_tenant_map), so the classifier
	// compares tenants outright and never consults the trie's SHARED row.
	b.SharedNetwork("net-T1", "T1").
		Subnet("sub-T1", "10.0.1.0/24", "10.0.1.1").
		VM("vm-client-t1", "T1", "10.0.1.5").
		VM("vm-client-t2", "T2", "10.0.1.6").
		VM("vm-back-a", "T1", "10.0.1.11").
		VM("vm-back-b", "T1", "10.0.1.12").
		LoadBalancer("lb1", "T1", "service", "10.0.1.50", scenario.ActiveStandby).
		Member("sub-T1", "10.0.1.11", 8080).
		Member("sub-T1", "10.0.1.12", 8080).
		Member("sub-back", "10.0.2.10", 8080).
		Done()
	// A gatewayed router per tenant: the harness fronts every VM with a
	// floating IP to drive traffic, and Neutron only associates one through
	// a router with an external gateway on the VM's subnet.
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").
		Attach("sub-T1", "10.0.1.1").
		Attach("sub-back", "10.0.2.1").
		ExternalGateway("net-ext")

	return &scenariotest.Scenario{
		Name:    "octavia-lb-attribution",
		Desc:    "Octavia LB: Amphora bytes bill the LB owner, Segment 2 is infra, Segment 1 keeps the client's zone.",
		Builder: b,
		Flows: []scenariotest.Flow{
			// Segment 1 from the owner's own tenant.
			{From: "vm-client-t1", To: scenariotest.VIPTarget("lb1"), Bytes: 4 << 20, Proto: scenariotest.TCP},
			// Segment 1 from another tenant — the revenue case.
			{From: "vm-client-t2", To: scenariotest.VIPTarget("lb1"), Bytes: 4 << 20, Proto: scenariotest.TCP},
			// Segment 1 from outside: dials the load balancer's floating
			// address, so the Amphora sees a routed peer and the flow takes
			// the trie path to EXTERNAL.
			{From: "vm-client-t1", To: scenariotest.LBFIPTarget("lb1"), Bytes: 4 << 20, Proto: scenariotest.TCP},
		},
		Expect: []scenariotest.Expect{
			// Segment 1, T1's client: same_tenant at both taps. The
			// Amphora's tap bills T1 because its ports were re-attributed
			// from the service project — the whole point of the feature.
			{TenantID: "T1", Zone: "same_tenant", Direction: "tx", MinBytes: 4 << 20},
			{TenantID: "T1", Zone: "same_tenant", Direction: "rx", MinBytes: 4 << 20},

			// Segment 1, T2's client: billed per side at the internal rate.
			// If this reads 0 the classifier has swallowed Segment 1 into
			// infra and cross-tenant load-balancer traffic is free.
			{TenantID: "T2", Zone: "other_tenant", Direction: "tx", MinBytes: 4 << 20},
			{TenantID: "T1", Zone: "other_tenant", Direction: "rx", MinBytes: 4 << 20},

			// Segment 1 over the floating address: external at both taps,
			// billed to the load balancer's owner. Zero here would mean an
			// internet-facing load balancer bills nobody.
			{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 4 << 20},
			{TenantID: "T1", Zone: "external", Direction: "rx", MinBytes: 4 << 20},

			// Segment 2, Amphora to backend: infra at both taps, billed to
			// T1 (the Amphora's side) and to T1 (the backends' own project,
			// which happens to be the same here). Two clients' worth of
			// payload crosses it, but round-robin splits it across three
			// members, so only the aggregate is asserted.
			{TenantID: "T1", Zone: "infra", Direction: "tx", MinBytes: 1 << 20},
			{TenantID: "T1", Zone: "infra", Direction: "rx", MinBytes: 1 << 20},
		},
	}
}
