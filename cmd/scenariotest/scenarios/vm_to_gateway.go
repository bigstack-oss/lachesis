package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// vmToGateway exercises the infra zone. One VM on a routed subnet; the
// router interface and the Nova metadata service (169.254.169.254) are
// both /32 INFRA rows (docs/architecture/trie-construction.md#the-five-step-algorithm Step 4). The flow targets the
// metadata service, which — unlike the bare gateway — runs a real
// HTTP responder, so infra traffic is generatable.
//
// Infra is not a bulk-transfer zone: the drive slice repeats metadata
// probes (small HTTP responses) until the 1 KiB MinBytes lower bound
// clears — a single request's headers alone would not. Driving and
// the exact probe land with the drive slice.
func vmToGateway() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.1.0/24", "10.0.1.1").
		VM("vm-a", "T1", "10.0.1.5")
	// A router on the subnet makes 10.0.1.1 an INFRA /32 too, matching
	// the canonical infra topology (scenarios_test.go Scenario B). The
	// external gateway exists for floating-IP reachability (Neutron
	// requires a gatewayed router on the VM's subnet to associate a
	// FIP); it does not change the infra classification.
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").
		Attach("sub-T1", "10.0.1.1").
		ExternalGateway("net-ext")
	return &scenariotest.Scenario{
		Name:    "vm-to-gateway",
		Desc:    "VM probing the metadata service / gateway. Infra zone.",
		Builder: b,
		Flows: []scenariotest.Flow{
			{From: "vm-a", To: scenariotest.ExternalTarget("169.254.169.254"), Bytes: 1 << 10, Proto: scenariotest.TCP},
		},
		Expect: []scenariotest.Expect{
			{TenantID: "T1", Zone: "infra", Direction: "tx", MinBytes: 1 << 10},
			// The metadata endpoint answers ICMP (the ovnmeta namespace
			// carries 169.254.169.254 on a real interface), so the sized
			// echo replies make infra/rx drivable too — the return leg of
			// the same /32 INFRA row, previously asserted tx-only.
			{TenantID: "T1", Zone: "infra", Direction: "rx", MinBytes: 1 << 10},
		},
	}
}
