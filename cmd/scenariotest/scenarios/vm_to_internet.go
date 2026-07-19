package scenarios

import (
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// vmToInternet exercises the external zone. One VM on an internal
// subnet behind a router whose external gateway is the real provider
// external network; the VM egresses to a public IP, which misses every
// specific trie prefix and matches the (T1, 0.0.0.0/0) → EXTERNAL
// catchall (docs/architecture/trie-construction.md#the-five-step-algorithm Step 1, scenarios_test.go Scenario D).
//
// The DSL ExternalNetwork is a marker: realize binds the router's
// external gateway to the configured provider external network
// (prerequisites.external_network_name) rather than creating one, so
// egress actually routes out via SNAT. The drive slice pulls a known
// large public object to generate the bytes.
func vmToInternet() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.1.0/24", "10.0.1.1").
		VM("vm-a", "T1", "10.0.1.5")
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").
		Attach("sub-T1", "10.0.1.1").
		ExternalGateway("net-ext")
	return &scenariotest.Scenario{
		Name:    "vm-to-internet",
		Desc:    "VM egressing to a public IP via SNAT. External zone.",
		Builder: b,
		Flows: []scenariotest.Flow{
			{From: "vm-a", To: scenariotest.ExternalTarget("8.8.8.8"), Bytes: 1 << 20, Proto: scenariotest.TCP},
		},
		Expect: []scenariotest.Expect{
			{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 1 << 20},
			// The same egress must carry the provider network's
			// external_network label ("net-ext" resolves to the bound
			// provider network, like TenantID → UUID) — pinning the
			// zone-gated label live (docs/architecture/metrics.md)...
			{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 1 << 20,
				ExternalNetwork: "net-ext"},
			// ...and the mortal per-server family must attribute it to
			// the driving VM's Nova UUID on the same tuple (docs/architecture/billing.md).
			{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 1 << 20,
				ExternalNetwork: "net-ext", VM: "vm-a"},
		},
	}
}
