package neutron

import (
	"strings"
	"testing"

	"github.com/bigstack-oss/lachesis/internal/bpf"
	"github.com/bigstack-oss/lachesis/internal/config"
	"github.com/bigstack-oss/lachesis/internal/tunables"
)

// The tunables store is a required dependency (the no-per-package-
// fallback rule), so a nil one is a construction error rather than a
// nil-deref at the first sync.
func TestNew_RequiresTunables(t *testing.T) {
	_, err := New(config.NeutronConfig{}, nil)
	if err == nil || !strings.Contains(err.Error(), "tunables store is required") {
		t.Fatalf("New(_, nil) error = %v, want a tunables-required error", err)
	}
}

// TestSyncResult_UsesConfiguredMaxHops closes the one link the resolver
// tests can't reach on their own: that the value [Neutron.Sync] hands
// the trie builder really comes from the injected tunables store, not a
// constant. resultFor is Sync's no-API-client half, so the assertion
// rides the production build path.
//
// A 5-router chain resolves other_tenant under the default limit and
// falls back to external once the store says 4 — same topology, only
// the knob differs, so nothing but the knob can explain the flip.
func TestSyncResult_UsesConfiguredMaxHops(t *testing.T) {
	// chainFixture's destination is unattached, so add an owner on the
	// last router: that makes the chain RESOLVE when the limit allows it.
	const chainLen = 5
	f := chainFixture(chainLen)
	f.addNetwork("net-T2", "T2", false, false)
	f.addSubnet("sub-T2", "net-T2", "T2", "10.99.0.0/16")
	f.addPort("p-dst", "net-T2", "T2", "network:router_interface", "R5",
		fip("sub-T2", "10.99.0.1"))
	// Every chainFixture router is admin and carries the same route, so
	// they all emit a row for this prefix. Re-tenant the SOURCE router so
	// exactly one row is the one whose traversal is under test.
	f.routers[0].ProjectID = "T1"
	snap := f.snapshot()

	// The route under test is R1's extraroute for 10.99.0.0/16.
	zoneOf := func(t *testing.T, maxHops int) bpf.ZoneCode {
		t.Helper()
		cfg := config.Defaults()
		cfg.Neutron.MaxStaticRouteHops = maxHops
		n, err := New(cfg.Neutron, tunables.New(cfg.Tunables()))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		for _, e := range n.resultFor(snap).Entries {
			if e.TenantID == "T1" && e.Prefix.String() == "10.99.0.0/16" {
				return e.Zone
			}
		}
		t.Fatalf("no trie row for T1 10.99.0.0/16 (maxHops=%d)", maxHops)
		return 0
	}

	// A chain of N routers costs N-1 nexthop follows to reach the owner
	// on the last one, so N-1 is exactly enough and N-2 is one short.
	// Both differ from the compiled-in default, so a Sync that ignored
	// the store would fail one of these whichever way it leaned.
	const enough, oneShort = chainLen - 1, chainLen - 2
	if got := zoneOf(t, enough); got != bpf.ZoneOtherTenant {
		t.Errorf("zone at limit %d = %v, want OTHER_TENANT (%d hops is exactly enough)",
			enough, got, enough)
	}
	if got := zoneOf(t, oneShort); got != bpf.ZoneExternal {
		t.Errorf("zone at limit %d = %v, want EXTERNAL (one hop short) — Sync is not reading the tunable",
			oneShort, got)
	}
}
