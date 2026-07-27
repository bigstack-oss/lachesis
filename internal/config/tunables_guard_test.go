package config

import (
	"reflect"
	"testing"
	"time"

	"github.com/bigstack-oss/lachesis/internal/tunables"
)

// TestTunablesProjection_CoversEveryField is the registration guard
// (the k8s config-roundtrip pattern, and this repo's metric-naming
// guard precedent): adding a field to tunables.Values requires exactly
// two manual acts — a `knob` tag and a line in Config.Tunables — and
// forgetting either fails HERE with the field's name, instead of
// shipping a knob that silently never hot-reloads or reloads unlogged.
//
// Mechanism: perturb every tunable config field away from its default,
// project, and require every Values field to differ from the
// zero-config projection. A field missing from the projection stays at
// its Defaults()-independent zero and is caught by name.
func TestTunablesProjection_CoversEveryField(t *testing.T) {
	perturbed := Defaults()
	perturbed.GC.GhostGrace = 71 * time.Second
	perturbed.GC.GhostSweepInterval = 72 * time.Second
	perturbed.GC.PressureHighWatermark = 0.73
	perturbed.GC.PressureLowWatermark = 0.37
	perturbed.GC.PressureMaxPerPass = 74
	perturbed.Reconcile.Interval = 75 * time.Second
	perturbed.Scrape.Interval = 76 * time.Second
	perturbed.WAL.FlushInterval = 77 * time.Second
	perturbed.Unresolved.Cap = 78
	perturbed.Unresolved.TTL = 79 * time.Second
	perturbed.Neutron.MaxStaticRouteHops = 8

	base := Defaults().Tunables()
	got := perturbed.Tunables()

	vt := reflect.TypeOf(got)
	bv, gv := reflect.ValueOf(base), reflect.ValueOf(got)
	for i := 0; i < vt.NumField(); i++ {
		f := vt.Field(i)
		if f.Tag.Get("knob") == "" {
			t.Errorf("tunables.Values.%s has no `knob` tag — reload logging cannot name it", f.Name)
		}
		if bv.Field(i).Interface() == gv.Field(i).Interface() {
			t.Errorf("tunables.Values.%s did not change under a fully-perturbed config — missing from Config.Tunables()? (or this test's perturbation list)", f.Name)
		}
	}
}

// TestTunablesDiff_NamesEveryChange: Diff reports one named change per
// differing field across a full perturbation — the reflection path the
// reload log rides.
func TestTunablesDiff_NamesEveryChange(t *testing.T) {
	base := Defaults().Tunables()
	perturbed := base
	perturbed.GhostGrace++
	perturbed.UnresolvedCap++
	changes := tunables.Diff(base, perturbed)
	if len(changes) != 2 {
		t.Fatalf("Diff reported %d changes, want 2: %+v", len(changes), changes)
	}
	if changes[0].Knob != "gc.ghost_grace" || changes[1].Knob != "unresolved.cap" {
		t.Errorf("change names = %q/%q, want the knob tags", changes[0].Knob, changes[1].Knob)
	}
}
