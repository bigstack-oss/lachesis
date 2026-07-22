package metadata

import (
	"reflect"
	"testing"
	"time"
)

// TestSameAttribution_EveryFieldClassified is the root-cause guard for
// the stale-attribution class of bug: a developer adding a TenantMeta
// field MUST classify it here as attribution (compared by
// [TenantMeta.SameAttribution]) or lifecycle (zeroed there), or this
// test fails. SameAttribution compares whole structs with lifecycle
// fields zeroed, so an unclassified field is attribution BY DEFAULT —
// safe (a spurious settle is sum-invariant) but this test still forces
// the conscious decision, exactly like the config tunables guard.
func TestSameAttribution_EveryFieldClassified(t *testing.T) {
	attribution := map[string]bool{
		"ProjectID":       true,
		"ServerID":        true,
		"PortID":          true,
		"ExternalNetwork": true,
		"IsAmphora":       true,
	}
	lifecycle := map[string]bool{
		"DeleteAt": true,
	}
	typ := reflect.TypeOf(TenantMeta{})
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		switch {
		case attribution[name] && lifecycle[name]:
			t.Errorf("TenantMeta.%s classified as BOTH attribution and lifecycle", name)
		case !attribution[name] && !lifecycle[name]:
			t.Errorf("TenantMeta.%s is unclassified — add it to this test's attribution or lifecycle list, and zero it in SameAttribution if lifecycle", name)
		}
	}
	if got, want := typ.NumField(), len(attribution)+len(lifecycle); got != want {
		t.Errorf("TenantMeta has %d fields, classification lists cover %d", got, want)
	}
}

// TestSameAttribution_Semantics pins the comparison: lifecycle fields
// are ignored, every attribution field is load-bearing.
func TestSameAttribution_Semantics(t *testing.T) {
	base := TenantMeta{ProjectID: "t1", ServerID: "s1", PortID: "p1", ExternalNetwork: "ext"}

	ghosted := base
	ghosted.DeleteAt = time.Unix(1000, 0)
	if !base.SameAttribution(ghosted) {
		t.Error("DeleteAt is lifecycle — a ghosted twin must compare equal")
	}

	cases := map[string]TenantMeta{
		"ProjectID":       {ProjectID: "t2", ServerID: "s1", PortID: "p1", ExternalNetwork: "ext"},
		"ServerID":        {ProjectID: "t1", ServerID: "s2", PortID: "p1", ExternalNetwork: "ext"},
		"PortID":          {ProjectID: "t1", ServerID: "s1", PortID: "p2", ExternalNetwork: "ext"},
		"ExternalNetwork": {ProjectID: "t1", ServerID: "s1", PortID: "p1", ExternalNetwork: "ext2"},
		"IsAmphora":       {ProjectID: "t1", ServerID: "s1", PortID: "p1", ExternalNetwork: "ext", IsAmphora: true},
	}
	for field, other := range cases {
		if base.SameAttribution(other) {
			t.Errorf("a %s change must be an attribution change", field)
		}
	}
}
