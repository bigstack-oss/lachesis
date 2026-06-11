package bpf

import "testing"

// TestZoneCode_String pins the canonical zone vocabulary. These
// strings are the `zone` label values on cubecos_bytes_total /
// cubecos_packets_total — dashboards and alert rules depend on
// them, so a change here is a breaking metrics-contract change.
func TestZoneCode_String(t *testing.T) {
	cases := []struct {
		code ZoneCode
		want string
	}{
		{ZoneExternal, "external"},
		{ZoneSameTenant, "same_tenant"},
		{ZoneOtherTenant, "other_tenant"},
		{ZoneInfra, "infra"},
		{ZoneMiss, "miss"},
		{ZoneShared, "shared"},
	}
	for _, tc := range cases {
		if got := tc.code.String(); got != tc.want {
			t.Errorf("ZoneCode(%d).String() = %q, want %q", uint8(tc.code), got, tc.want)
		}
	}
	if got := ZoneCode(99).String(); got != "99" {
		t.Errorf("unknown code: got %q, want \"99\"", got)
	}
}

// TestDirection_String pins the canonical direction vocabulary —
// the `direction` label values. Same contract weight as
// [TestZoneCode_String].
func TestDirection_String(t *testing.T) {
	if got := DirectionIngress.String(); got != "ingress" {
		t.Errorf("DirectionIngress.String() = %q, want ingress", got)
	}
	if got := DirectionEgress.String(); got != "egress" {
		t.Errorf("DirectionEgress.String() = %q, want egress", got)
	}
	if got := Direction(7).String(); got != "7" {
		t.Errorf("unknown direction: got %q, want \"7\"", got)
	}
}
