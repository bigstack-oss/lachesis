package bpf

import "testing"

// TestZoneCode_String pins the canonical zone vocabulary. These
// strings are the `zone` label values on lachesis_bytes_total /
// lachesis_packets_total — dashboards and alert rules depend on
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
		{ZoneMulticast, "multicast"},
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

// TestZoneCode_WireValuesPinned pins the numeric zone encoding. The
// values are persisted: every WAL snapshot stores [FlowKey.DstZone]
// as a number and reads it back on restore, so renumbering the C
// enum silently reclassifies every restored flow. This test makes
// that break mechanical instead.
func TestZoneCode_WireValuesPinned(t *testing.T) {
	cases := []struct {
		code ZoneCode
		want uint8
	}{
		{ZoneExternal, 0},
		{ZoneSameTenant, 1},
		{ZoneOtherTenant, 2},
		{ZoneInfra, 3},
		{ZoneMiss, 4},
		{ZoneShared, 5},
		{ZoneMulticast, 6},
	}
	for _, tc := range cases {
		if uint8(tc.code) != tc.want {
			t.Errorf("%s = %d, want %d (persisted in WAL snapshots — do not renumber)",
				tc.code, uint8(tc.code), tc.want)
		}
	}
}

// TestDirection_WireValuesPinned pins the direction encoding for the
// same WAL-persistence reason as [TestZoneCode_WireValuesPinned].
func TestDirection_WireValuesPinned(t *testing.T) {
	if uint8(DirectionIngress) != 0 {
		t.Errorf("DirectionIngress = %d, want 0 (persisted in WAL snapshots — do not renumber)",
			uint8(DirectionIngress))
	}
	if uint8(DirectionEgress) != 1 {
		t.Errorf("DirectionEgress = %d, want 1 (persisted in WAL snapshots — do not renumber)",
			uint8(DirectionEgress))
	}
}

// TestStatReason_String pins the canonical stat-reason vocabulary —
// the `reason` label values on lachesis_bpf_update_failures_total.
// Same contract weight as [TestZoneCode_String].
func TestStatReason_String(t *testing.T) {
	if got := StatUpdateFailure.String(); got != "update_failure" {
		t.Errorf("StatUpdateFailure.String() = %q, want update_failure", got)
	}
	if got := StatSkippedEthertype.String(); got != "skipped_ethertype" {
		t.Errorf("StatSkippedEthertype.String() = %q, want skipped_ethertype", got)
	}
	if got := StatReason(9).String(); got != "9" {
		t.Errorf("unknown reason: got %q, want \"9\"", got)
	}
}

// TestDirection_String pins the canonical direction vocabulary —
// the `direction` label values. Same contract weight as
// [TestZoneCode_String]. The values are VM-frame ("tx" = VM sending),
// not the hook-frame enum names — see [Direction.String].
func TestDirection_String(t *testing.T) {
	if got := DirectionIngress.String(); got != "tx" {
		t.Errorf("DirectionIngress.String() = %q, want tx", got)
	}
	if got := DirectionEgress.String(); got != "rx" {
		t.Errorf("DirectionEgress.String() = %q, want rx", got)
	}
	if got := Direction(7).String(); got != "7" {
		t.Errorf("unknown direction: got %q, want \"7\"", got)
	}
}

// TestTenantValue pins the mac_tenant_map value packing against
// bpf/telemetry.c: the Amphora marker rides the top bit, the tenant id
// the low 31, and the two never bleed into each other. A drift here
// mis-zones every Octavia flow (docs/architecture/octavia.md).
func TestTenantValue(t *testing.T) {
	tests := []struct {
		name      string
		tenantID  uint32
		isAmphora bool
		want      uint32
	}{
		{"plain tenant", 100, false, 100},
		{"amphora tenant", 100, true, 0x8000_0064},
		{"unset tenant stays zero", 0, false, 0}, // metadata.TenantIDUnset
		{"amphora with unset tenant is still flagged", 0, true, TenantAmphoraFlag},
		{"largest representable tenant", TenantIDMask, false, TenantIDMask},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TenantValue(tt.tenantID, tt.isAmphora)
			if got != tt.want {
				t.Fatalf("TenantValue(%d, %v) = %#x, want %#x", tt.tenantID, tt.isAmphora, got, tt.want)
			}
			// What the kernel does with it: mask for the tenant compare
			// and the trie key, test the top bit for the Amphora branch.
			if id := got & TenantIDMask; id != tt.tenantID {
				t.Errorf("masked id = %d, want %d", id, tt.tenantID)
			}
			if flagged := got&TenantAmphoraFlag != 0; flagged != tt.isAmphora {
				t.Errorf("amphora bit = %v, want %v", flagged, tt.isAmphora)
			}
		})
	}
}

// TestTenantFlagAndMaskArePartition guards the invariant the C side
// relies on: the two constants cover all 32 bits and never overlap.
func TestTenantFlagAndMaskArePartition(t *testing.T) {
	if TenantAmphoraFlag&TenantIDMask != 0 {
		t.Errorf("flag %#x and mask %#x overlap", TenantAmphoraFlag, TenantIDMask)
	}
	if TenantAmphoraFlag|TenantIDMask != 0xFFFF_FFFF {
		t.Errorf("flag %#x | mask %#x leaves a gap", TenantAmphoraFlag, TenantIDMask)
	}
}
