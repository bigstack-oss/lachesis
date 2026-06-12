package bpf

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func TestMACKey(t *testing.T) {
	tests := []struct {
		name string
		mac  [6]uint8
		want uint64
	}{
		{"zero", [6]uint8{}, 0},
		{"low byte only", [6]uint8{0, 0, 0, 0, 0, 0xff}, 0xff},
		{"high byte only", [6]uint8{0xff, 0, 0, 0, 0, 0}, 0xff << 40},
		{"all set", [6]uint8{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 0xffffffffffff},
		// Matches the locally-administered MACs in
		// internal/testenv/classifier — the test there asserts the
		// same bit pattern crossing into the kernel mac_tenant_map.
		{"vmA pattern", [6]uint8{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, 0x020000000001},
		{"big-endian ordering", [6]uint8{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, 0xaabbccddeeff},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := MACKey(tc.mac); got != tc.want {
				t.Fatalf("MACKey(%v) = %#x, want %#x", tc.mac, got, tc.want)
			}
		})
	}
}

func TestLpmKeyForPrefix_Prefixlen(t *testing.T) {
	tests := []struct {
		cidr string
		want uint32
	}{
		{"0.0.0.0/0", 32},   // catchall
		{"10.0.0.0/8", 40},  //  8-bit ip prefix
		{"10.0.1.0/24", 56}, // 24-bit ip prefix
		{"169.254.169.254/32", 64},
	}
	for _, tc := range tests {
		t.Run(tc.cidr, func(t *testing.T) {
			got := LpmKeyForPrefix(1, netip.MustParsePrefix(tc.cidr))
			if got.Prefixlen != tc.want {
				t.Fatalf("Prefixlen for %s = %d, want %d", tc.cidr, got.Prefixlen, tc.want)
			}
		})
	}
}

// TestLpmKeyForPrefix_IPMemoryLayout asserts the in-memory bytes of
// the Ip field equal the wire bytes of the IPv4 address, regardless
// of host endianness. The numeric value Ip holds is host-dependent
// (NativeEndian); the memory layout is what the kernel LPM trie
// walks, and that must match the wire.
func TestLpmKeyForPrefix_IPMemoryLayout(t *testing.T) {
	for _, cidr := range []string{"10.0.1.0/24", "192.0.2.5/32", "169.254.169.254/32"} {
		t.Run(cidr, func(t *testing.T) {
			prefix := netip.MustParsePrefix(cidr)
			got := LpmKeyForPrefix(1, prefix)
			wantBytes := prefix.Addr().As4()
			var gotBytes [4]byte
			binary.NativeEndian.PutUint32(gotBytes[:], got.Ip)
			if gotBytes != wantBytes {
				t.Fatalf("Ip memory bytes for %s = %v, want %v (wire order)",
					cidr, gotBytes, wantBytes)
			}
		})
	}
}

func TestLpmKeyForPrefix_TenantID(t *testing.T) {
	got := LpmKeyForPrefix(42, netip.MustParsePrefix("10.0.0.0/8"))
	if got.TenantId != 42 {
		t.Fatalf("TenantId = %d, want 42", got.TenantId)
	}
}

func TestLpmKeyForPrefix_IPv6Panics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on IPv6 prefix")
		}
	}()
	LpmKeyForPrefix(1, netip.MustParsePrefix("fd00::/64"))
}

// makeSpec returns a minimal CollectionSpec with telemetry_map,
// mac_tenant_map, subnet_zone_trie, and telemetry_stats. mac_tenant_map
// and subnet_zone_trie are sized as supplied; telemetry_map and
// telemetry_stats are always at their expected sizes so the existing
// mac/trie drift tests stay focused on the map they name. Used by
// ValidateMapSizes tests.
func makeSpec(macMax, trieMax uint32) *ebpf.CollectionSpec {
	return &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			MapTelemetry:      {MaxEntries: MapTelemetryMaxEntries},
			MapMacTenant:      {MaxEntries: macMax},
			MapSubnetZoneTrie: {MaxEntries: trieMax},
			MapTelemetryStats: {MaxEntries: MapTelemetryStatsMaxEntries},
		},
	}
}

func TestValidateMapSizes_OK(t *testing.T) {
	spec := makeSpec(MapMacTenantMaxEntries, MapSubnetZoneTrieMaxEntries)
	if err := ValidateMapSizes(spec); err != nil {
		t.Fatalf("ValidateMapSizes on matching spec: %v", err)
	}
}

func TestValidateMapSizes_TelemetryDrift(t *testing.T) {
	spec := makeSpec(MapMacTenantMaxEntries, MapSubnetZoneTrieMaxEntries)
	spec.Maps[MapTelemetry].MaxEntries = MapTelemetryMaxEntries / 2 // simulate stale .o
	err := ValidateMapSizes(spec)
	if err == nil {
		t.Fatal("drifted telemetry_map should error")
	}
	if !strings.Contains(err.Error(), MapTelemetry) {
		t.Errorf("error should name the offending map: %v", err)
	}
}

func TestValidateMapSizes_MacUndersize(t *testing.T) {
	spec := makeSpec(1024, MapSubnetZoneTrieMaxEntries) // simulate stale .o
	err := ValidateMapSizes(spec)
	if err == nil {
		t.Fatal("undersized mac_tenant_map should error")
	}
	if !strings.Contains(err.Error(), MapMacTenant) {
		t.Errorf("error should name the offending map: %v", err)
	}
	if !strings.Contains(err.Error(), "task generate") {
		t.Errorf("error should hint at the fix: %v", err)
	}
}

func TestValidateMapSizes_TrieOversize(t *testing.T) {
	// Either direction of drift fails — exact match is the contract.
	spec := makeSpec(MapMacTenantMaxEntries, MapSubnetZoneTrieMaxEntries*2)
	if err := ValidateMapSizes(spec); err == nil {
		t.Fatal("oversized subnet_zone_trie should error (drift)")
	}
}

func TestValidateMapSizes_StatsDrift(t *testing.T) {
	// Simulates a stat_reason added in bpf/telemetry.c (STAT_REASON_MAX
	// grows the map) without updating the Go-side mirror — the enum
	// lockstep guard, not just a sizing check.
	spec := makeSpec(MapMacTenantMaxEntries, MapSubnetZoneTrieMaxEntries)
	spec.Maps[MapTelemetryStats].MaxEntries = MapTelemetryStatsMaxEntries + 1
	err := ValidateMapSizes(spec)
	if err == nil {
		t.Fatal("drifted telemetry_stats should error")
	}
	if !strings.Contains(err.Error(), MapTelemetryStats) {
		t.Errorf("error should name the offending map: %v", err)
	}
}

func TestValidateMapSizes_MapAbsent(t *testing.T) {
	spec := &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{
		MapMacTenant: {MaxEntries: MapMacTenantMaxEntries},
		// subnet_zone_trie missing
	}}
	err := ValidateMapSizes(spec)
	if err == nil {
		t.Fatal("missing trie map should error")
	}
	if !strings.Contains(err.Error(), "not present") {
		t.Errorf("error should mention 'not present': %v", err)
	}
}

func TestValidateMapSizes_NilSpec(t *testing.T) {
	if err := ValidateMapSizes(nil); err == nil {
		t.Fatal("nil spec should error")
	}
}

// TestValidateMapSizes_LiveSpec catches a real stale-.o condition:
// the actual loaded spec must agree with the Go-side constants.
// This is the test that fails locally when someone forgets to run
// `task generate` after bumping a size.
func TestValidateMapSizes_LiveSpec(t *testing.T) {
	spec, err := LoadTelemetry()
	if err != nil {
		t.Fatalf("LoadTelemetry: %v", err)
	}
	if err := ValidateMapSizes(spec); err != nil {
		t.Fatalf("loaded BPF object disagrees with Go-side constants: %v", err)
	}
}
