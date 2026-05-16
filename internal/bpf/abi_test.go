package bpf

import (
	"encoding/binary"
	"net/netip"
	"testing"
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
