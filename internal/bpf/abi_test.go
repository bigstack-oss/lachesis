package bpf

import "testing"

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
