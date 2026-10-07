package netlink

import "testing"

func TestShouldAttach(t *testing.T) {
	cases := []struct {
		name     string
		iface    string
		linkType string
		prefixes []string
		explicit []string
		want     bool
		wantSkip string
	}{
		{
			name:     "default tap prefix matches tap0",
			iface:    "tap0",
			prefixes: []string{"tap"},
			want:     true,
		},
		{
			name:     "default tap prefix matches tap-abcdef",
			iface:    "tap-abcdef",
			prefixes: []string{"tap"},
			want:     true,
		},
		{
			name:     "eth0 does not match tap prefix",
			iface:    "eth0",
			prefixes: []string{"tap"},
			want:     false,
		},
		{
			name:     "explicit allowlist accepts eth1",
			iface:    "eth1",
			explicit: []string{"eth1"},
			want:     true,
		},
		{
			name:     "explicit allowlist is exact, no prefix match",
			iface:    "eth1x",
			explicit: []string{"eth1"},
			want:     false,
		},
		{
			name:     "multiple prefixes — first matches",
			iface:    "tap0",
			prefixes: []string{"tap", "qvb"},
			want:     true,
		},
		{
			name:     "multiple prefixes — later matches",
			iface:    "qvb-xyz",
			prefixes: []string{"tap", "qvb"},
			want:     true,
		},
		{
			name:     "empty prefix entry is skipped, not a wildcard",
			iface:    "anything",
			prefixes: []string{""},
			want:     false,
		},
		{
			name:  "no allowlist at all returns false",
			iface: "tap0",
			want:  false,
		},
		{
			name:     "explicit-then-prefix: explicit hit short-circuits prefix",
			iface:    "eth1",
			prefixes: []string{"tap"},
			explicit: []string{"eth1"},
			want:     true,
		},
		{
			name:     "loopback is not implicitly skipped",
			iface:    "lo",
			prefixes: []string{"lo"},
			want:     true,
		},
		{
			name:     "VM tap (tuntap) matching a prefix attaches",
			iface:    "tap29a0c4f7-85",
			linkType: "tuntap",
			prefixes: []string{"tap"},
			want:     true,
		},
		{
			name:     "OVS internal port matching a prefix attaches",
			iface:    "tapb324f996-fb",
			linkType: "openvswitch",
			prefixes: []string{"tap"},
			want:     true,
		},
		{
			name:     "OVN metadata veth matching a prefix is skipped",
			iface:    "tapf386a51d-c0",
			linkType: "veth",
			prefixes: []string{"tap"},
			want:     false,
			wantSkip: "veth",
		},
		{
			name:     "explicit veth attaches regardless of type",
			iface:    "tapf386a51d-c0",
			linkType: "veth",
			prefixes: []string{"tap"},
			explicit: []string{"tapf386a51d-c0"},
			want:     true,
		},
		{
			name:     "veth matching no prefix is ignored, not a skip",
			iface:    "veth0",
			linkType: "veth",
			prefixes: []string{"tap"},
			want:     false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, skip := ShouldAttach(c.iface, c.linkType, c.prefixes, c.explicit)
			if got != c.want || skip != c.wantSkip {
				t.Errorf("ShouldAttach(%q, %q, prefixes=%v, explicit=%v) = (%v, %q), want (%v, %q)",
					c.iface, c.linkType, c.prefixes, c.explicit, got, skip, c.want, c.wantSkip)
			}
		})
	}
}
