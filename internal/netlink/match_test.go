package netlink

import "testing"

func TestShouldAttach(t *testing.T) {
	cases := []struct {
		name     string
		iface    string
		prefixes []string
		explicit []string
		want     bool
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
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ShouldAttach(c.iface, c.prefixes, c.explicit); got != c.want {
				t.Errorf("ShouldAttach(%q, prefixes=%v, explicit=%v) = %v, want %v",
					c.iface, c.prefixes, c.explicit, got, c.want)
			}
		})
	}
}
