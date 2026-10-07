//go:build linux

package tcattach

import (
	"testing"

	"github.com/vishvananda/netlink"
)

func TestTelemetryFilter(t *testing.T) {
	cases := []struct {
		name   string
		filter netlink.Filter
		want   bool
	}{
		{
			name:   "ingress telemetry bpf filter is ours",
			filter: &netlink.BpfFilter{Name: FilterIngressName},
			want:   true,
		},
		{
			name:   "egress telemetry bpf filter is ours",
			filter: &netlink.BpfFilter{Name: FilterEgressName},
			want:   true,
		},
		{
			name:   "unrelated bpf filter is not ours",
			filter: &netlink.BpfFilter{Name: "some_other_prog"},
			want:   false,
		},
		{
			name:   "empty-name bpf filter is not ours",
			filter: &netlink.BpfFilter{Name: ""},
			want:   false,
		},
		{
			name:   "u32 filter is not ours",
			filter: &netlink.U32{},
			want:   false,
		},
		{
			name:   "generic filter is not ours",
			filter: &netlink.GenericFilter{FilterType: "matchall"},
			want:   false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, got := telemetryFilter(c.filter); got != c.want {
				t.Errorf("telemetryFilter(%T %q) = %v, want %v",
					c.filter, c.filter.Attrs().Handle, got, c.want)
			}
		})
	}
}
