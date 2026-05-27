//go:build linux

package zombie

import (
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/tcattach"
)

func TestIsTelemetryOrphan(t *testing.T) {
	cases := []struct {
		name   string
		filter netlink.Filter
		want   bool
	}{
		{
			name:   "ingress telemetry bpf filter is an orphan",
			filter: &netlink.BpfFilter{Name: tcattach.FilterIngressName},
			want:   true,
		},
		{
			name:   "egress telemetry bpf filter is an orphan",
			filter: &netlink.BpfFilter{Name: tcattach.FilterEgressName},
			want:   true,
		},
		{
			name:   "unrelated bpf filter is not an orphan",
			filter: &netlink.BpfFilter{Name: "some_other_prog"},
			want:   false,
		},
		{
			name:   "empty-name bpf filter is not an orphan",
			filter: &netlink.BpfFilter{Name: ""},
			want:   false,
		},
		{
			name:   "u32 filter is not an orphan",
			filter: &netlink.U32{},
			want:   false,
		},
		{
			name:   "generic filter is not an orphan",
			filter: &netlink.GenericFilter{FilterType: "matchall"},
			want:   false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isTelemetryOrphan(c.filter); got != c.want {
				t.Errorf("isTelemetryOrphan(%T %q) = %v, want %v",
					c.filter, c.filter.Attrs().Handle, got, c.want)
			}
		})
	}
}
