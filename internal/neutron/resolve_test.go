package neutron

import (
	"testing"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
)

func TestZoneFor(t *testing.T) {
	const (
		t1 = "tenant-1"
		t2 = "tenant-2"
	)
	tests := []struct {
		name    string
		owner   string
		source  string
		network Network
		want    bpf.ZoneCode
	}{
		{
			name:    "external network classifies EXTERNAL regardless of owner",
			owner:   t1,
			source:  t1,
			network: Network{IsExternal: true},
			want:    bpf.ZoneExternal,
		},
		{
			name:    "shared non-external network classifies SHARED",
			owner:   t2,
			source:  t1,
			network: Network{Shared: true},
			want:    bpf.ZoneShared,
		},
		{
			name:    "internal non-shared owned by source tenant classifies SAME_TENANT",
			owner:   t1,
			source:  t1,
			network: Network{},
			want:    bpf.ZoneSameTenant,
		},
		{
			name:    "internal non-shared owned by peer tenant classifies OTHER_TENANT",
			owner:   t2,
			source:  t1,
			network: Network{},
			want:    bpf.ZoneOtherTenant,
		},
		{
			name:    "external precedence: external+shared classifies EXTERNAL (external wins)",
			owner:   t1,
			source:  t1,
			network: Network{IsExternal: true, Shared: true},
			want:    bpf.ZoneExternal,
		},
		{
			name:    "shared precedence: shared owned by source classifies SHARED (shared wins over owner==source)",
			owner:   t1,
			source:  t1,
			network: Network{Shared: true},
			want:    bpf.ZoneShared,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := zoneFor(tc.owner, tc.source, tc.network)
			if got != tc.want {
				t.Errorf("zoneFor(owner=%q, source=%q, network=%+v) = %v, want %v",
					tc.owner, tc.source, tc.network, got, tc.want)
			}
		})
	}
}
