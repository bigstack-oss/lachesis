//go:build linux

package agent

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/bigstack-oss/lachesis/internal/config"
	"github.com/bigstack-oss/lachesis/internal/logging"
	"github.com/bigstack-oss/lachesis/internal/metadata"
	"github.com/bigstack-oss/lachesis/internal/neutron"
)

// TestPopulateMetadataFromPorts_TrunkSubportWarning pins the trunk
// blind-spot detection (docs/DESIGN.md §8 Tier 1): a snapshot
// containing trunk subports admits their MACs (the metadata layer
// accepts them) but emits exactly one summary warning and sets the
// lachesis_neutron_trunk_subports gauge, while a trunk-free snapshot
// emits no warning and leaves the gauge at zero.
func TestPopulateMetadataFromPorts_TrunkSubportWarning(t *testing.T) {
	tests := []struct {
		name      string
		ports     []neutron.Port
		wantWarns int // occurrences of the summary warning (0 or 1)
		wantGauge int
	}{
		{
			name: "no trunk subports",
			ports: []neutron.Port{
				{ID: "p1", DeviceOwner: "compute:nova", ProjectID: "t1", MACAddress: "fa:16:3e:00:00:01"},
				{ID: "p2", DeviceOwner: "Octavia", ProjectID: "t2", MACAddress: "fa:16:3e:00:00:02"},
			},
		},
		{
			name: "trunk subports present",
			ports: []neutron.Port{
				{ID: "p1", DeviceOwner: "compute:nova", ProjectID: "t1", MACAddress: "fa:16:3e:00:00:01"},
				{ID: "p2", DeviceOwner: "trunk:subport", ProjectID: "t1", MACAddress: "fa:16:3e:00:00:02"},
				{ID: "p3", DeviceOwner: "trunk:subport", ProjectID: "t2", MACAddress: "fa:16:3e:00:00:03"},
			},
			wantWarns: 1,
			wantGauge: 2,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if _, err := logging.Init(config.LoggingConfig{Level: "info", Format: "json"}, &buf); err != nil {
				t.Fatalf("logging.Init: %v", err)
			}
			mx := neutron.NewMetrics(func() time.Time { return time.Time{} })

			s := populateMetadataFromPorts(metadata.New(), tc.ports, mx)

			// Trunk subports still admit — the warning flags the
			// data-plane blind spot, it does not reject the MACs.
			if s.inserted != len(tc.ports) {
				t.Errorf("inserted = %d, want %d", s.inserted, len(tc.ports))
			}
			const msg = "802.1Q-tagged traffic on trunk parents is not counted"
			if got := strings.Count(buf.String(), msg); got != tc.wantWarns {
				t.Errorf("trunk warning emitted %d times, want %d; logs:\n%s", got, tc.wantWarns, buf.String())
			}

			reg := prometheus.NewRegistry()
			for _, c := range mx.Collectors() {
				if err := reg.Register(c); err != nil {
					t.Fatalf("register: %v", err)
				}
			}
			want := fmt.Sprintf(`
# HELP lachesis_neutron_trunk_subports Count of trunk subport MACs admitted to mac_tenant_map at the last Neutron cold-start or resync; nonzero means 802.1Q-tagged subport traffic passes the data plane uncounted (DESIGN §8).
# TYPE lachesis_neutron_trunk_subports gauge
lachesis_neutron_trunk_subports %d
`, tc.wantGauge)
			if err := testutil.GatherAndCompare(reg, strings.NewReader(want),
				"lachesis_neutron_trunk_subports"); err != nil {
				t.Errorf("metric mismatch:\n%v", err)
			}
		})
	}
}
