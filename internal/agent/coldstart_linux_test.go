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

	"github.com/bigstack-oss/lachesis/internal/bpf"
	"github.com/bigstack-oss/lachesis/internal/config"
	"github.com/bigstack-oss/lachesis/internal/logging"
	"github.com/bigstack-oss/lachesis/internal/metadata"
	"github.com/bigstack-oss/lachesis/internal/neutron"
	"github.com/bigstack-oss/lachesis/internal/reconcile"
)

// TestPopulateMetadataFromPorts_TrunkSubportWarning pins the trunk
// blind-spot detection (docs/architecture/edge-cases.md#tier-1--hard-limits): a snapshot
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

			s := populateMetadataFromPorts(metadata.New(), &neutron.Snapshot{Ports: tc.ports}, mx)

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
# HELP lachesis_neutron_trunk_subports Count of trunk subport MACs admitted to mac_tenant_map at the last Neutron cold-start or resync; nonzero means 802.1Q-tagged subport traffic passes the data plane uncounted (docs/architecture/edge-cases.md).
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

// TestPopulateMetadataFromPorts_CarriesAttribution: cold-start inserts
// carry the full attribution — server_id from the port's device_id and
// the external network resolved from the snapshot's FIPs
// (docs/architecture/billing.md) — so the very first scrape after boot labels correctly.
func TestPopulateMetadataFromPorts_CarriesAttribution(t *testing.T) {
	var buf bytes.Buffer
	if _, err := logging.Init(config.LoggingConfig{Level: "info", Format: "json"}, &buf); err != nil {
		t.Fatalf("logging.Init: %v", err)
	}
	mx := neutron.NewMetrics(func() time.Time { return time.Time{} })
	meta := metadata.New()

	snap := neutron.Snapshot{
		Networks: []neutron.Network{{ID: "net-pub", Name: "public-1", IsExternal: true}},
		Ports: []neutron.Port{{
			ID: "p1", DeviceOwner: "compute:nova", ProjectID: "t1",
			MACAddress: "fa:16:3e:00:00:01", DeviceID: "srv-1",
		}},
		FloatingIPs: []neutron.FloatingIP{{ID: "f1", PortID: "p1", FloatingNetworkID: "net-pub"}},
	}
	if s := populateMetadataFromPorts(meta, &snap, mx); s.inserted != 1 {
		t.Fatalf("inserted = %d, want 1", s.inserted)
	}

	hw := [6]uint8{0xfa, 0x16, 0x3e, 0, 0, 0x01}
	got, ok := meta.Lookup(bpf.MACKey(hw))
	if !ok {
		t.Fatal("inserted MAC not found")
	}
	want := metadata.TenantMeta{ProjectID: "t1", ServerID: "srv-1", PortID: "p1", ExternalNetwork: "public-1"}
	if *got != want {
		t.Errorf("TenantMeta = %+v, want %+v", *got, want)
	}
}

// TestPopulateMetadataFromPorts_MatchesDesiredMACs is the cross-check
// that cold-start and the reconciler cannot disagree about attribution.
// Cold-start now publishes reconcile.DesiredMACs directly, so this
// asserts the publish step is faithful: every MAC the reconciler would
// want is in the map, with byte-identical attribution, and nothing else
// is. Without it, someone re-introducing a local rewrite in the insert
// loop would produce a boot-then-reconcile flip-flop that only shows up
// as a settled-and-relabelled billing series in production.
//
// The snapshot deliberately spans every branch: a plain VM, an Amphora
// data port (rewritten), its management port (not rewritten), an infra
// port and an unparseable MAC (both excluded).
func TestPopulateMetadataFromPorts_MatchesDesiredMACs(t *testing.T) {
	var buf bytes.Buffer
	if _, err := logging.Init(config.LoggingConfig{Level: "info", Format: "json"}, &buf); err != nil {
		t.Fatalf("logging.Init: %v", err)
	}
	snap := neutron.Snapshot{
		Networks: []neutron.Network{{ID: "net-pub", Name: "public-1", IsExternal: true}},
		Ports: []neutron.Port{
			{ID: "p-vm", DeviceOwner: "compute:nova", ProjectID: "t1", DeviceID: "srv-1",
				MACAddress: "fa:16:3e:00:00:01"},
			{ID: "p-amp-mgmt", DeviceOwner: "compute:nova", ProjectID: "service", DeviceID: "nova-amp",
				MACAddress: "fa:16:3e:00:00:02",
				FixedIPs:   []neutron.FixedIP{{IPAddress: "10.254.0.9"}}},
			{ID: "p-amp-data", DeviceOwner: "compute:nova", ProjectID: "service", DeviceID: "nova-amp",
				MACAddress: "fa:16:3e:00:00:03",
				FixedIPs:   []neutron.FixedIP{{IPAddress: "192.168.1.99"}}},
			{ID: "p-infra", DeviceOwner: "network:router_interface", ProjectID: "t1",
				MACAddress: "fa:16:3e:00:00:04"},
			{ID: "p-badmac", DeviceOwner: "compute:nova", ProjectID: "t1",
				MACAddress: "not-a-mac"},
		},
		FloatingIPs:   []neutron.FloatingIP{{ID: "f1", PortID: "p-vm", FloatingNetworkID: "net-pub"}},
		LoadBalancers: []neutron.LoadBalancer{{ID: "lb1", ProjectID: "lb-owner", Provider: "amphora"}},
		Amphorae: []neutron.Amphora{{
			ID: "amp1", LoadBalancerID: "lb1", ComputeID: "nova-amp",
			LBNetworkIP: "10.254.0.9", Status: "ALLOCATED",
		}},
	}

	meta := metadata.New()
	mx := neutron.NewMetrics(func() time.Time { return time.Time{} })
	populateMetadataFromPorts(meta, &snap, mx)

	want := reconcile.DesiredMACs(&snap)
	if len(want) == 0 {
		t.Fatal("DesiredMACs produced nothing; the fixture no longer exercises anything")
	}
	for mac, w := range want {
		got, ok := meta.Lookup(mac)
		if !ok {
			t.Errorf("mac %012x wanted by the reconciler but absent after cold-start", mac)
			continue
		}
		if *got != w {
			t.Errorf("mac %012x: cold-start wrote %+v, reconciler wants %+v", mac, *got, w)
		}
	}
	inserted := 0
	meta.Range(func(mac uint64, _ *metadata.TenantMeta) bool {
		if _, ok := want[mac]; !ok {
			t.Errorf("mac %012x inserted by cold-start but not wanted by the reconciler", mac)
		}
		inserted++
		return true
	})
	if inserted != len(want) {
		t.Errorf("cold-start inserted %d MACs, reconciler wants %d", inserted, len(want))
	}
}

// TestPopulateMetadataFromPorts_AmphoraBillsLBOwner pins the Octavia
// re-attribution at cold-start (docs/architecture/octavia.md): the
// Amphora's data port bills the load balancer's owning tenant rather
// than the Octavia service project it literally belongs to, its
// management port keeps the service project (health-manager heartbeats
// are not tenant traffic), and the count is published on
// lachesis_neutron_amphora_ports.
func TestPopulateMetadataFromPorts_AmphoraBillsLBOwner(t *testing.T) {
	var buf bytes.Buffer
	if _, err := logging.Init(config.LoggingConfig{Level: "info", Format: "json"}, &buf); err != nil {
		t.Fatalf("logging.Init: %v", err)
	}
	mx := neutron.NewMetrics(func() time.Time { return time.Time{} })
	meta := metadata.New()

	snap := neutron.Snapshot{
		Ports: []neutron.Port{
			{ID: "p-mgmt", DeviceOwner: "compute:nova", ProjectID: "service", DeviceID: "nova-amp",
				MACAddress: "fa:16:3e:00:00:01",
				FixedIPs:   []neutron.FixedIP{{IPAddress: "10.254.0.9"}}},
			{ID: "p-data", DeviceOwner: "compute:nova", ProjectID: "service", DeviceID: "nova-amp",
				MACAddress: "fa:16:3e:00:00:02",
				FixedIPs:   []neutron.FixedIP{{IPAddress: "192.168.1.99"}}},
		},
		LoadBalancers: []neutron.LoadBalancer{{ID: "lb1", ProjectID: "lb-owner", Provider: "amphora"}},
		Amphorae: []neutron.Amphora{{
			ID: "amp1", LoadBalancerID: "lb1", ComputeID: "nova-amp",
			LBNetworkIP: "10.254.0.9", Status: "ALLOCATED",
		}},
	}
	s := populateMetadataFromPorts(meta, &snap, mx)
	if s.amphoraPorts != 1 {
		t.Errorf("amphoraPorts = %d, want 1", s.amphoraPorts)
	}

	data, ok := meta.Lookup(bpf.MACKey([6]uint8{0xfa, 0x16, 0x3e, 0, 0, 0x02}))
	if !ok {
		t.Fatal("Amphora data port MAC not found")
	}
	if data.ProjectID != "lb-owner" || !data.IsAmphora {
		t.Errorf("data port = %+v, want ProjectID=lb-owner IsAmphora=true", *data)
	}

	mgmt, ok := meta.Lookup(bpf.MACKey([6]uint8{0xfa, 0x16, 0x3e, 0, 0, 0x01}))
	if !ok {
		t.Fatal("Amphora management port MAC not found")
	}
	if mgmt.ProjectID != "service" || mgmt.IsAmphora {
		t.Errorf("management port = %+v, want ProjectID=service IsAmphora=false", *mgmt)
	}

	reg := prometheus.NewRegistry()
	for _, c := range mx.Collectors() {
		if err := reg.Register(c); err != nil {
			t.Fatalf("register: %v", err)
		}
	}
	const want = `
# HELP lachesis_neutron_amphora_ports Count of Octavia Amphora ports re-attributed from the service project to their load balancer's owning tenant at the last Neutron cold-start or resync (docs/architecture/octavia.md); drops to 0 if the Octavia lists stop resolving.
# TYPE lachesis_neutron_amphora_ports gauge
lachesis_neutron_amphora_ports 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want),
		"lachesis_neutron_amphora_ports"); err != nil {
		t.Errorf("metric mismatch:\n%v", err)
	}
}
