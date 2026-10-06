package neutron

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

const (
	tenantInfoHeader = `# HELP lachesis_tenant_info Identity mapping for a tenant: value is always 1, joined onto the billing families by tenant_id (group_left) to render name(id). One series per known Keystone project.
# TYPE lachesis_tenant_info gauge
`
	serverInfoHeader = `# HELP lachesis_server_info Identity mapping for a server: value is always 1, joined onto the per-server family by server_id (group_left) to render name(id). One series per known Nova server; absent when the Nova fetch fails.
# TYPE lachesis_server_info gauge
`
)

// snapFunc returns a snapshot accessor over a fixed value, mimicking
// [Neutron.Snapshot]'s atomic-pointer read.
func snapFunc(s *Snapshot) func() *Snapshot { return func() *Snapshot { return s } }

func TestInfoCollector_EmitsBothFamilies(t *testing.T) {
	c := NewInfoCollector(snapFunc(&Snapshot{
		Projects: []Project{{ID: "proj-1", Name: "alpha"}, {ID: "proj-2", Name: "beta"}},
		Servers: []Server{
			{ID: "srv-1", Name: "web-0", ProjectID: "proj-1"},
			{ID: "srv-2", Name: "db-0", ProjectID: "proj-2"},
		},
	}))

	expected := tenantInfoHeader +
		`lachesis_tenant_info{name="alpha",tenant_id="proj-1"} 1
lachesis_tenant_info{name="beta",tenant_id="proj-2"} 1
` + serverInfoHeader +
		`lachesis_server_info{name="web-0",server_id="srv-1",tenant_id="proj-1"} 1
lachesis_server_info{name="db-0",server_id="srv-2",tenant_id="proj-2"} 1
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected),
		"lachesis_tenant_info", "lachesis_server_info"); err != nil {
		t.Errorf("CollectAndCompare: %v", err)
	}
}

// TestInfoCollector_NilSnapshotEmitsNothing pins the never-synced path:
// before the first commit the accessor returns nil and the collector
// emits no series (graceful — dashboards fall back to bare ids).
func TestInfoCollector_NilSnapshotEmitsNothing(t *testing.T) {
	c := NewInfoCollector(snapFunc(nil))
	if n := testutil.CollectAndCount(c); n != 0 {
		t.Errorf("nil snapshot emitted %d series, want 0", n)
	}
}

// TestInfoCollector_NovaDegradedOmitsServerFamily is the graceful-
// degradation contract: a snapshot whose Servers is empty (Nova fetch
// failed) still emits lachesis_tenant_info but no lachesis_server_info.
func TestInfoCollector_NovaDegradedOmitsServerFamily(t *testing.T) {
	c := NewInfoCollector(snapFunc(&Snapshot{
		Projects: []Project{{ID: "proj-1", Name: "alpha"}},
	}))

	expected := tenantInfoHeader + `lachesis_tenant_info{name="alpha",tenant_id="proj-1"} 1
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected),
		"lachesis_tenant_info"); err != nil {
		t.Errorf("tenant_info: %v", err)
	}
	if n := testutil.CollectAndCount(c, "lachesis_server_info"); n != 0 {
		t.Errorf("server_info emitted %d series with no servers, want 0", n)
	}
}

// TestInfoCollector_SkipsEmptyIDsAndDuplicates guards Collect against a
// malformed upstream list: entries with an empty id are skipped, and a
// repeated id is emitted once — a duplicate label set would otherwise
// fail the whole scrape's Gather.
func TestInfoCollector_SkipsEmptyIDsAndDuplicates(t *testing.T) {
	c := NewInfoCollector(snapFunc(&Snapshot{
		Projects: []Project{
			{ID: "proj-1", Name: "alpha"},
			{ID: "", Name: "no-id"},     // skipped
			{ID: "proj-1", Name: "dup"}, // deduped (first wins)
		},
		Servers: []Server{
			{ID: "srv-1", Name: "web-0", ProjectID: "proj-1"},
			{ID: "", Name: "no-id", ProjectID: "proj-1"}, // skipped
		},
	}))

	expected := tenantInfoHeader + `lachesis_tenant_info{name="alpha",tenant_id="proj-1"} 1
` + serverInfoHeader + `lachesis_server_info{name="web-0",server_id="srv-1",tenant_id="proj-1"} 1
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected),
		"lachesis_tenant_info", "lachesis_server_info"); err != nil {
		t.Errorf("CollectAndCompare: %v", err)
	}
}

const portInfoHeader = `# HELP lachesis_port_info Identity mapping for a VM port: value is always 1, joined onto the per-port family by port_id (group_left) to render its MAC and fixed IPs. One series per VM port; ips is the sorted, comma-joined fixed-IP list.
# TYPE lachesis_port_info gauge
`

// TestInfoCollector_PortInfo pins lachesis_port_info: VM ports only
// (the mac_tenant_map admission predicate), one series per port with a
// sorted comma-joined ips label, and the same skip/dedupe guards as the
// other families.
func TestInfoCollector_PortInfo(t *testing.T) {
	vm := func(id string, ips ...string) Port {
		p := Port{ID: id, ProjectID: "proj-1", MACAddress: "fa:16:3e:00:00:01", DeviceOwner: "compute:nova", DeviceID: "srv-1"}
		for _, ip := range ips {
			p.FixedIPs = append(p.FixedIPs, FixedIP{SubnetID: "sub", IPAddress: ip})
		}
		return p
	}
	tests := []struct {
		name  string
		ports []Port
		want  string // series lines, header excluded; empty = no series
	}{
		{
			name:  "single fixed IP",
			ports: []Port{vm("port-1", "10.0.0.5")},
			want:  `lachesis_port_info{ips="10.0.0.5",mac="fa:16:3e:00:00:01",port_id="port-1",server_id="srv-1",tenant_id="proj-1"} 1` + "\n",
		},
		{
			name:  "dual-stack sorted regardless of Neutron order",
			ports: []Port{vm("port-1", "fd00::5", "10.0.0.5")},
			want:  `lachesis_port_info{ips="10.0.0.5,fd00::5",mac="fa:16:3e:00:00:01",port_id="port-1",server_id="srv-1",tenant_id="proj-1"} 1` + "\n",
		},
		{
			name:  "no fixed IP still emits with empty ips",
			ports: []Port{vm("port-1")},
			want:  `lachesis_port_info{ips="",mac="fa:16:3e:00:00:01",port_id="port-1",server_id="srv-1",tenant_id="proj-1"} 1` + "\n",
		},
		{
			name: "infra ports excluded",
			ports: []Port{
				{ID: "rtr", ProjectID: "proj-1", MACAddress: "fa:16:3e:00:00:02", DeviceOwner: "network:router_interface"},
				{ID: "dhcp", ProjectID: "proj-1", MACAddress: "fa:16:3e:00:00:03", DeviceOwner: "network:dhcp"},
			},
		},
		{
			name: "ports outside mac_tenant_map excluded",
			ports: []Port{
				{ID: "unbound", ProjectID: "proj-1", MACAddress: "fa:16:3e:00:00:04"},         // no device_owner
				{ID: "no-proj", MACAddress: "fa:16:3e:00:00:05", DeviceOwner: "compute:nova"}, // no project
				{ID: "no-mac", ProjectID: "proj-1", DeviceOwner: "compute:nova"},              // no MAC
				{ProjectID: "proj-1", MACAddress: "fa:16:3e:00:00:06", DeviceOwner: "compute:nova"},
			},
		},
		{
			name:  "duplicate port id emitted once (first wins)",
			ports: []Port{vm("port-1", "10.0.0.5"), vm("port-1", "10.0.0.9")},
			want:  `lachesis_port_info{ips="10.0.0.5",mac="fa:16:3e:00:00:01",port_id="port-1",server_id="srv-1",tenant_id="proj-1"} 1` + "\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewInfoCollector(snapFunc(&Snapshot{Ports: tt.ports}))
			if tt.want == "" {
				if n := testutil.CollectAndCount(c, "lachesis_port_info"); n != 0 {
					t.Errorf("emitted %d port_info series, want 0", n)
				}
				return
			}
			if err := testutil.CollectAndCompare(c, strings.NewReader(portInfoHeader+tt.want),
				"lachesis_port_info"); err != nil {
				t.Errorf("CollectAndCompare: %v", err)
			}
		})
	}
}
