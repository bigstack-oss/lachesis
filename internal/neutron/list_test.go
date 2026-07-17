package neutron

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// neutronStub serves both Keystone /v3/auth/tokens and the v2.0
// Network resource endpoints from a single httptest.Server. The
// catalogued Neutron URL points back at the same server so
// gophercloud's discovery routes list calls here.
type neutronStub struct {
	*httptest.Server
	networksJSON string
	subnetsJSON  string
	portsJSON    string
	routersJSON  string
	projectsJSON string
	serversJSON  string
	// serversAllTenants records the all_tenants query value the last
	// server-list request carried, so TestListServers can assert the
	// cross-tenant ListOpts is wired.
	serversAllTenants string
}

func newNeutronStub(t *testing.T) *neutronStub {
	t.Helper()
	ns := &neutronStub{}
	ns.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v3/auth/tokens":
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			ns.serveKeystone(w)
		case "/":
			// gophercloud probes the catalogued endpoint with an
			// HTTP GET to confirm the major API version (see
			// gophercloud/openstack/endpoint.go:endpointSupportsVersion).
			// Real Neutron returns the multi-version document here.
			ns.serveVersionDiscovery(w, r)
		case "/v2.0/networks":
			ns.serveJSON(w, r, ns.networksJSON)
		case "/v2.0/subnets":
			ns.serveJSON(w, r, ns.subnetsJSON)
		case "/v2.0/ports":
			ns.serveJSON(w, r, ns.portsJSON)
		case "/v2.0/routers":
			ns.serveJSON(w, r, ns.routersJSON)
		case "/v3/projects":
			ns.serveJSON(w, r, ns.projectsJSON)
		case "/compute/v2.1/servers/detail":
			ns.serversAllTenants = r.URL.Query().Get("all_tenants")
			ns.serveJSON(w, r, ns.serversJSON)
		default:
			http.NotFound(w, r)
		}
	}))
	return ns
}

func (ns *neutronStub) serveVersionDiscovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{
		"versions": [
			{
				"id": "v2.0",
				"status": "CURRENT",
				"links": [{"href": "%s/v2.0/", "rel": "self"}]
			}
		]
	}`, ns.URL)
}

func (ns *neutronStub) serveJSON(w http.ResponseWriter, r *http.Request, body string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, body)
}

func (ns *neutronStub) serveKeystone(w http.ResponseWriter) {
	w.Header().Set("X-Subject-Token", "tok-stub")
	w.WriteHeader(http.StatusCreated)
	// Catalog URL is the bare server origin; gophercloud's
	// NewNetworkV2 appends `v2.0/` to derive the resource base.
	_ = json.NewEncoder(w).Encode(map[string]any{
		"token": map[string]any{
			"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano),
			"catalog": []any{
				map[string]any{
					"type": "network",
					"name": "neutron",
					"endpoints": []any{
						map[string]any{"interface": "internal", "region": "R1", "region_id": "R1", "url": ns.URL + "/"},
					},
				},
				map[string]any{
					"type": "identity",
					"name": "keystone",
					"endpoints": []any{
						map[string]any{"interface": "internal", "region": "R1", "region_id": "R1", "url": ns.URL + "/v3"},
					},
				},
				map[string]any{
					"type": "compute",
					"name": "nova",
					"endpoints": []any{
						map[string]any{"interface": "internal", "region": "R1", "region_id": "R1", "url": ns.URL + "/compute/v2.1/"},
					},
				},
			},
		},
	})
}

func newListClient(t *testing.T, ns *neutronStub) *Client {
	t.Helper()
	c, err := NewClient(context.Background(), testCreds(ns.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func TestListNetworks(t *testing.T) {
	ns := newNeutronStub(t)
	defer ns.Close()
	ns.networksJSON = `{
		"networks": [
			{"id":"net-A","project_id":"proj-1","name":"net-A","shared":false,"router:external":false},
			{"id":"net-B","tenant_id":"proj-2","name":"net-B","shared":true,"router:external":false},
			{"id":"net-ext","project_id":"proj-admin","name":"public","shared":true,"router:external":true}
		]
	}`
	c := newListClient(t, ns)

	got, err := c.ListNetworks(context.Background())
	if err != nil {
		t.Fatalf("ListNetworks: %v", err)
	}
	want := []Network{
		{ID: "net-A", ProjectID: "proj-1", Name: "net-A", Shared: false, IsExternal: false},
		{ID: "net-B", ProjectID: "proj-2", Name: "net-B", Shared: true, IsExternal: false}, // tenant_id → ProjectID fallback
		{ID: "net-ext", ProjectID: "proj-admin", Name: "public", Shared: true, IsExternal: true},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d networks, want %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("network[%d]\n got:  %+v\n want: %+v", i, got[i], want[i])
		}
	}
}

func TestListSubnets(t *testing.T) {
	ns := newNeutronStub(t)
	defer ns.Close()
	// Two rows: one with project_id, one with tenant_id only.
	// Both must surface ProjectID populated via preferProjectID.
	ns.subnetsJSON = `{
		"subnets": [
			{"id":"sub-A","network_id":"net-A","project_id":"proj-1","cidr":"10.0.0.0/24","gateway_ip":"10.0.0.1","ip_version":4},
			{"id":"sub-B","network_id":"net-B","tenant_id":"proj-2","cidr":"10.1.0.0/24","gateway_ip":"10.1.0.1","ip_version":4}
		]
	}`
	c := newListClient(t, ns)

	got, err := c.ListSubnets(context.Background())
	if err != nil {
		t.Fatalf("ListSubnets: %v", err)
	}
	want := []Subnet{
		{ID: "sub-A", NetworkID: "net-A", ProjectID: "proj-1", CIDR: "10.0.0.0/24", GatewayIP: "10.0.0.1", IPVersion: 4},
		{ID: "sub-B", NetworkID: "net-B", ProjectID: "proj-2", CIDR: "10.1.0.0/24", GatewayIP: "10.1.0.1", IPVersion: 4},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d subnets, want %d: %+v", len(got), len(want), got)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("subnet[%d]\n got:  %+v\n want: %+v", i, got[i], want[i])
		}
	}
}

func TestListPorts(t *testing.T) {
	ns := newNeutronStub(t)
	defer ns.Close()
	// port-C exercises preferProjectID's tenant_id fallback.
	ns.portsJSON = `{
		"ports": [
			{
				"id":"port-A",
				"network_id":"net-A",
				"project_id":"proj-1",
				"mac_address":"fa:16:3e:00:00:01",
				"device_owner":"compute:nova",
				"device_id":"vm-uuid-1",
				"fixed_ips":[
					{"subnet_id":"sub-A","ip_address":"10.0.0.42"},
					{"subnet_id":"sub-A6","ip_address":"fd00::42"}
				]
			},
			{
				"id":"port-B",
				"network_id":"net-A",
				"project_id":"proj-1",
				"mac_address":"fa:16:3e:00:00:02",
				"device_owner":"network:router_interface",
				"device_id":"router-uuid-1",
				"fixed_ips":[{"subnet_id":"sub-A","ip_address":"10.0.0.1"}]
			},
			{
				"id":"port-C",
				"network_id":"net-B",
				"tenant_id":"proj-2",
				"mac_address":"fa:16:3e:00:00:03",
				"device_owner":"compute:nova",
				"fixed_ips":[{"subnet_id":"sub-B","ip_address":"10.1.0.42"}]
			}
		]
	}`
	c := newListClient(t, ns)

	got, err := c.ListPorts(context.Background())
	if err != nil {
		t.Fatalf("ListPorts: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d ports, want 3", len(got))
	}
	if got[0].MACAddress != "fa:16:3e:00:00:01" || got[0].DeviceOwner != "compute:nova" {
		t.Errorf("port[0] = %+v", got[0])
	}
	if len(got[0].FixedIPs) != 2 {
		t.Fatalf("port[0] FixedIPs = %v, want 2", got[0].FixedIPs)
	}
	if got[0].FixedIPs[0] != (FixedIP{SubnetID: "sub-A", IPAddress: "10.0.0.42"}) {
		t.Errorf("FixedIPs[0] = %+v", got[0].FixedIPs[0])
	}
	if got[1].DeviceOwner != "network:router_interface" {
		t.Errorf("port[1] device_owner = %q", got[1].DeviceOwner)
	}
	if got[2].ProjectID != "proj-2" {
		t.Errorf("port[2] ProjectID = %q, want proj-2 (tenant_id fallback)", got[2].ProjectID)
	}
}

func TestListRouters(t *testing.T) {
	ns := newNeutronStub(t)
	defer ns.Close()
	// r-C exercises preferProjectID's tenant_id fallback.
	ns.routersJSON = `{
		"routers": [
			{
				"id":"r-A",
				"project_id":"proj-1",
				"name":"edge",
				"external_gateway_info":{"network_id":"net-EXT"},
				"routes":[
					{"destination":"10.99.0.0/16","nexthop":"10.0.0.2"}
				]
			},
			{
				"id":"r-B",
				"project_id":"proj-2",
				"routes":[]
			},
			{
				"id":"r-C",
				"tenant_id":"proj-3",
				"routes":[]
			}
		]
	}`
	c := newListClient(t, ns)

	got, err := c.ListRouters(context.Background())
	if err != nil {
		t.Fatalf("ListRouters: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d routers, want 3", len(got))
	}
	if got[0].ExternalNetworkID != "net-EXT" {
		t.Errorf("router[0] external = %q, want net-EXT", got[0].ExternalNetworkID)
	}
	if got[0].Name != "edge" {
		t.Errorf("router[0] name = %q, want edge", got[0].Name)
	}
	if len(got[0].Routes) != 1 || got[0].Routes[0] != (Route{Destination: "10.99.0.0/16", Nexthop: "10.0.0.2"}) {
		t.Errorf("router[0] routes = %+v", got[0].Routes)
	}
	if got[1].ExternalNetworkID != "" {
		t.Errorf("router[1] external = %q, want empty (no gateway)", got[1].ExternalNetworkID)
	}
	if len(got[1].Routes) != 0 {
		t.Errorf("router[1] routes = %v, want []", got[1].Routes)
	}
	if got[2].ProjectID != "proj-3" {
		t.Errorf("router[2] ProjectID = %q, want proj-3 (tenant_id fallback)", got[2].ProjectID)
	}
}

func TestListProjects(t *testing.T) {
	ns := newNeutronStub(t)
	defer ns.Close()
	ns.projectsJSON = `{
		"projects": [
			{"id":"proj-1","name":"alpha"},
			{"id":"proj-2","name":"beta"}
		]
	}`
	c := newListClient(t, ns)

	got, err := c.ListProjects(context.Background())
	if err != nil {
		t.Fatalf("ListProjects: %v", err)
	}
	want := []Project{
		{ID: "proj-1", Name: "alpha"},
		{ID: "proj-2", Name: "beta"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d projects, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("project[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestListServers(t *testing.T) {
	ns := newNeutronStub(t)
	defer ns.Close()
	ns.serversJSON = `{
		"servers": [
			{"id":"srv-1","name":"web-0","tenant_id":"proj-1"},
			{"id":"srv-2","name":"db-0","tenant_id":"proj-2"}
		]
	}`
	c := newListClient(t, ns)

	got, err := c.ListServers(context.Background())
	if err != nil {
		t.Fatalf("ListServers: %v", err)
	}
	want := []Server{
		{ID: "srv-1", Name: "web-0", ProjectID: "proj-1"},
		{ID: "srv-2", Name: "db-0", ProjectID: "proj-2"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d servers, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("server[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
	if ns.serversAllTenants != "true" {
		t.Errorf("all_tenants query = %q, want \"true\" (cross-tenant scope)", ns.serversAllTenants)
	}
}

// TestListServersComputeUnavailable pins the graceful path: when the
// catalog carried no Compute endpoint (c.compute is nil), ListServers
// returns an empty list and no error, so the info series is simply
// absent rather than failing the sync.
func TestListServersComputeUnavailable(t *testing.T) {
	c := &Client{} // no compute client
	got, err := c.ListServers(context.Background())
	if err != nil {
		t.Fatalf("ListServers with nil compute: %v", err)
	}
	if got != nil {
		t.Errorf("got %+v, want nil", got)
	}
}

func TestPreferProjectID(t *testing.T) {
	tests := []struct {
		projectID, tenantID, want string
	}{
		{"", "", ""},
		{"p", "", "p"},
		{"", "t", "t"},
		{"p", "t", "p"}, // ProjectID wins when both present
	}
	for _, tc := range tests {
		if got := preferProjectID(tc.projectID, tc.tenantID); got != tc.want {
			t.Errorf("preferProjectID(%q,%q) = %q, want %q",
				tc.projectID, tc.tenantID, got, tc.want)
		}
	}
}
