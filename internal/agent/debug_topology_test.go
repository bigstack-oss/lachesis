package agent

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/neutron"
)

func TestBuildTopologyPage_NilSnapshot(t *testing.T) {
	page, err := buildTopologyPage(nil, time.Now())
	if err != nil {
		t.Fatalf("buildTopologyPage(nil): %v", err)
	}
	if len(page.Graph.Nodes) != 0 {
		t.Errorf("Nodes = %d, want 0", len(page.Graph.Nodes))
	}
	if len(page.Tenants) != 0 {
		t.Errorf("Tenants = %d, want 0", len(page.Tenants))
	}
}

func TestBuildTopologyPage_SingleTenantTopology(t *testing.T) {
	snap := &neutron.Snapshot{
		Networks: []neutron.Network{
			{ID: "net-T1", ProjectID: "T1", Name: "net-T1"},
			{ID: "ext", ProjectID: "admin", Name: "ext", IsExternal: true},
		},
		Subnets: []neutron.Subnet{
			{ID: "sub-T1", NetworkID: "net-T1", ProjectID: "T1", CIDR: "10.0.1.0/24", IPVersion: 4},
		},
		Ports: []neutron.Port{
			{
				ID: "p-rif", NetworkID: "net-T1", ProjectID: "T1",
				DeviceOwner: "network:router_interface", DeviceID: "R1",
				FixedIPs:    []neutron.FixedIP{{SubnetID: "sub-T1", IPAddress: "10.0.1.1"}},
			},
		},
		Routers: []neutron.Router{
			{ID: "R1", ProjectID: "T1", ExternalNetworkID: "ext"},
		},
	}
	page, err := buildTopologyPage(snap, time.Time{})
	if err != nil {
		t.Fatalf("buildTopologyPage: %v", err)
	}

	// 2 networks + 1 router
	if got := len(page.Graph.Nodes); got != 3 {
		t.Errorf("nodes = %d, want 3", got)
	}
	// 1 attach edge (R1 → net-T1) + 1 gateway edge (R1 → ext)
	if got := len(page.Graph.Edges); got != 2 {
		t.Fatalf("edges = %d, want 2", got)
	}
	var kinds []string
	for _, e := range page.Graph.Edges {
		kinds = append(kinds, e.Kind)
	}
	wantKinds := map[string]bool{"attach": false, "gateway": false}
	for _, k := range kinds {
		wantKinds[k] = true
	}
	for k, seen := range wantKinds {
		if !seen {
			t.Errorf("missing %q edge", k)
		}
	}
	// Subnet CIDR should be in the network label.
	var netLabel string
	for _, n := range page.Graph.Nodes {
		if n.ID == "net-T1" {
			netLabel = n.Label
			break
		}
	}
	if !strings.Contains(netLabel, "10.0.1.0/24") {
		t.Errorf("net-T1 label %q missing subnet CIDR", netLabel)
	}
	// External network gets the network-external kind.
	for _, n := range page.Graph.Nodes {
		if n.ID == "ext" && n.Kind != "network-external" {
			t.Errorf("ext kind = %q, want network-external", n.Kind)
		}
	}
}

func TestBuildTopologyPage_ExtraroutesResolveOnlyToRouters(t *testing.T) {
	snap := &neutron.Snapshot{
		Networks: []neutron.Network{
			{ID: "transit", ProjectID: "admin", Name: "transit", Shared: true},
		},
		Subnets: []neutron.Subnet{
			{ID: "sub-tr", NetworkID: "transit", ProjectID: "admin", CIDR: "10.10.0.0/24", IPVersion: 4},
		},
		Ports: []neutron.Port{
			{
				ID: "p-R1", NetworkID: "transit", ProjectID: "T1",
				DeviceOwner: "network:router_interface", DeviceID: "R1",
				FixedIPs:    []neutron.FixedIP{{SubnetID: "sub-tr", IPAddress: "10.10.0.1"}},
			},
			{
				ID: "p-R2", NetworkID: "transit", ProjectID: "T2",
				DeviceOwner: "network:router_interface", DeviceID: "R2",
				FixedIPs:    []neutron.FixedIP{{SubnetID: "sub-tr", IPAddress: "10.10.0.2"}},
			},
			{
				ID: "p-vm", NetworkID: "transit", ProjectID: "T3",
				DeviceOwner: "compute:nova", DeviceID: "vm-1",
				FixedIPs:    []neutron.FixedIP{{SubnetID: "sub-tr", IPAddress: "10.10.0.99"}},
			},
		},
		Routers: []neutron.Router{
			{ID: "R1", ProjectID: "T1", Routes: []neutron.Route{
				{Destination: "10.99.0.0/16", Nexthop: "10.10.0.2"},   // resolves to R2
				{Destination: "10.88.0.0/16", Nexthop: "10.10.0.99"},  // hits VM port, skip
				{Destination: "10.77.0.0/16", Nexthop: "10.10.0.250"}, // unresolvable, skip
			}},
			{ID: "R2", ProjectID: "T2"},
		},
	}
	page, err := buildTopologyPage(snap, time.Time{})
	if err != nil {
		t.Fatalf("buildTopologyPage: %v", err)
	}

	var xrtCount int
	var xrtTarget string
	for _, e := range page.Graph.Edges {
		if e.Kind == "extraroute" {
			xrtCount++
			xrtTarget = e.Target
		}
	}
	if xrtCount != 1 {
		t.Errorf("extraroute edges = %d, want exactly 1 (VM nexthop + unresolvable must skip)", xrtCount)
	}
	if xrtTarget != "R2" {
		t.Errorf("extraroute target = %q, want R2", xrtTarget)
	}

	// Tenants list should include T1, T2 (from routers) and admin (from network).
	want := map[string]bool{"T1": true, "T2": true, "admin": true}
	if len(page.Tenants) != len(want) {
		t.Fatalf("tenants = %v, want keys %v", page.Tenants, want)
	}
	for _, tt := range page.Tenants {
		if !want[tt] {
			t.Errorf("unexpected tenant %q", tt)
		}
	}
}

func TestHandleDebugTopology_EmptyState(t *testing.T) {
	a := &Agent{}
	req := httptest.NewRequest(http.MethodGet, "/debug/topology", nil)
	rec := httptest.NewRecorder()
	a.handleDebugTopology(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "No topology data yet") {
		t.Errorf("missing empty-state message")
	}
}

func TestHandleDebugTopology_RendersGraph(t *testing.T) {
	a := &Agent{}
	a.SetNeutronSnapshot(&neutron.Snapshot{
		Networks: []neutron.Network{{ID: "net-T1", ProjectID: "T1", Name: "net-T1"}},
		Routers:  []neutron.Router{{ID: "R1", ProjectID: "T1"}},
	})
	a.MarkNeutronSync(time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC))

	req := httptest.NewRequest(http.MethodGet, "/debug/topology", nil)
	rec := httptest.NewRecorder()
	a.handleDebugTopology(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Topology",
		"net-T1", "R1", "T1",
		"/debug/static/cytoscape.min.js",
		"2026-05-20T12:00:00Z",
		`<div id="cy">`,
		`<select id="tenant">`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in body", want)
		}
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
}
