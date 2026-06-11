package debug

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/neutron"
)

func topologyServer(snap *neutron.Snapshot) *Server {
	opts := Options{
		Snapshot: func() *neutron.Snapshot { return snap },
	}
	if snap != nil {
		opts.LastSync = func() time.Time { return time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC) }
	}
	return New(opts)
}

func TestBuildTopologyDirectoryModel_NilSnapshot(t *testing.T) {
	m := buildTopologyDirectoryModel(nil, time.Time{})
	if len(m.Rows) != 0 || m.Synced {
		t.Fatalf("model = %+v, want empty unsynced", m)
	}
}

func TestBuildTopologyDirectoryModel_CountsAndSorts(t *testing.T) {
	// T1: 2 nets / 1 router, one outgoing attach to T2's net.
	// T2: 1 net / 1 router, one outgoing extraroute to T1's router.
	// T3: 1 net / 0 routers, zero cross-tenant edges (should sort last).
	snap := &neutron.Snapshot{
		Networks: []neutron.Network{
			{ID: "n1a", ProjectID: "T1"},
			{ID: "n1b", ProjectID: "T1"},
			{ID: "n2", ProjectID: "T2"},
			{ID: "n3", ProjectID: "T3"},
		},
		Routers: []neutron.Router{
			{ID: "R1", ProjectID: "T1", Routes: nil},
			{ID: "R2", ProjectID: "T2", Routes: []neutron.Route{
				{Destination: "10.99.0.0/16", Nexthop: "10.0.0.1"},
			}},
		},
		Ports: []neutron.Port{
			{ID: "p1", NetworkID: "n2", DeviceOwner: "network:router_interface", DeviceID: "R1",
				FixedIPs: []neutron.FixedIP{{IPAddress: "192.168.5.1"}}},
			{ID: "p2", NetworkID: "n1a", DeviceOwner: "network:router_interface", DeviceID: "R1",
				FixedIPs: []neutron.FixedIP{{IPAddress: "10.0.0.1"}}},
		},
		Projects: []neutron.Project{
			{ID: "T1", Name: "tenant-one"},
			{ID: "T2", Name: "tenant-two"},
			{ID: "T3", Name: "tenant-three"},
		},
	}

	m := buildTopologyDirectoryModel(snap, time.Now())
	if len(m.Rows) != 3 {
		t.Fatalf("Rows = %d, want 3", len(m.Rows))
	}
	if m.Rows[0].TenantID != "T1" {
		t.Errorf("Rows[0].TenantID = %q, want T1", m.Rows[0].TenantID)
	}
	if m.Rows[1].TenantID != "T2" {
		t.Errorf("Rows[1].TenantID = %q, want T2", m.Rows[1].TenantID)
	}
	if m.Rows[2].TenantID != "T3" || m.Rows[2].CrossTotal != 0 {
		t.Errorf("Rows[2] = %+v, want T3 with CrossTotal=0", m.Rows[2])
	}

	t1 := m.Rows[0]
	if t1.Networks != 2 || t1.Routers != 1 || t1.OutAttach != 1 || t1.InExtra != 1 {
		t.Errorf("T1 row = %+v, want networks=2 routers=1 outAttach=1 inExtra=1", t1)
	}
}

func TestTopology_DirectoryEmptyState(t *testing.T) {
	rec := get(t, New(Options{}).Handler(), "/debug/topology")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "No tenant data yet") {
		t.Errorf("missing empty-state message")
	}
}

func TestTopology_DirectoryRenders(t *testing.T) {
	snap := &neutron.Snapshot{
		Networks: []neutron.Network{{ID: "n1", ProjectID: "T1"}},
		Routers:  []neutron.Router{{ID: "R1", ProjectID: "T1"}},
		Projects: []neutron.Project{{ID: "T1", Name: "tenant-one"}},
	}
	rec := get(t, topologyServer(snap).Handler(), "/debug/topology")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Topology Directory",
		"tenant-one",
		"T1",
		`href="/debug/topology/T1"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in body", want)
		}
	}
}

func TestTopology_DirectoryJSON(t *testing.T) {
	snap := &neutron.Snapshot{
		Networks: []neutron.Network{{ID: "n1", ProjectID: "T1"}},
	}
	rec := get(t, topologyServer(snap).Handler(), "/debug/topology?format=json")
	var m topologyDirectoryModel
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(m.Rows) != 1 || m.Rows[0].Networks != 1 {
		t.Errorf("model = %+v, want one T1 row with 1 network", m)
	}
}

// --- Per-tenant detail page (tables only) ---

func TestBuildTopologyTenantModel_NilSnapshot(t *testing.T) {
	m := buildTopologyTenantModel(nil, "T1", time.Now())
	if !m.NotFound {
		t.Errorf("NotFound = false, want true for nil snapshot")
	}
}

func TestBuildTopologyTenantModel_UnknownTenant(t *testing.T) {
	snap := &neutron.Snapshot{
		Networks: []neutron.Network{{ID: "n1", ProjectID: "T1"}},
	}
	m := buildTopologyTenantModel(snap, "nonexistent", time.Now())
	if !m.NotFound {
		t.Errorf("NotFound = false, want true for unknown tenant")
	}
}

func TestBuildTopologyTenantModel_InternalOnly(t *testing.T) {
	snap := &neutron.Snapshot{
		Networks: []neutron.Network{
			{ID: "n1", ProjectID: "T1", Name: "tenant1-net"},
		},
		Subnets: []neutron.Subnet{
			{ID: "s1", NetworkID: "n1", CIDR: "10.0.1.0/24", IPVersion: 4},
		},
		Ports: []neutron.Port{
			{ID: "p1", NetworkID: "n1", DeviceOwner: "network:router_interface", DeviceID: "R1",
				FixedIPs: []neutron.FixedIP{{IPAddress: "10.0.1.1"}}},
		},
		Routers:  []neutron.Router{{ID: "R1", ProjectID: "T1"}},
		Projects: []neutron.Project{{ID: "T1", Name: "tenant-one"}},
	}
	m := buildTopologyTenantModel(snap, "T1", time.Now())
	if m.NotFound {
		t.Fatal("NotFound=true, want page rendered")
	}
	if len(m.Networks) != 1 || m.Networks[0].ID != "n1" {
		t.Errorf("Networks = %+v, want 1 row for n1", m.Networks)
	}
	if len(m.Routers) != 1 || m.Routers[0].ID != "R1" {
		t.Errorf("Routers = %+v, want 1 router R1", m.Routers)
	}
	if got := len(m.Routers[0].Attachments); got != 1 {
		t.Errorf("R1 attachments = %d, want 1", got)
	}
	if m.Summary.Attachments != 1 || m.Summary.CrossAttach != 0 {
		t.Errorf("Summary = %+v, want Attachments=1 CrossAttach=0", m.Summary)
	}
	if m.TenantName != "tenant-one" {
		t.Errorf("TenantName = %q, want tenant-one", m.TenantName)
	}
}

func TestBuildTopologyTenantModel_CrossTenantSurfaced(t *testing.T) {
	// T1 owns n1 + R1. T2 owns R2 + n2.
	//   - T1's R1 attaches to T2's n2 (cross attach, outgoing for T1).
	//   - T2's R2 extraroutes via T1's R1 (cross extraroute, incoming for T1).
	snap := &neutron.Snapshot{
		Networks: []neutron.Network{
			{ID: "n1", ProjectID: "T1", Name: "tenant1-net"},
			{ID: "n2", ProjectID: "T2", Name: "tenant2-net"},
		},
		Subnets: []neutron.Subnet{
			{ID: "s1", NetworkID: "n1", CIDR: "10.0.1.0/24", IPVersion: 4},
			{ID: "s2", NetworkID: "n2", CIDR: "10.0.2.0/24", IPVersion: 4},
		},
		Ports: []neutron.Port{
			// T1's internal attach.
			{ID: "p1", NetworkID: "n1", DeviceOwner: "network:router_interface", DeviceID: "R1",
				FixedIPs: []neutron.FixedIP{{IPAddress: "10.0.1.1"}}},
			// T1's R1 attaches to T2's n2 — cross-tenant outgoing.
			{ID: "p2", NetworkID: "n2", DeviceOwner: "network:router_interface", DeviceID: "R1",
				FixedIPs: []neutron.FixedIP{{IPAddress: "10.0.2.10"}}},
			// T2's R2 on n2 — nexthop target for the extraroute below.
			{ID: "p3", NetworkID: "n2", DeviceOwner: "network:router_interface", DeviceID: "R2",
				FixedIPs: []neutron.FixedIP{{IPAddress: "10.0.2.1"}}},
		},
		Routers: []neutron.Router{
			{ID: "R1", ProjectID: "T1"},
			{ID: "R2", ProjectID: "T2", Routes: []neutron.Route{
				{Destination: "10.99.0.0/16", Nexthop: "10.0.1.1"},
			}},
		},
		Projects: []neutron.Project{
			{ID: "T1", Name: "tenant-one"},
			{ID: "T2", Name: "tenant-two"},
		},
	}

	m := buildTopologyTenantModel(snap, "T1", time.Now())
	if m.NotFound {
		t.Fatal("NotFound=true, want page rendered")
	}

	// Summary counters track both internal and cross.
	if m.Summary.Attachments != 2 || m.Summary.CrossAttach != 1 {
		t.Errorf("Summary attach = %+v, want Attachments=2 CrossAttach=1", m.Summary)
	}
	if m.Summary.CrossExtraroute != 1 {
		t.Errorf("Summary CrossExtraroute = %d, want 1", m.Summary.CrossExtraroute)
	}

	// R1's attachments include the cross-tenant one with the right tenant badge.
	var crossAttachFound bool
	for _, a := range m.Routers[0].Attachments {
		if a.CrossTenant && a.NetworkTenantID == "T2" && a.NetworkTenantName == "tenant-two" {
			crossAttachFound = true
		}
	}
	if !crossAttachFound {
		t.Errorf("R1's cross-tenant attachment not found in card: %+v", m.Routers[0].Attachments)
	}

	// Flat cross-tenant extraroutes table has the incoming entry.
	if len(m.Extraroutes) != 1 {
		t.Fatalf("Extraroutes = %d, want 1", len(m.Extraroutes))
	}
	xr := m.Extraroutes[0]
	if xr.Direction != "in" || xr.SourceRouterID != "R2" || xr.TargetRouterID != "R1" {
		t.Errorf("Extraroute = %+v, want direction=in source=R2 target=R1", xr)
	}
}

func TestTopologyTenant_RendersTables(t *testing.T) {
	snap := &neutron.Snapshot{
		Networks: []neutron.Network{{ID: "n1", ProjectID: "T1", Name: "tenant1-net"}},
		Subnets:  []neutron.Subnet{{ID: "s1", NetworkID: "n1", CIDR: "10.0.1.0/24", IPVersion: 4}},
		Ports: []neutron.Port{
			{ID: "p1", NetworkID: "n1", DeviceOwner: "network:router_interface", DeviceID: "R1",
				FixedIPs: []neutron.FixedIP{{IPAddress: "10.0.1.1"}}},
		},
		Routers:  []neutron.Router{{ID: "R1", ProjectID: "T1", Name: "edge"}},
		Projects: []neutron.Project{{ID: "T1", Name: "tenant-one"}},
	}
	rec := get(t, topologyServer(snap).Handler(), "/debug/topology/T1")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"tenant-one", "tenant1-net", "10.0.1.0/24", "edge", "R1", "10.0.1.1"} {
		if !strings.Contains(body, want) {
			t.Errorf("tenant page missing %q", want)
		}
	}
}

func TestTopologyTenant_UnknownIsEmptyNot404(t *testing.T) {
	snap := &neutron.Snapshot{
		Networks: []neutron.Network{{ID: "n1", ProjectID: "T1"}},
	}
	rec := get(t, topologyServer(snap).Handler(), "/debug/topology/ghost")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (empty state, not 404)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "No Neutron resources") {
		t.Errorf("missing not-found empty state")
	}
}

func TestTopologyTenant_JSON(t *testing.T) {
	snap := &neutron.Snapshot{
		Networks: []neutron.Network{{ID: "n1", ProjectID: "T1", Name: "net"}},
	}
	rec := get(t, topologyServer(snap).Handler(), "/debug/topology/T1?format=json")
	var m topologyTenantModel
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m.TenantID != "T1" || m.NotFound || m.Summary.Networks != 1 {
		t.Errorf("model = %+v, want T1 with 1 network", m)
	}
}
