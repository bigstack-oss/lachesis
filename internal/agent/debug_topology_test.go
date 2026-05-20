package agent

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/neutron"
)

// --- Directory page (text/HTML table) ---

func TestBuildTopologyDirectoryPage_NilSnapshot(t *testing.T) {
	page := buildTopologyDirectoryPage(nil, time.Now())
	if len(page.Rows) != 0 {
		t.Errorf("Rows = %d, want 0", len(page.Rows))
	}
}

func TestBuildTopologyDirectoryPage_CountsAndSorts(t *testing.T) {
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

	page := buildTopologyDirectoryPage(snap, time.Now())
	if len(page.Rows) != 3 {
		t.Fatalf("Rows = %d, want 3", len(page.Rows))
	}
	if page.Rows[0].TenantID != "T1" {
		t.Errorf("Rows[0].TenantID = %q, want T1", page.Rows[0].TenantID)
	}
	if page.Rows[1].TenantID != "T2" {
		t.Errorf("Rows[1].TenantID = %q, want T2", page.Rows[1].TenantID)
	}
	if page.Rows[2].TenantID != "T3" || page.Rows[2].CrossTotal != 0 {
		t.Errorf("Rows[2] = %+v, want T3 with CrossTotal=0", page.Rows[2])
	}

	t1 := page.Rows[0]
	if t1.Networks != 2 || t1.Routers != 1 || t1.OutAttach != 1 || t1.InExtra != 1 {
		t.Errorf("T1 row = %+v, want networks=2 routers=1 outAttach=1 inExtra=1", t1)
	}
}

func TestHandleDebugTopology_DirectoryEmptyState(t *testing.T) {
	a := &Agent{}
	req := httptest.NewRequest(http.MethodGet, "/debug/topology", nil)
	rec := httptest.NewRecorder()
	a.handleDebugTopology(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "No tenant data yet") {
		t.Errorf("missing empty-state message")
	}
}

func TestHandleDebugTopology_DirectoryRenders(t *testing.T) {
	a := &Agent{}
	a.SetNeutronSnapshot(&neutron.Snapshot{
		Networks: []neutron.Network{{ID: "n1", ProjectID: "T1"}},
		Routers:  []neutron.Router{{ID: "R1", ProjectID: "T1"}},
		Projects: []neutron.Project{{ID: "T1", Name: "tenant-one"}},
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

// --- Per-tenant detail page (text-first + cross-tenant graph) ---

func TestBuildTopologyTenantPage_NilSnapshot(t *testing.T) {
	page, err := buildTopologyTenantPage(nil, "T1", time.Now())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !page.NotFound {
		t.Errorf("NotFound = false, want true for nil snapshot")
	}
}

func TestBuildTopologyTenantPage_UnknownTenant(t *testing.T) {
	snap := &neutron.Snapshot{
		Networks: []neutron.Network{{ID: "n1", ProjectID: "T1"}},
	}
	page, err := buildTopologyTenantPage(snap, "nonexistent", time.Now())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !page.NotFound {
		t.Errorf("NotFound = false, want true for unknown tenant")
	}
}

func TestBuildTopologyTenantPage_InternalOnlyHasNoCrossGraph(t *testing.T) {
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
	page, err := buildTopologyTenantPage(snap, "T1", time.Now())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if page.NotFound {
		t.Fatal("NotFound=true, want page rendered")
	}
	if len(page.Networks) != 1 || page.Networks[0].ID != "n1" {
		t.Errorf("Networks = %+v, want 1 row for n1", page.Networks)
	}
	if len(page.Routers) != 1 || page.Routers[0].ID != "R1" {
		t.Errorf("Routers = %+v, want 1 router R1", page.Routers)
	}
	if got := len(page.Routers[0].Attachments); got != 1 {
		t.Errorf("R1 attachments = %d, want 1", got)
	}
	if page.Summary.Attachments != 1 || page.Summary.CrossAttach != 0 {
		t.Errorf("Summary = %+v, want Attachments=1 CrossAttach=0", page.Summary)
	}
	if len(page.CrossGraph.Nodes) != 0 {
		t.Errorf("CrossGraph nodes = %d, want 0 (no cross-tenant edges)", len(page.CrossGraph.Nodes))
	}
	if page.TenantName != "tenant-one" {
		t.Errorf("TenantName = %q, want tenant-one", page.TenantName)
	}
}

func TestBuildTopologyTenantPage_CrossTenantSurfaced(t *testing.T) {
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

	page, err := buildTopologyTenantPage(snap, "T1", time.Now())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if page.NotFound {
		t.Fatal("NotFound=true, want page rendered")
	}

	// Summary counters track both internal and cross.
	if page.Summary.Attachments != 2 || page.Summary.CrossAttach != 1 {
		t.Errorf("Summary attach = %+v, want Attachments=2 CrossAttach=1", page.Summary)
	}
	if page.Summary.CrossExtraroute != 1 {
		t.Errorf("Summary CrossExtraroute = %d, want 1", page.Summary.CrossExtraroute)
	}

	// R1's attachments include the cross-tenant one with the right tenant badge.
	var crossAttachFound bool
	for _, a := range page.Routers[0].Attachments {
		if a.CrossTenant && a.NetworkTenantID == "T2" && a.NetworkTenantName == "tenant-two" {
			crossAttachFound = true
		}
	}
	if !crossAttachFound {
		t.Errorf("R1's cross-tenant attachment not found in card: %+v", page.Routers[0].Attachments)
	}

	// Flat cross-tenant extraroutes table has the incoming entry.
	if len(page.Extraroutes) != 1 {
		t.Fatalf("Extraroutes = %d, want 1", len(page.Extraroutes))
	}
	xr := page.Extraroutes[0]
	if xr.Direction != "in" || xr.SourceRouterID != "R2" || xr.TargetRouterID != "R1" {
		t.Errorf("Extraroute = %+v, want direction=in source=R2 target=R1", xr)
	}

	// CrossGraph: 2 cross-tenant edges → R1, n2, R2 nodes. n1 should NOT be there.
	wantNodes := map[string]bool{"R1": false, "n2": false, "R2": false}
	for _, n := range page.CrossGraph.Nodes {
		if _, ok := wantNodes[n.ID]; ok {
			wantNodes[n.ID] = true
		}
		if n.ID == "n1" {
			t.Errorf("CrossGraph should not include internal-only node n1")
		}
	}
	for id, seen := range wantNodes {
		if !seen {
			t.Errorf("CrossGraph missing expected node %q", id)
		}
	}

	// Boundary nodes should carry their owning tenant via the
	// TenantName field — the template's hover panel reads this to
	// show "Project: tenant-two (T2)" without re-parsing the label.
	for _, n := range page.CrossGraph.Nodes {
		if strings.Contains(n.Kind, "boundary") && n.TenantName != "tenant-two" {
			t.Errorf("boundary node %q TenantName = %q, want tenant-two", n.ID, n.TenantName)
		}
	}
}

func TestHandleDebugTopologyTenant_RendersTablesAndGraphScript(t *testing.T) {
	a := &Agent{}
	a.SetNeutronSnapshot(&neutron.Snapshot{
		Networks: []neutron.Network{
			{ID: "n1", ProjectID: "T1", Name: "tenant1-net"},
			{ID: "n2", ProjectID: "T2", Name: "tenant2-net"},
		},
		Ports: []neutron.Port{
			{ID: "p1", NetworkID: "n2", DeviceOwner: "network:router_interface", DeviceID: "R1",
				FixedIPs: []neutron.FixedIP{{IPAddress: "10.0.2.10"}}},
		},
		Routers:  []neutron.Router{{ID: "R1", ProjectID: "T1"}},
		Projects: []neutron.Project{
			{ID: "T1", Name: "tenant-one"},
			{ID: "T2", Name: "tenant-two"},
		},
	})
	a.MarkNeutronSync(time.Now())

	req := httptest.NewRequest(http.MethodGet, "/debug/topology/T1", nil)
	req.SetPathValue("tenant", "T1")
	rec := httptest.NewRecorder()
	a.handleDebugTopologyTenant(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"tenant-one",
		"<h2>Networks",
		"<h2>Routers",
		"tenant1-net",
		"R1",
		"<h2>Cross-tenant relationships",
		"/debug/static/cytoscape.min.js",
		`href="/debug/topology/T2"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in body", want)
		}
	}
}

func TestHandleDebugTopologyTenant_NoCrossGraphWhenIsolated(t *testing.T) {
	a := &Agent{}
	a.SetNeutronSnapshot(&neutron.Snapshot{
		Networks: []neutron.Network{{ID: "n1", ProjectID: "T1", Name: "tenant1-net"}},
		Routers:  []neutron.Router{{ID: "R1", ProjectID: "T1"}},
		Projects: []neutron.Project{{ID: "T1", Name: "tenant-one"}},
	})

	req := httptest.NewRequest(http.MethodGet, "/debug/topology/T1", nil)
	req.SetPathValue("tenant", "T1")
	rec := httptest.NewRecorder()
	a.handleDebugTopologyTenant(rec, req)

	body := rec.Body.String()
	// Isolated tenant: no cross-tenant relationships section.
	if strings.Contains(body, "Cross-tenant relationships") {
		t.Errorf("isolated tenant should not render cross-tenant section")
	}
	// And no Cytoscape script (since there's no graph to render).
	if strings.Contains(body, "/debug/static/cytoscape.min.js") {
		t.Errorf("isolated tenant should not pull in cytoscape script")
	}
}

func TestHandleDebugTopologyTenant_UnknownIsEmptyNot404(t *testing.T) {
	a := &Agent{}
	a.SetNeutronSnapshot(&neutron.Snapshot{
		Networks: []neutron.Network{{ID: "n1", ProjectID: "T1"}},
	})

	req := httptest.NewRequest(http.MethodGet, "/debug/topology/missing", nil)
	req.SetPathValue("tenant", "missing")
	rec := httptest.NewRecorder()
	a.handleDebugTopologyTenant(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (empty state, not 404)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "No Neutron resources") {
		t.Errorf("missing empty-state message")
	}
}
