package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/metadata"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/neutron"
)

// invoke runs the /debug/lookup handler against rawQuery and
// returns the decoded response + status. Tests check the status
// and the populated sub-sections (zone, neutron, mac) rather than
// raw JSON strings; the schema is exercised directly.
func invoke(t *testing.T, a *Agent, rawQuery string) (lookupResult, int) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/debug/lookup?"+rawQuery, nil)
	rec := httptest.NewRecorder()
	a.handleDebugLookup(rec, req)
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	var got lookupResult
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode body: %v\n--- body ---\n%s", err, rec.Body.String())
	}
	return got, rec.Code
}

func TestHandleDebugLookup_MissingParams_400(t *testing.T) {
	a := &Agent{}
	req := httptest.NewRequest(http.MethodGet, "/debug/lookup", nil)
	rec := httptest.NewRecorder()
	a.handleDebugLookup(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "?ip=") {
		t.Errorf("error body missing usage hint: %s", rec.Body.String())
	}
}

func TestHandleDebugLookup_BothIPAndMAC_400(t *testing.T) {
	a := &Agent{}
	req := httptest.NewRequest(http.MethodGet, "/debug/lookup?ip=10.0.0.1&mac=fa:16:3e:00:00:01", nil)
	rec := httptest.NewRecorder()
	a.handleDebugLookup(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleDebugLookup_InvalidIP_400(t *testing.T) {
	a := &Agent{}
	req := httptest.NewRequest(http.MethodGet, "/debug/lookup?ip=not-an-ip", nil)
	rec := httptest.NewRecorder()
	a.handleDebugLookup(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestHandleDebugLookup_InvalidMAC_400(t *testing.T) {
	a := &Agent{}
	req := httptest.NewRequest(http.MethodGet, "/debug/lookup?mac=not-a-mac", nil)
	rec := httptest.NewRecorder()
	a.handleDebugLookup(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestHandleDebugLookup_IPWithTenant_HitsPerTenantRow: the IP
// 10.0.0.5 lives in T1's /24, and the snapshot has a port on it.
// The response should populate Zone (via=tenant) and Neutron
// (Subnet+Network+Port+Owner) and omit MAC.
func TestHandleDebugLookup_IPWithTenant_HitsPerTenantRow(t *testing.T) {
	a := &Agent{}
	snap := &neutron.Snapshot{
		Networks: []neutron.Network{{ID: "n1", Name: "private", ProjectID: "T1"}},
		Subnets:  []neutron.Subnet{{ID: "s1", NetworkID: "n1", CIDR: "10.0.0.0/24", IPVersion: 4}},
		Ports: []neutron.Port{{
			ID: "p1", NetworkID: "n1", ProjectID: "T1",
			MACAddress: "fa:16:3e:00:00:01",
			DeviceOwner: "compute:nova", DeviceID: "vm-uuid",
			FixedIPs: []neutron.FixedIP{{SubnetID: "s1", IPAddress: "10.0.0.5"}},
		}},
		Projects: []neutron.Project{{ID: "T1", Name: "alpha-project"}},
	}
	a.SetNeutronSnapshot(snap)
	a.SetTrieEntries([]neutron.TrieEntry{
		{TenantID: "", Prefix: netip.MustParsePrefix("0.0.0.0/0"), Zone: bpf.ZoneExternal},
		{TenantID: "T1", Prefix: netip.MustParsePrefix("10.0.0.0/24"), Zone: bpf.ZoneSameTenant},
	})

	got, status := invoke(t, a, "ip=10.0.0.5&tenant=T1")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if got.Zone == nil || got.Zone.Code != "SAME_TENANT" || got.Zone.Via != "tenant" {
		t.Errorf("Zone = %+v, want SAME_TENANT via=tenant", got.Zone)
	}
	if got.Zone != nil && got.Zone.Match.TenantName != "alpha-project" {
		t.Errorf("Zone.Match.TenantName = %q, want alpha-project", got.Zone.Match.TenantName)
	}
	if got.Neutron == nil || got.Neutron.Port == nil || got.Neutron.Port.ID != "p1" {
		t.Errorf("Neutron.Port = %+v, want p1", got.Neutron)
	}
	if got.Neutron.Owner == nil || got.Neutron.Owner.Name != "alpha-project" {
		t.Errorf("Neutron.Owner = %+v, want alpha-project", got.Neutron.Owner)
	}
	if got.MAC != nil {
		t.Errorf("MAC = %+v, want nil for IP query", got.MAC)
	}
}

// TestHandleDebugLookup_IPNoTenant_FallsBackToGlobal: omitting
// the tenant takes the global-only path.
func TestHandleDebugLookup_IPNoTenant_FallsBackToGlobal(t *testing.T) {
	a := &Agent{}
	a.SetTrieEntries([]neutron.TrieEntry{
		{TenantID: "", Prefix: netip.MustParsePrefix("0.0.0.0/0"), Zone: bpf.ZoneExternal},
		{TenantID: "T1", Prefix: netip.MustParsePrefix("10.0.0.0/24"), Zone: bpf.ZoneSameTenant},
	})
	got, status := invoke(t, a, "ip=10.0.0.5")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if got.Zone == nil || got.Zone.Code != "EXTERNAL" || got.Zone.Via != "global" {
		t.Fatalf("Zone = %+v, want EXTERNAL via=global", got.Zone)
	}
}

// TestHandleDebugLookup_IPOutsideSnapshot: a valid IP that no
// subnet covers still resolves via the catchall — Zone populated,
// Neutron section omitted.
func TestHandleDebugLookup_IPOutsideSnapshot(t *testing.T) {
	a := &Agent{}
	a.SetNeutronSnapshot(&neutron.Snapshot{})
	a.SetTrieEntries([]neutron.TrieEntry{
		{TenantID: "", Prefix: netip.MustParsePrefix("0.0.0.0/0"), Zone: bpf.ZoneExternal},
	})
	got, status := invoke(t, a, "ip=8.8.8.8")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if got.Zone == nil || got.Zone.Code != "EXTERNAL" {
		t.Errorf("Zone = %+v, want EXTERNAL", got.Zone)
	}
	if got.Neutron != nil {
		t.Errorf("Neutron = %+v, want nil (IP outside every subnet)", got.Neutron)
	}
}

// TestHandleDebugLookup_MAC_FindsPortAndMapEntry: a MAC present in
// both the snapshot and the userspace MAC map fills Neutron (port
// + network + owner) and MAC entry (Found=true with TenantID).
func TestHandleDebugLookup_MAC_FindsPortAndMapEntry(t *testing.T) {
	a := &Agent{meta: metadata.New()}
	mac := "fa:16:3e:ab:cd:01"
	a.SetNeutronSnapshot(&neutron.Snapshot{
		Networks: []neutron.Network{{ID: "n1", Name: "alpha"}},
		Ports: []neutron.Port{{
			ID: "p1", NetworkID: "n1", ProjectID: "T1",
			MACAddress: mac, DeviceOwner: "compute:nova", DeviceID: "vm-uuid",
		}},
		Projects: []neutron.Project{{ID: "T1", Name: "alpha-project"}},
	})
	a.meta.Insert(bpf.MACKey([6]uint8{0xfa, 0x16, 0x3e, 0xab, 0xcd, 0x01}),
		&metadata.TenantMeta{ProjectID: "T1", IsAmphora: false})

	got, status := invoke(t, a, "mac="+mac)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if got.Neutron == nil || got.Neutron.Port == nil || got.Neutron.Port.ID != "p1" {
		t.Errorf("Neutron.Port = %+v, want p1", got.Neutron)
	}
	if got.MAC == nil || !got.MAC.Found || got.MAC.TenantID != "T1" {
		t.Errorf("MAC = %+v, want Found=true tenant=T1", got.MAC)
	}
	if got.MAC != nil && got.MAC.TenantName != "alpha-project" {
		t.Errorf("MAC.TenantName = %q, want alpha-project", got.MAC.TenantName)
	}
	if got.Zone != nil {
		t.Errorf("Zone = %+v, want nil for MAC query", got.Zone)
	}
}

// TestHandleDebugLookup_MAC_NoSnapshotNoMap: a MAC query against a
// freshly-constructed agent (no snapshot, empty MAC map) returns
// Found=false and no Neutron section.
func TestHandleDebugLookup_MAC_NoSnapshotNoMap(t *testing.T) {
	a := &Agent{meta: metadata.New()}
	got, status := invoke(t, a, "mac=fa:16:3e:00:00:99")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if got.MAC == nil || got.MAC.Found {
		t.Errorf("MAC = %+v, want Found=false section", got.MAC)
	}
	if got.Neutron != nil {
		t.Errorf("Neutron = %+v, want nil", got.Neutron)
	}
}

// TestHandleDebugLookup_MAC_CanonicalisesQuery: an uppercase MAC
// input is echoed back in canonical lowercase form, matching the
// snapshot's normalised value.
func TestHandleDebugLookup_MAC_CanonicalisesQuery(t *testing.T) {
	a := &Agent{meta: metadata.New()}
	got, status := invoke(t, a, "mac=FA:16:3E:00:00:01")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if got.Query.MAC != "fa:16:3e:00:00:01" {
		t.Errorf("Query.MAC = %q, want lowercase canonical form", got.Query.MAC)
	}
}
