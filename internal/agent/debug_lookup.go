package agent

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/neutron"
)

// /debug/lookup is the JSON tooling endpoint behind the landing
// page's lookup form. Supports two query shapes:
//
//	GET /debug/lookup?ip=<addr>[&tenant=<uuid>]
//	GET /debug/lookup?mac=<addr>
//
// Either form returns 200 with a [lookupResult] JSON body — including
// "no hit on any sub-question" results, since the operator needs to
// know what the lookup actually saw. Only malformed / missing
// parameters return 4xx with a {"error": "..."} body.

// lookupResult is the JSON envelope. Each sub-section corresponds
// to one independently-resolved question: zone classification,
// owning Neutron resource, MAC→tenant map entry. A query
// populates the sections relevant to its inputs; the others are
// omitted (omitempty on the field).
type lookupResult struct {
	Query   lookupQuery     `json:"query"`
	Zone    *lookupZone     `json:"zone,omitempty"`
	Neutron *lookupNeutron  `json:"neutron,omitempty"`
	MAC     *lookupMACEntry `json:"mac_tenant_map,omitempty"`
}

type lookupQuery struct {
	IP     string `json:"ip,omitempty"`
	MAC    string `json:"mac,omitempty"`
	Tenant string `json:"tenant,omitempty"`
}

// lookupZone reports the trie row the kernel would match for the
// queried IP. Via is "tenant" when a per-tenant row matched, or
// "global" when the catchall / sentinel rows did.
type lookupZone struct {
	Code  string        `json:"code"`
	Via   string        `json:"via"`
	Match lookupTrieRow `json:"matched_row"`
}

type lookupTrieRow struct {
	TenantID   string `json:"tenant_id"`
	TenantName string `json:"tenant_name,omitempty"`
	Prefix     string `json:"prefix"`
	Zone       string `json:"zone"`
}

// lookupNeutron describes which Neutron resources own the queried
// address. Any field may be nil — see [neutron.LookupResource] and
// [neutron.LookupPortByMAC] for which combinations are produced.
type lookupNeutron struct {
	Subnet  *lookupSubnet  `json:"subnet,omitempty"`
	Network *lookupNetwork `json:"network,omitempty"`
	Port    *lookupPort    `json:"port,omitempty"`
	Owner   *lookupTenant  `json:"owner,omitempty"`
}

type lookupSubnet struct {
	ID        string `json:"id"`
	CIDR      string `json:"cidr"`
	GatewayIP string `json:"gateway_ip,omitempty"`
}

type lookupNetwork struct {
	ID         string `json:"id"`
	Name       string `json:"name,omitempty"`
	Shared     bool   `json:"shared,omitempty"`
	IsExternal bool   `json:"external,omitempty"`
}

type lookupPort struct {
	ID          string `json:"id"`
	MAC         string `json:"mac,omitempty"`
	DeviceOwner string `json:"device_owner,omitempty"`
	DeviceID    string `json:"device_id,omitempty"`
}

type lookupTenant struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

// lookupMACEntry reports what the userspace `mac_tenant_map`
// mirror has for the queried MAC. Found=false with an otherwise
// empty struct distinguishes "MAC absent from the map" from "no
// MAC query made" — the latter omits the whole section.
type lookupMACEntry struct {
	Found      bool   `json:"found"`
	TenantID   string `json:"tenant_id,omitempty"`
	TenantName string `json:"tenant_name,omitempty"`
	IsAmphora  bool   `json:"is_amphora,omitempty"`
}

// handleDebugLookup parses the query, dispatches to the IP or MAC
// path, and writes the JSON response. Validation errors are 4xx;
// "no match" results are still 200 — the operator wants to see
// the empty sections, not retry.
func (a *Agent) handleDebugLookup(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ip := strings.TrimSpace(q.Get("ip"))
	mac := strings.TrimSpace(q.Get("mac"))
	tenant := strings.TrimSpace(q.Get("tenant"))

	if ip == "" && mac == "" {
		writeLookupError(w, http.StatusBadRequest, "provide ?ip=<addr> or ?mac=<addr>")
		return
	}
	result, errMsg := a.runLookup(ip, mac, tenant)
	if errMsg != "" {
		writeLookupError(w, http.StatusBadRequest, errMsg)
		return
	}
	writeLookupJSON(w, http.StatusOK, result)
}

// runLookup performs the validation + dispatch shared by the JSON
// endpoint (/debug/lookup) and the landing page (/debug). Returns
// either a populated [lookupResult] and "", or a zero result and a
// human-readable error string. Empty ip and empty mac both yield
// ("", "") — the caller decides whether that's a 400 or "form
// rendered without a result".
func (a *Agent) runLookup(ip, mac, tenant string) (lookupResult, string) {
	if ip == "" && mac == "" {
		return lookupResult{}, ""
	}
	if ip != "" && mac != "" {
		return lookupResult{}, "specify either ip or mac, not both"
	}
	result := lookupResult{Query: lookupQuery{IP: ip, MAC: mac, Tenant: tenant}}
	if ip != "" {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return lookupResult{}, "invalid ip: " + err.Error()
		}
		a.fillIPLookup(&result, addr, tenant)
		return result, ""
	}
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 {
		msg := "invalid mac"
		if err != nil {
			msg += ": " + err.Error()
		}
		return lookupResult{}, msg
	}
	canon := hw.String()
	result.Query.MAC = canon
	a.fillMACLookup(&result, hw, canon)
	return result, ""
}

// fillIPLookup populates the Zone and Neutron sections of result
// for an IP-style query. Both sections are independent: a known
// trie row but unknown Neutron port leaves Neutron.Port nil, etc.
func (a *Agent) fillIPLookup(result *lookupResult, ip netip.Addr, tenant string) {
	snap := a.NeutronSnapshot()
	entries := a.TrieEntries()

	if row, via := neutron.LookupZone(entries, ip, tenant); row != nil {
		result.Zone = &lookupZone{
			Code: row.Zone.String(),
			Via:  via,
			Match: lookupTrieRow{
				TenantID:   row.TenantID,
				TenantName: projectName(snap, row.TenantID),
				Prefix:     row.Prefix.String(),
				Zone:       row.Zone.String(),
			},
		}
	}

	m := neutron.LookupResource(snap, ip, tenant)
	result.Neutron = neutronSectionFrom(snap, m)
}

// fillMACLookup populates the Neutron and MAC sections for a
// MAC-style query. hw is the parsed 6-byte form (for the
// `mac_tenant_map` lookup); canon is the lowercase colon-separated
// string form (for the Neutron port match).
func (a *Agent) fillMACLookup(result *lookupResult, hw net.HardwareAddr, canon string) {
	snap := a.NeutronSnapshot()
	m := neutron.LookupPortByMAC(snap, canon)
	result.Neutron = neutronSectionFrom(snap, m)

	var key [6]uint8
	copy(key[:], hw)
	macKey := bpf.MACKey(key)

	entry := &lookupMACEntry{Found: false}
	if a.meta != nil {
		if meta, ok := a.meta.Lookup(macKey); ok {
			entry.Found = true
			entry.TenantID = meta.ProjectID
			entry.TenantName = projectName(snap, meta.ProjectID)
			entry.IsAmphora = meta.IsAmphora
		}
	}
	result.MAC = entry
}

// neutronSectionFrom converts a [neutron.ResourceMatch] into the
// JSON sub-struct. Returns nil when every field is unset so the
// outer envelope's omitempty kicks in.
func neutronSectionFrom(snap *neutron.Snapshot, m neutron.ResourceMatch) *lookupNeutron {
	if m.Subnet == nil && m.Network == nil && m.Port == nil {
		return nil
	}
	out := &lookupNeutron{}
	if m.Subnet != nil {
		out.Subnet = &lookupSubnet{
			ID:        m.Subnet.ID,
			CIDR:      m.Subnet.CIDR,
			GatewayIP: m.Subnet.GatewayIP,
		}
	}
	if m.Network != nil {
		out.Network = &lookupNetwork{
			ID:         m.Network.ID,
			Name:       m.Network.Name,
			Shared:     m.Network.Shared,
			IsExternal: m.Network.IsExternal,
		}
	}
	if m.Port != nil {
		out.Port = &lookupPort{
			ID:          m.Port.ID,
			MAC:         m.Port.MACAddress,
			DeviceOwner: m.Port.DeviceOwner,
			DeviceID:    m.Port.DeviceID,
		}
	}
	// Owner: port's ProjectID first (the L2 binding), else
	// network's (for unallocated addresses inside a known subnet).
	var ownerID string
	switch {
	case m.Port != nil && m.Port.ProjectID != "":
		ownerID = m.Port.ProjectID
	case m.Network != nil && m.Network.ProjectID != "":
		ownerID = m.Network.ProjectID
	}
	if ownerID != "" {
		out.Owner = &lookupTenant{ID: ownerID, Name: projectName(snap, ownerID)}
	}
	return out
}

// projectName resolves a project UUID through the snapshot's
// project list. Empty in / empty out so callers don't have to
// guard on missing snapshots.
func projectName(snap *neutron.Snapshot, id string) string {
	if snap == nil || id == "" {
		return ""
	}
	if name := snap.ProjectName(id); name != id {
		return name
	}
	return ""
}

// writeLookupError writes a uniform `{"error": "..."}` body at the
// given status code. Centralised so curl users see one shape.
func writeLookupError(w http.ResponseWriter, status int, msg string) {
	writeLookupJSON(w, status, map[string]string{"error": msg})
}

// writeLookupJSON marshals body with indentation (operators run
// this through curl + eyeballs more than through jq) and logs an
// encode failure since the operator can't see the response anyway.
func writeLookupJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(body); err != nil {
		slog.Error("encode /debug/lookup failed", "component", "debug", "err", err)
	}
}
