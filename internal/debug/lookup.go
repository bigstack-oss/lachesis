package debug

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/bigstack-oss/lachesis/internal/bpf"
	"github.com/bigstack-oss/lachesis/internal/neutron"
)

// /debug/lookup is the JSON tooling endpoint behind the index
// page's lookup form. Supports two query shapes:
//
//	GET /debug/lookup?ip=<addr>[&tenant=<uuid>]
//	GET /debug/lookup?mac=<addr>
//
// Either form returns 200 with a [lookupResult] JSON body — including
// "no hit on any sub-question" results, since the operator needs to
// know what the lookup actually saw. Only malformed / missing
// parameters return 4xx with a {"error": "..."} body. JSON-only:
// the human rendering of the same result lives inline on /debug.

// handleLookup parses the query, dispatches to the IP or MAC path,
// and writes the JSON response.
func (s *Server) handleLookup(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ip := strings.TrimSpace(q.Get("ip"))
	mac := strings.TrimSpace(q.Get("mac"))
	tenant := strings.TrimSpace(q.Get("tenant"))

	if ip == "" && mac == "" {
		writeLookupError(w, http.StatusBadRequest, "provide ?ip=<addr> or ?mac=<addr>")
		return
	}
	result, errMsg := s.runLookup(ip, mac, tenant)
	if errMsg != "" {
		writeLookupError(w, http.StatusBadRequest, errMsg)
		return
	}
	writeLookupJSON(w, http.StatusOK, result)
}

// runLookup performs the validation + dispatch shared by the JSON
// endpoint (/debug/lookup) and the index page form (/debug).
// Returns either a populated [lookupResult] and "", or a zero
// result and a human-readable error string. Empty ip and empty mac
// both yield ("", "") — the caller decides whether that's a 400 or
// "form rendered without a result".
func (s *Server) runLookup(ip, mac, tenant string) (lookupResult, string) {
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
		s.fillIPLookup(&result, addr, tenant)
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
	s.fillMACLookup(&result, hw, canon)
	return result, ""
}

// fillIPLookup populates the Zone and Neutron sections of result
// for an IP-style query. Both sections are independent: a known
// trie row but unknown Neutron port leaves Neutron.Port nil, etc.
func (s *Server) fillIPLookup(result *lookupResult, ip netip.Addr, tenant string) {
	snap := s.opts.Snapshot()
	entries := s.opts.Trie()

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
func (s *Server) fillMACLookup(result *lookupResult, hw net.HardwareAddr, canon string) {
	snap := s.opts.Snapshot()
	m := neutron.LookupPortByMAC(snap, canon)
	result.Neutron = neutronSectionFrom(snap, m)

	var key [6]uint8
	copy(key[:], hw)

	entry := &lookupMACEntry{Found: false}
	if meta, ok := s.opts.MACLookup(bpf.MACKey(key)); ok && meta != nil {
		entry.Found = true
		entry.TenantID = meta.ProjectID
		entry.TenantName = projectName(snap, meta.ProjectID)
		entry.IsAmphora = meta.IsAmphora
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
		slog.Error("encode /debug/lookup failed", "component", componentDebug, "err", err)
	}
}
