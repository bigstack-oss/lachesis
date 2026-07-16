package debug

import (
	"net"
	"net/http"
	"sort"
	"strings"

	"github.com/bigstack-oss/lachesis/internal/bpf"
)

// /debug/flows is the JSON tooling endpoint over the agent's live flow
// rows (GlobalState): GET /debug/flows?mac=<addr> returns every row
// whose key carries that MAC on either side, with the key decoded to
// operator-readable fields. This is how attribution is verified at
// flow granularity — "which peer actually carried these bytes" — both
// by operators debugging a label and by scenariotest's flow-level
// assertions. The mac parameter is mandatory: an unfiltered dump of a
// production GlobalState would be enormous and never what an operator
// wants from a browser.

// flowRow is one decoded GlobalState row.
type flowRow struct {
	SrcMAC    string `json:"src_mac"`
	DstMAC    string `json:"dst_mac"`
	Direction string `json:"direction"`
	Zone      string `json:"zone"`
	Bytes     uint64 `json:"bytes"`
	Packets   uint64 `json:"packets"`
}

type flowsResult struct {
	MAC   string    `json:"mac"`
	Total int       `json:"total"`
	Rows  []flowRow `json:"rows"`
}

// handleFlows parses ?mac=, filters the live snapshot, and writes the
// JSON response. 400 on a missing/malformed MAC; an agent without a
// flows accessor (nil option) serves an empty result rather than 404,
// so consumers can distinguish "no such flows" from "no such endpoint".
func (s *Server) handleFlows(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("mac"))
	if q == "" {
		writeLookupError(w, http.StatusBadRequest, "provide ?mac=<addr>")
		return
	}
	hw, err := net.ParseMAC(q)
	if err != nil || len(hw) != 6 {
		writeLookupError(w, http.StatusBadRequest, "malformed mac: "+q)
		return
	}
	var key [6]uint8
	copy(key[:], hw)
	want := bpf.MACKey(key)

	result := flowsResult{MAC: hw.String(), Rows: []flowRow{}}
	if s.opts.Flows != nil {
		for _, e := range s.opts.Flows() {
			if bpf.MACKey(e.Key.SrcMac) != want && bpf.MACKey(e.Key.DstMac) != want {
				continue
			}
			result.Rows = append(result.Rows, flowRow{
				SrcMAC:    macString(e.Key.SrcMac),
				DstMAC:    macString(e.Key.DstMac),
				Direction: e.Key.Direction.String(),
				Zone:      e.Key.DstZone.String(),
				Bytes:     e.Total.Bytes,
				Packets:   e.Total.Packets,
			})
		}
	}
	sort.Slice(result.Rows, func(i, j int) bool { return result.Rows[i].Bytes > result.Rows[j].Bytes })
	result.Total = len(result.Rows)
	writeLookupJSON(w, http.StatusOK, result)
}

func macString(m [6]uint8) string {
	return net.HardwareAddr(m[:]).String()
}
