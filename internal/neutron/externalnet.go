// externalnet.go resolves each VM port's external-network attribution —
// the source of the `external_network` metric label and the per-server
// export dimension. Pure functions over a Snapshot, mirroring the trie
// builder's style: no I/O, no retention.
//
// Full rationale: docs/architecture/billing.md

package neutron

import (
	"log/slog"
	"net"
	"sort"

	"github.com/bigstack-oss/lachesis/internal/bpf"
)

// ExternalNetworkByPort maps each VM port to the external network its
// egress leaves through: a bound floating IP wins (OVN NATs through it
// whichever router carries the traffic), else the external gateway of
// an attached router. Ports with neither are absent. The label is the
// network Name, which is what rate tables key on.
//
// A multi-homed VM gets ONE attribution, picked deterministically, so
// an unchanged topology never flaps and re-labels live series.
func ExternalNetworkByPort(snap *Snapshot) map[string]string {
	out := make(map[string]string)
	for portID, c := range externalCandidatesByPort(snap) {
		out[portID] = c.picked
		if len(c.candidates) > 1 {
			slog.Debug("VM port has multiple external paths; attributed to one deterministically",
				"component", componentNeutron, "port_id", portID,
				"picked", c.picked, "candidates", c.candidates)
		}
	}
	return out
}

// detectMultiExternalPaths reports every VM port whose external
// attribution was ambiguous — the anomaly-side view of the same
// computation [ExternalNetworkByPort] resolves. Pure function, no
// logging (the anomaly framework owns surfacing). Output order: by
// PortID ascending, stable across runs on identical input.
func detectMultiExternalPaths(snap Snapshot) []MultiExternalPathHit {
	byPort := externalCandidatesByPort(&snap)
	meta := make(map[string]Port, len(snap.Ports))
	for _, p := range snap.Ports {
		meta[p.ID] = p
	}
	var out []MultiExternalPathHit
	for portID, c := range byPort {
		if len(c.candidates) < 2 {
			continue
		}
		p := meta[portID]
		out = append(out, MultiExternalPathHit{
			PortID:     portID,
			ServerID:   p.DeviceID,
			ProjectID:  p.ProjectID,
			Candidates: c.candidates,
			Picked:     c.picked,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PortID < out[j].PortID })
	return out
}

// portCandidates is one VM port's resolved external paths: the sorted
// distinct candidate labels and the deterministic pick.
type portCandidates struct {
	candidates []string
	picked     string
}

// externalCandidatesByPort computes each VM port's external-network
// candidates — the single source both [ExternalNetworkByPort] (the
// attribution) and [detectMultiExternalPaths] (the anomaly view)
// derive from, so the two can never disagree about what "ambiguous"
// means. Ports with no external path are absent from the map.
func externalCandidatesByPort(snap *Snapshot) map[string]portCandidates {
	netLabel := make(map[string]string, len(snap.Networks))
	for _, n := range snap.Networks {
		if n.Name != "" {
			netLabel[n.ID] = n.Name
		} else {
			netLabel[n.ID] = n.ID
		}
	}

	// Tier 2: subnet → external label via attached routers, built first
	// so FIP hits can shadow it. Only one interface holds a subnet's
	// gateway_ip and the VMs' default route points there, so that router
	// is authoritative for SNAT. Others count only when no
	// gateway-owning router has an external gateway — the documented
	// unsolvable case (edge-cases.md row 9).
	routerExt := make(map[string]string) // routerID → ext label
	for _, r := range snap.Routers {
		if r.ExternalNetworkID != "" {
			routerExt[r.ID] = netLabel[r.ExternalNetworkID]
		}
	}
	subnetGateway := make(map[string]string, len(snap.Subnets)) // subnetID → gateway IP
	for _, s := range snap.Subnets {
		subnetGateway[s.ID] = s.GatewayIP
	}
	gwExt := make(map[string][]string)  // subnetID → labels via the gateway-owning router
	anyExt := make(map[string][]string) // subnetID → labels via any attached router
	for _, p := range snap.Ports {
		if p.DeviceOwner != DeviceOwnerRouterInterface {
			continue
		}
		ext, ok := routerExt[p.DeviceID]
		if !ok {
			continue
		}
		for _, fip := range p.FixedIPs {
			anyExt[fip.SubnetID] = append(anyExt[fip.SubnetID], ext)
			if gw := subnetGateway[fip.SubnetID]; gw != "" && fip.IPAddress == gw {
				gwExt[fip.SubnetID] = append(gwExt[fip.SubnetID], ext)
			}
		}
	}
	subnetExt := func(subnetID string) []string {
		if ext := gwExt[subnetID]; len(ext) > 0 {
			return ext
		}
		return anyExt[subnetID]
	}

	fipExt := make(map[string][]string) // portID → candidate labels
	for _, f := range snap.FloatingIPs {
		if f.PortID == "" || f.FloatingNetworkID == "" {
			continue
		}
		fipExt[f.PortID] = append(fipExt[f.PortID], netLabel[f.FloatingNetworkID])
	}

	out := make(map[string]portCandidates)
	for _, p := range snap.Ports {
		if !IsVMPort(p.DeviceOwner) {
			continue
		}
		raw := fipExt[p.ID]
		if len(raw) == 0 {
			for _, fip := range p.FixedIPs {
				raw = append(raw, subnetExt(fip.SubnetID)...)
			}
		}
		candidates := dedupe(raw)
		if len(candidates) == 0 {
			continue
		}
		out[p.ID] = portCandidates{candidates: candidates, picked: candidates[0]}
	}
	return out
}

// dedupe returns the sorted distinct non-empty values of in. Sorting
// is what makes the pick deterministic: candidates[0] is the
// lexicographically smallest label.
func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	for _, s := range in {
		if s != "" {
			seen[s] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// RouterExtMACs maps each router-interface MAC to its router's external
// network — the per-flow attribution for routed external traffic, since
// such a flow's peer MAC IS that interface. Relies on OVN's unique
// per-interface MAC, which the duplicate_router_mac anomaly asserts.
func RouterExtMACs(snap *Snapshot) map[uint64]string {
	netLabel := make(map[string]string, len(snap.Networks))
	for _, n := range snap.Networks {
		if n.Name != "" {
			netLabel[n.ID] = n.Name
		} else {
			netLabel[n.ID] = n.ID
		}
	}
	routerExt := make(map[string]string, len(snap.Routers))
	for _, r := range snap.Routers {
		if r.ExternalNetworkID != "" {
			routerExt[r.ID] = netLabel[r.ExternalNetworkID]
		}
	}
	out := make(map[uint64]string)
	for _, p := range snap.Ports {
		if p.DeviceOwner != DeviceOwnerRouterInterface {
			continue
		}
		ext, ok := routerExt[p.DeviceID]
		if !ok {
			continue
		}
		hw, err := net.ParseMAC(p.MACAddress)
		if err != nil || len(hw) != 6 {
			continue
		}
		var key [6]uint8
		copy(key[:], hw)
		out[bpf.MACKey(key)] = ext
	}
	return out
}
