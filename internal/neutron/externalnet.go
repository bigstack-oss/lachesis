// externalnet.go resolves each VM port's external-network attribution —
// the source of the `external_network` metric label and the per-server
// export dimension (docs/architecture/billing.md). Pure functions over a
// Snapshot, mirroring the trie builder's style: no I/O, no retention.

package neutron

import (
	"log/slog"
	"net"
	"sort"

	"github.com/bigstack-oss/lachesis/internal/bpf"
)

// ExternalNetworkByPort maps each VM port ID to the label of the
// external network its egress leaves through:
//
//  1. A floating IP bound to the port pins it to the FIP's network —
//     the strongest signal, because OVN NATs the VM's external traffic
//     through the FIP regardless of which router carries it.
//  2. Otherwise, the external gateway of a router attached to any of
//     the port's subnets: traffic leaves via the router's
//     `external_gateway_info` network (SNAT).
//
// Ports with neither path are absent from the map — their VMs have no
// external attribution and emit the [metadata.NoExternalNetwork]
// sentinel via the zone gate.
//
// The label is the network's operator-assigned Name, falling back to
// its ID when the name is empty — names are what dashboards and rate
// tables key on ("public-1" vs "public-2").
//
// Known limitation (first cut, tracked on the metadata task): a VM
// with multiple external paths gets ONE attribution, chosen
// deterministically (lexicographically smallest label, FIP tier
// first) so successive syncs over an unchanged topology attribute
// identically — an attribution flap would needlessly settle-and-
// relabel live series every reconcile pass. Each ambiguous port is
// surfaced as a [MultiExternalPathHit] on the anomalies gauge
// (`lachesis_neutron_anomalies{class="multi_external_path"}`) and the
// /debug/anomalies page via [DetectAnomalies]; here it only logs at
// Debug, because a legitimately multi-homed VM is a persistent
// condition, not a per-pass event.
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

	// Tier 2: subnet → external-network label, via attached routers
	// with external gateways. Built first so FIP hits can shadow it.
	//
	// The gateway-IP rule: Neutron allows several routers on one
	// subnet, but only one interface holds the subnet's gateway_ip —
	// and the VMs' default route points exactly there, so SNAT egress
	// is deterministic via that router. Interfaces holding the
	// gateway IP are therefore authoritative (gwExt); other attached
	// routers (anyExt) count only when no gateway-owning router has
	// an external gateway — they can carry traffic solely via
	// in-guest static routes, the documented-unsolvable case
	// (docs/architecture/edge-cases.md#tier-4--subtle-correctness row 9).
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

// RouterExtMACs maps each router-interface port's MAC (as a
// [bpf.MACKey] u64) to the label of the external network its router
// gateways to — the per-flow attribution source for routed external
// traffic (docs/architecture/billing.md): a routed external flow's peer MAC is
// a router interface's MAC, unique per logical router interface on OVN
// (the duplicate_router_mac anomaly asserts exactly this), so the map
// identifies which exit network actually carried each flow. Interfaces
// of routers with no external gateway are absent — their flows fall
// back to the per-VM attribution. Ports with unparseable MACs are
// skipped silently (mirroring the VM-port admission gate; a malformed
// port must not log every pass).
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
