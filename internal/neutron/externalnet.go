// externalnet.go resolves each VM port's external-network attribution —
// the source of the `external_network` metric label and the per-server
// export dimension (docs/DESIGN.md §11.5). Pure functions over a
// Snapshot, mirroring the trie builder's style: no I/O, no retention.

package neutron

import (
	"log/slog"
	"sort"
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
// Known limitation (first cut, tracked on the metadata task): a VM with
// multiple external paths — several FIPs on different networks, or
// multiple gateway routers — gets ONE attribution, chosen
// deterministically (lexicographically smallest label, FIP tier first).
// Real traffic could leave through any of them; per-path attribution
// needs conntrack-level data the agent does not collect. One warn log
// per resolve pass summarises how many ports were ambiguous.
func ExternalNetworkByPort(snap *Snapshot) map[string]string {
	netLabel := make(map[string]string, len(snap.Networks))
	for _, n := range snap.Networks {
		if n.Name != "" {
			netLabel[n.ID] = n.Name
		} else {
			netLabel[n.ID] = n.ID
		}
	}

	// Tier 2 first: subnet → external-network label, via each gateway
	// router's interface ports. Built before the per-port pass so FIP
	// hits can shadow it.
	routerExt := make(map[string]string) // routerID → ext label
	for _, r := range snap.Routers {
		if r.ExternalNetworkID != "" {
			routerExt[r.ID] = netLabel[r.ExternalNetworkID]
		}
	}
	subnetExt := make(map[string][]string) // subnetID → candidate labels
	for _, p := range snap.Ports {
		if p.DeviceOwner != DeviceOwnerRouterInterface {
			continue
		}
		ext, ok := routerExt[p.DeviceID]
		if !ok {
			continue
		}
		for _, fip := range p.FixedIPs {
			subnetExt[fip.SubnetID] = append(subnetExt[fip.SubnetID], ext)
		}
	}

	fipExt := make(map[string][]string) // portID → candidate labels
	for _, f := range snap.FloatingIPs {
		if f.PortID == "" || f.FloatingNetworkID == "" {
			continue
		}
		fipExt[f.PortID] = append(fipExt[f.PortID], netLabel[f.FloatingNetworkID])
	}

	out := make(map[string]string)
	ambiguous := 0
	for _, p := range snap.Ports {
		if !IsVMPort(p.DeviceOwner) {
			continue
		}
		candidates := fipExt[p.ID]
		if len(candidates) == 0 {
			for _, fip := range p.FixedIPs {
				candidates = append(candidates, subnetExt[fip.SubnetID]...)
			}
		}
		if len(candidates) == 0 {
			continue
		}
		if picked := pickDeterministic(candidates); picked != "" {
			if len(dedupe(candidates)) > 1 {
				ambiguous++
			}
			out[p.ID] = picked
		}
	}
	if ambiguous > 0 {
		slog.Warn("VM ports with multiple external paths; attributed to one deterministically (known limitation)",
			"component", componentNeutron, "ports", ambiguous)
	}
	return out
}

// pickDeterministic returns the lexicographically smallest non-empty
// candidate, so successive syncs over an unchanged topology attribute
// identically — an attribution flap would needlessly settle-and-relabel
// live series every reconcile pass.
func pickDeterministic(candidates []string) string {
	picked := ""
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if picked == "" || c < picked {
			picked = c
		}
	}
	return picked
}

// dedupe returns the sorted distinct non-empty values of in.
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
