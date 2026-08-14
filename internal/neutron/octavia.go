// octavia.go resolves which Neutron ports belong to an Octavia Amphora
// and which tenant their traffic should bill to. Pure functions over a
// Snapshot, mirroring externalnet.go: no I/O, no retention.

package neutron

import (
	"log/slog"
	"strings"
)

// AmphoraOwnerByPort maps each Amphora data port ID to the Keystone
// project that owns the load balancer it serves — the re-attribution
// this subsystem exists for (docs/architecture/octavia.md).
//
// An Amphora is a VM in the Octavia service project, so its ports carry
// that project's ID. Billing its traffic there charges the operator for
// a tenant's load balancer. The map produced here lets the metadata
// populators substitute the LB owner instead, which is all the
// re-attribution takes: attribution is a userspace lookup on the
// VM-side MAC, so rewriting the port's project rewrites both the
// `tenant_id` label and the interned tenant the kernel keys zone
// comparisons on.
//
// The join runs in three hops, one per helper below:
//
//	load balancer   ─ project_id ─→  the billing tenant
//	      ↑ loadbalancer_id
//	  Amphora       ─ compute_id ─→  every port whose device_id matches
//	                                 MINUS the management port
//
// `device_id` is the join key rather than the Amphora's `vrrp_port_id`
// because that field names only the VIP-network port. When a pool
// member lives on another subnet, Octavia plugs the Amphora into the
// member's network too — and it does so by handing Nova a network ID
// with no port, so Nova mints a port that looks like any other
// `compute:nova` port and carries no Octavia marker at all. Enumerating
// by the Nova instance UUID is the only signal that covers both.
//
// Ports with no Amphora binding are absent from the map — callers keep
// the port's own attribution for those, which is also what happens
// wholesale when Octavia is absent or unreachable.
func AmphoraOwnerByPort(snap *Snapshot) map[string]string {
	owners := amphoraLBOwners(snap)       // 1. load balancer → billing tenant
	amps := amphoraBindings(snap, owners) // 2. Nova instance → tenant + mgmt address
	return amphoraDataPorts(snap, amps)   // 3. Neutron port  → billing tenant
}

// amphoraLBOwners maps load-balancer ID to owning project, keeping only
// the providers whose traffic shape this subsystem models: a VM running
// HAProxy that terminates the client connection and originates a fresh
// one to the backend.
//
// The OVN provider has no Amphora VM and preserves the client's source
// IP end-to-end, so its traffic is already attributed correctly by the
// normal path. Its load balancers are counted and warn-logged once per
// sync — an OVN-provider deployment is out of scope
// (docs/architecture/octavia.md), and learning that from a billing
// discrepancy is worse than learning it from the log.
func amphoraLBOwners(snap *Snapshot) map[string]string {
	out := make(map[string]string, len(snap.LoadBalancers))
	skipped := 0
	for _, lb := range snap.LoadBalancers {
		if lb.ID == "" || lb.ProjectID == "" {
			continue
		}
		if !isAmphoraProvider(lb.Provider) {
			skipped++
			continue
		}
		out[lb.ID] = lb.ProjectID
	}
	if skipped > 0 {
		slog.Warn("load balancers on a non-amphora provider are not re-attributed (docs/architecture/octavia.md)",
			"component", componentNeutron, "count", skipped)
	}
	return out
}

// isAmphoraProvider reports whether an Octavia provider name is the
// amphora driver, under either its current name or the deprecated alias
// Yoga still reports. An empty name means the API reported none: treat
// it as the amphora default rather than silently skipping a real load
// balancer.
func isAmphoraProvider(provider string) bool {
	return provider == "" ||
		strings.EqualFold(provider, providerAmphora) ||
		strings.EqualFold(provider, providerAmphoraAlias)
}

// amphoraBinding is what one Amphora contributes to the join: the tenant
// its data ports must bill, and the management address identifying the
// one port that must not.
type amphoraBinding struct {
	owner  string
	mgmtIP string
}

// amphoraBindings maps each live Amphora's Nova instance UUID to its
// binding. `owners` comes from [amphoraLBOwners].
//
// An Amphora is dropped when it has no Nova instance to join on (still
// booting), when it is DELETED (a torn-down load balancer must not keep
// claiming ports), or when its load balancer is absent from `owners` —
// either deleted between the two list calls, or on a provider this
// subsystem does not model.
func amphoraBindings(snap *Snapshot, owners map[string]string) map[string]amphoraBinding {
	if len(owners) == 0 {
		return nil
	}
	out := make(map[string]amphoraBinding, len(snap.Amphorae))
	for _, a := range snap.Amphorae {
		if a.ComputeID == "" || strings.EqualFold(a.Status, amphoraStatusDeleted) {
			continue
		}
		owner, ok := owners[a.LoadBalancerID]
		if !ok {
			continue
		}
		out[a.ComputeID] = amphoraBinding{owner: owner, mgmtIP: a.LBNetworkIP}
	}
	return out
}

// amphoraDataPorts is the final hop: every port bound to one of the
// Amphora instances in `amps`, minus each Amphora's management port,
// mapped to the tenant that port's traffic should bill.
func amphoraDataPorts(snap *Snapshot, amps map[string]amphoraBinding) map[string]string {
	if len(amps) == 0 {
		return nil
	}
	out := make(map[string]string)
	for _, p := range snap.Ports {
		amp, ok := amps[p.DeviceID]
		if !ok || amp.isManagementPort(p) {
			continue
		}
		out[p.ID] = amp.owner
	}
	return out
}

// isManagementPort reports whether p is its Amphora's port on the
// Octavia management network — the one carrying health-manager
// heartbeats rather than tenant traffic. Both ports are ordinary
// `compute:nova` ports sharing one device_id, so the management address
// is the only thing telling them apart.
//
// Excluding it is what stops a tenant being billed, forever and as a
// constant background trickle, for the operator's own control plane.
//
// When Octavia reported no management address the Amphora's ports all
// count as data. Deliberate: getting the data port right is the point of
// the whole subsystem, so over-including costs a tenant a few heartbeat
// bytes whereas under-including would leave real load-balancer traffic
// billed to the service project. In practice unreachable — Octavia
// populates lb_network_ip and compute_id together at allocation, and
// [amphoraBindings] has already dropped rows missing the latter.
func (b amphoraBinding) isManagementPort(p Port) bool {
	return b.mgmtIP != "" && portHasIP(p, b.mgmtIP)
}

// portHasIP reports whether any of p's fixed IPs equals ip.
func portHasIP(p Port, ip string) bool {
	for _, f := range p.FixedIPs {
		if f.IPAddress == ip {
			return true
		}
	}
	return false
}
