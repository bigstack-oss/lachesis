// Package scenario is a small declarative builder for the Neutron
// snapshots that exercise [neutron.BuildTrie] in tests. It hides
// the boilerplate of struct literals (per-port MACs, manual
// DeviceID wiring on router-interface ports, IPVersion=4 on every
// subnet) while still producing the same [neutron.Snapshot] the
// production builder consumes.
//
// The package is intentionally minimal — just enough to express
// scenarios A through L from docs/architecture/primer.md. Callers that need
// fields the DSL doesn't expose (MAC addresses, OVN-specific
// device_owner strings, IPv6 ports) should build the Snapshot
// struct directly rather than grow the DSL.
//
// Typical use:
//
//	snap := scenario.New().
//	    Network("net-T1", "T1").
//	        Subnet("sub-T1", "10.0.1.0/24", "10.0.1.1").
//	        VM("vm-a", "T1", "10.0.1.5").
//	    Build()
//	got := neutron.BuildTrie(snap)
package scenario

import (
	"fmt"

	"github.com/bigstack-oss/lachesis/internal/neutron"
)

// Builder accumulates Neutron resources and emits a [neutron.Snapshot].
// Zero value is unusable — construct with [New].
type Builder struct {
	networks []neutron.Network
	subnets  []neutron.Subnet
	ports    []neutron.Port
	routers  []neutron.Router

	rifSeq int // sequence for auto-generated router_interface port IDs
}

// New returns an empty scenario builder.
func New() *Builder { return &Builder{} }

// Network adds a non-shared, non-external network owned by project.
// Returns a [*NetRef] for chaining subnets and ports under this network.
func (b *Builder) Network(id, project string) *NetRef {
	b.networks = append(b.networks, neutron.Network{ID: id, ProjectID: project})
	return &NetRef{b: b, netID: id, lastSubnet: ""}
}

// SharedNetwork adds a network with `shared=true`. Convention: owned
// by an admin tenant since "shared" makes per-tenant ownership moot.
func (b *Builder) SharedNetwork(id, project string) *NetRef {
	b.networks = append(b.networks, neutron.Network{ID: id, ProjectID: project, Shared: true})
	return &NetRef{b: b, netID: id}
}

// ExternalNetwork adds a network with `router:external=true`.
func (b *Builder) ExternalNetwork(id, project string) *NetRef {
	b.networks = append(b.networks, neutron.Network{ID: id, ProjectID: project, IsExternal: true})
	return &NetRef{b: b, netID: id}
}

// Router adds a router. Returns a [*RouterRef] for chaining
// interface attachments and extraroutes.
func (b *Builder) Router(id, project string) *RouterRef {
	b.routers = append(b.routers, neutron.Router{ID: id, ProjectID: project})
	return &RouterRef{b: b, routerID: id}
}

// Build snapshots the builder's state into the four resource slices
// [neutron.BuildTrie] consumes. The Builder is unchanged; Build can
// be called multiple times.
func (b *Builder) Build() neutron.Snapshot {
	return neutron.Snapshot{
		Networks: append([]neutron.Network(nil), b.networks...),
		Subnets:  append([]neutron.Subnet(nil), b.subnets...),
		Ports:    append([]neutron.Port(nil), b.ports...),
		Routers:  append([]neutron.Router(nil), b.routers...),
	}
}

// NetRef is the cursor returned by [Builder.Network] et al. Subnet
// and VM/FIP calls implicitly target this network and the most-
// recently-added subnet on it.
type NetRef struct {
	b          *Builder
	netID      string
	lastSubnet string
}

// Subnet adds an IPv4 subnet on this network. The gateway is the
// /32 INFRA row Step 4 emits; pass "" to omit.
func (n *NetRef) Subnet(id, cidr, gateway string) *NetRef {
	net := n.b.findNetwork(n.netID)
	n.b.subnets = append(n.b.subnets, neutron.Subnet{
		ID: id, NetworkID: n.netID, ProjectID: net.ProjectID,
		CIDR: cidr, GatewayIP: gateway, IPVersion: 4,
	})
	n.lastSubnet = id
	return n
}

// VM adds a compute:nova port on the network's most recent Subnet.
// The port's project is the VM owner, which may differ from the
// network's project (e.g. admin-owned network hosting tenant VMs).
func (n *NetRef) VM(id, project, ip string) *NetRef {
	return n.attachPort(id, project, "compute:nova", id+"-instance", ip)
}

// VMInAZ is [NetRef.VM] for a named availability zone: Nova writes
// compute:<az-name> as the device_owner, "nova" being only the
// default AZ's name.
func (n *NetRef) VMInAZ(id, project, az, ip string) *NetRef {
	return n.attachPort(id, project, "compute:"+az, id+"-instance", ip)
}

// Octavia adds an Octavia management port (device_owner="Octavia").
func (n *NetRef) Octavia(id, project, ip string) *NetRef {
	return n.attachPort(id, project, "Octavia", id, ip)
}

// FIP adds a network:floatingip bookkeeping port (no L2 endpoint;
// pure Neutron metadata). Used by Scenario E.
func (n *NetRef) FIP(id, ip string) *NetRef {
	return n.attachPort(id, n.b.findNetwork(n.netID).ProjectID, "network:floatingip", "", ip)
}

func (n *NetRef) attachPort(id, project, owner, deviceID, ip string) *NetRef {
	if n.lastSubnet == "" {
		panic(fmt.Sprintf("scenario: port %q on network %q has no preceding Subnet", id, n.netID))
	}
	n.b.ports = append(n.b.ports, neutron.Port{
		ID: id, NetworkID: n.netID, ProjectID: project,
		DeviceOwner: owner, DeviceID: deviceID,
		FixedIPs: []neutron.FixedIP{{SubnetID: n.lastSubnet, IPAddress: ip}},
	})
	return n
}

// RouterRef is the cursor returned by [Builder.Router].
type RouterRef struct {
	b        *Builder
	routerID string
}

// Attach creates a network:router_interface port at ip on subnetID,
// with DeviceID wired to this router. The router_interface port is
// what the multi-hop resolver hops through at Step B.
func (r *RouterRef) Attach(subnetID, ip string) *RouterRef {
	sub := r.b.findSubnet(subnetID)
	router := r.b.findRouter(r.routerID)
	r.b.rifSeq++
	r.b.ports = append(r.b.ports, neutron.Port{
		ID:          fmt.Sprintf("p-rif-%s-%d", r.routerID, r.b.rifSeq),
		NetworkID:   sub.NetworkID,
		ProjectID:   router.ProjectID,
		DeviceOwner: "network:router_interface",
		DeviceID:    r.routerID,
		FixedIPs:    []neutron.FixedIP{{SubnetID: subnetID, IPAddress: ip}},
	})
	return r
}

// ExternalGateway sets the router's upstream external network.
func (r *RouterRef) ExternalGateway(externalNetworkID string) *RouterRef {
	rp := r.b.findRouterPtr(r.routerID)
	rp.ExternalNetworkID = externalNetworkID
	return r
}

// ExtraRoute appends a static route to this router. The resolver
// walks (destinationCIDR, nexthopIP) at cold-start (docs/architecture/trie-construction.md#the-static-route-resolver).
func (r *RouterRef) ExtraRoute(destinationCIDR, nexthopIP string) *RouterRef {
	rp := r.b.findRouterPtr(r.routerID)
	rp.Routes = append(rp.Routes, neutron.Route{Destination: destinationCIDR, Nexthop: nexthopIP})
	return r
}

// --- internal lookups ---

func (b *Builder) findNetwork(id string) neutron.Network {
	for _, n := range b.networks {
		if n.ID == id {
			return n
		}
	}
	panic(fmt.Sprintf("scenario: unknown network %q", id))
}

func (b *Builder) findSubnet(id string) neutron.Subnet {
	for _, s := range b.subnets {
		if s.ID == id {
			return s
		}
	}
	panic(fmt.Sprintf("scenario: unknown subnet %q", id))
}

func (b *Builder) findRouter(id string) neutron.Router {
	for _, r := range b.routers {
		if r.ID == id {
			return r
		}
	}
	panic(fmt.Sprintf("scenario: unknown router %q", id))
}

func (b *Builder) findRouterPtr(id string) *neutron.Router {
	for i := range b.routers {
		if b.routers[i].ID == id {
			return &b.routers[i]
		}
	}
	panic(fmt.Sprintf("scenario: unknown router %q", id))
}
