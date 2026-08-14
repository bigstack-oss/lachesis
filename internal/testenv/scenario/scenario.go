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
	"strings"

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
	nicSeq int // sequence for auto-generated extra-NIC port IDs

	lbs      []neutron.LoadBalancer
	amphorae []neutron.Amphora
	lbDecls  []LBDecl
	// lbSeq numbers auto-generated Amphora / port ids so an
	// ACTIVE_STANDBY pair gets two distinct instances.
	lbSeq int
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
		Networks:      append([]neutron.Network(nil), b.networks...),
		Subnets:       append([]neutron.Subnet(nil), b.subnets...),
		Ports:         append([]neutron.Port(nil), b.ports...),
		Routers:       append([]neutron.Router(nil), b.routers...),
		LoadBalancers: append([]neutron.LoadBalancer(nil), b.lbs...),
		Amphorae:      append([]neutron.Amphora(nil), b.amphorae...),
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

// NIC adds an additional compute:nova port to an already-declared VM
// on subnetID, sharing the VM's server identity (the same DeviceID) so
// realize boots ONE Nova server carrying every NIC. This is the
// static, boot-time form of a multi-homed VM; the runtime form (plug a
// NIC into a live VM) is the attach/detach step family. The VM must be
// declared first — its primary port supplies the owning project and
// device_owner. Returns the Builder for further top-level chaining.
//
// Cursorless by design: a NIC usually lands on a different network
// than the VM's, so it references the target subnet by id (like
// [RouterRef.Attach]) rather than riding a network cursor.
func (b *Builder) NIC(vmID, subnetID, ip string) *Builder {
	sub := b.findSubnet(subnetID)
	var owner, project string
	for _, p := range b.ports {
		if p.ID == vmID && strings.HasPrefix(p.DeviceOwner, "compute:") {
			owner, project = p.DeviceOwner, p.ProjectID
			break
		}
	}
	if owner == "" {
		panic(fmt.Sprintf("scenario: NIC references unknown VM %q (declare it with VM() first)", vmID))
	}
	b.nicSeq++
	b.ports = append(b.ports, neutron.Port{
		ID:          fmt.Sprintf("%s-nic-%d", vmID, b.nicSeq),
		NetworkID:   sub.NetworkID,
		ProjectID:   project,
		DeviceOwner: owner,
		DeviceID:    vmID + "-instance",
		FixedIPs:    []neutron.FixedIP{{SubnetID: subnetID, IPAddress: ip}},
	})
	return b
}

// Octavia adds an Octavia management port (device_owner="Octavia").
func (n *NetRef) Octavia(id, project, ip string) *NetRef {
	return n.attachPort(id, project, "Octavia", id, ip)
}

// LBTopology selects how many Amphorae serve a load balancer.
// Standalone is one; ActiveStandby is a MASTER/BACKUP pair and needs an
// Octavia flavor carrying loadbalancer_topology=ACTIVE_STANDBY, which
// the harness resolves at preflight and never creates.
type LBTopology string

const (
	Standalone    LBTopology = "STANDALONE"
	ActiveStandby LBTopology = "ACTIVE_STANDBY"
)

// LoadBalancer declares an Octavia load balancer whose VIP sits on this
// network's most recent Subnet, owned by project. It reproduces the
// resource shape a live amphora-provider deployment produces (verified
// against OVN-Yoga):
//
//   - a VIP reservation port, device_owner "Octavia", device_id
//     "lb-<id>", owned by the LB's project — never on the wire;
//   - per Amphora, a data port on the VIP subnet carrying the Amphora's
//     own base address plus the VIP as an allowed-address pair, and a
//     management port on the Octavia management network. Both are
//     ordinary compute:nova ports owned by the SERVICE project, joined
//     to their Amphora only by device_id.
//
// That last property is the whole reason the attribution join keys on
// the Nova instance UUID (docs/architecture/octavia.md). Members are
// declared with [LBRef.Member]; a member on another subnet grows the
// Amphora an extra data port there, exactly as Octavia plugs one.
//
// serviceProject is the project Amphorae are owned by (the Octavia
// service project on a real cloud) — passed explicitly so a test can
// assert the re-attribution actually moved the billing identity.
func (n *NetRef) LoadBalancer(id, project, serviceProject, vip string, topology LBTopology) *LBRef {
	if n.lastSubnet == "" {
		panic(fmt.Sprintf("scenario: load balancer %q on network %q has no preceding Subnet", id, n.netID))
	}
	n.b.lbs = append(n.b.lbs, neutron.LoadBalancer{
		ID: id, ProjectID: project, Provider: "amphora",
	})
	// The VIP reservation port: the LB owner's project, no Nova binding.
	n.b.ports = append(n.b.ports, neutron.Port{
		ID: id + "-vip", NetworkID: n.netID, ProjectID: project,
		DeviceOwner: "Octavia", DeviceID: "lb-" + id,
		FixedIPs: []neutron.FixedIP{{SubnetID: n.lastSubnet, IPAddress: vip}},
	})
	n.b.lbDecls = append(n.b.lbDecls, LBDecl{
		ID: id, ProjectID: project, VIPSubnetID: n.lastSubnet, VIP: vip,
		Topology: topology, Protocol: defaultLBProtocol,
		Port: defaultLBPort, Algorithm: defaultLBAlgorithm,
	})
	ref := &LBRef{b: n.b, lbID: id, netID: n.netID, subnetID: n.lastSubnet,
		project: project, serviceProject: serviceProject, vip: vip,
		declIdx: len(n.b.lbDecls) - 1}
	count := 1
	if topology == ActiveStandby {
		count = 2
	}
	for i := 0; i < count; i++ {
		ref.addAmphora()
	}
	return ref
}

// LBDecl is the live tier's view of a declared load balancer: the
// listener, pool and members Octavia needs, which a
// [neutron.Snapshot] has no place for because the agent never reads
// them. Retrieved with [Builder.LoadBalancers]; the Snapshot carries
// the resulting Neutron shape instead.
type LBDecl struct {
	ID          string
	ProjectID   string
	VIPSubnetID string
	VIP         string
	Topology    LBTopology
	Protocol    string
	Port        int
	Algorithm   string
	Members     []LBMemberDecl
}

// LBMemberDecl is one declared pool member.
type LBMemberDecl struct {
	SubnetID string
	Address  string
	Port     int
}

// LoadBalancers returns the declared load balancers in declaration
// order. Empty for a topology with none.
func (b *Builder) LoadBalancers() []LBDecl {
	return append([]LBDecl(nil), b.lbDecls...)
}

// defaultLBProtocol, defaultLBPort and defaultLBAlgorithm are what a
// declared load balancer listens on unless a scenario overrides them
// with [LBRef.Listener]. TCP:80 round-robin is the shape every
// attribution scenario needs — the point is byte accounting, not L7
// behaviour.
const (
	defaultLBProtocol  = "TCP"
	defaultLBPort      = 80
	defaultLBAlgorithm = "ROUND_ROBIN"
)

// LBRef is the cursor returned by [NetRef.LoadBalancer].
type LBRef struct {
	b              *Builder
	lbID           string
	netID          string
	subnetID       string
	project        string
	serviceProject string
	vip            string
	computeIDs     []string
	declIdx        int
}

// Listener overrides the declared listener protocol and port.
func (r *LBRef) Listener(protocol string, port int) *LBRef {
	r.b.lbDecls[r.declIdx].Protocol = protocol
	r.b.lbDecls[r.declIdx].Port = port
	return r
}

// addAmphora appends one Amphora with its management and VIP-subnet
// data ports. Addresses are synthesised from the sequence counter — the
// DSL is a topology model, not an IPAM.
func (r *LBRef) addAmphora() {
	r.b.lbSeq++
	amp := fmt.Sprintf("%s-amp-%d", r.lbID, r.b.lbSeq)
	compute := amp + "-instance"
	mgmtIP := fmt.Sprintf("10.254.%d.%d", r.b.lbSeq, 10+r.b.lbSeq)
	r.b.amphorae = append(r.b.amphorae, neutron.Amphora{
		ID: amp, LoadBalancerID: r.lbID, ComputeID: compute,
		LBNetworkIP: mgmtIP, Status: "ALLOCATED",
	})
	// Management port: carries health-manager heartbeats, must never be
	// re-attributed. It has no subnet in the topology, so it is attached
	// bare — the join excludes it by matching LBNetworkIP.
	r.b.ports = append(r.b.ports, neutron.Port{
		ID: amp + "-mgmt", NetworkID: "net-lb-mgmt", ProjectID: r.serviceProject,
		DeviceOwner: "compute:nova", DeviceID: compute,
		FixedIPs: []neutron.FixedIP{{SubnetID: "sub-lb-mgmt", IPAddress: mgmtIP}},
	})
	// Data port on the VIP subnet: the Amphora's base address, with the
	// VIP as an allowed-address pair (which is how it reaches the wire).
	r.b.ports = append(r.b.ports, neutron.Port{
		ID: amp + "-vrrp", NetworkID: r.netID, ProjectID: r.serviceProject,
		DeviceOwner: "compute:nova", DeviceID: compute,
		FixedIPs: []neutron.FixedIP{{SubnetID: r.subnetID, IPAddress: r.baseIP()}},
	})
	r.computeIDs = append(r.computeIDs, compute)
}

// baseIP synthesises the next Amphora base address on the VIP subnet by
// replacing the VIP's last octet.
func (r *LBRef) baseIP() string {
	i := strings.LastIndex(r.vip, ".")
	return fmt.Sprintf("%s.%d", r.vip[:i], 200+r.b.lbSeq)
}

// Member declares a pool member at ip on subnetID. When the subnet is
// not the VIP's, Octavia plugs every Amphora into that member's network
// — a port Nova mints, indistinguishable from any other compute port and
// carrying no Octavia marker — so the DSL grows the same extra ports.
// The member VM itself is declared separately with [NetRef.VM]; this
// call models only what the load balancer does in response.
func (r *LBRef) Member(subnetID, ip string, port int) *LBRef {
	r.b.lbDecls[r.declIdx].Members = append(r.b.lbDecls[r.declIdx].Members,
		LBMemberDecl{SubnetID: subnetID, Address: ip, Port: port})
	if subnetID == r.subnetID {
		return r // same subnet: already L2-adjacent, nothing plugged
	}
	sub := r.b.findSubnet(subnetID)
	for i, compute := range r.computeIDs {
		r.b.ports = append(r.b.ports, neutron.Port{
			ID:          fmt.Sprintf("%s-member-%s-%d", r.lbID, subnetID, i),
			NetworkID:   sub.NetworkID,
			ProjectID:   r.serviceProject,
			DeviceOwner: "compute:nova",
			DeviceID:    compute,
			FixedIPs:    []neutron.FixedIP{{SubnetID: subnetID, IPAddress: memberPlugIP(ip, i)}},
		})
	}
	return r
}

// Done returns the Builder for further top-level chaining.
func (r *LBRef) Done() *Builder { return r.b }

// memberPlugIP synthesises the Amphora's address on a member subnet,
// offset per Amphora so an ACTIVE_STANDBY pair does not collide.
func memberPlugIP(memberIP string, idx int) string {
	i := strings.LastIndex(memberIP, ".")
	return fmt.Sprintf("%s.%d", memberIP[:i], 240+idx)
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
