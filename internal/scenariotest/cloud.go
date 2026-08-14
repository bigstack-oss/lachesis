package scenariotest

import "context"

// Cloud is the live OpenStack surface that scenariotest's preflight
// and realize steps consume. The gophercloud-backed implementation is
// the openstack package; unit tests substitute a recording fake. Read-only
// lookups back preflight; the per-project creation methods back `up`.
//
// Methods that create project-owned resources take a projectID; the
// implementation issues those calls through a token scoped to that
// project, because gophercloud fixes project scope at client
// construction and a resource is born in the token's project. Booting
// a Nova server in another project has no API parameter for it — only
// the token scope — so per-project scoping is unavoidable.
//
// The interface is intentionally a thin pass-through: all of the
// topology decisions (ordering, external-network resolution, which
// ports become router interfaces) live in [realize], not here, so
// they can be unit-tested against the fake without a cluster.
type Cloud interface {
	// --- prerequisite + placement lookups (read-only, admin) ---

	// FindImage resolves a Glance image name to its ID.
	FindImage(ctx context.Context, name string) (id string, err error)
	// FindFlavor resolves a Nova flavor name to its ID.
	FindFlavor(ctx context.Context, name string) (id string, err error)
	// FindLBFlavor resolves an Octavia load-balancer flavor name to its
	// ID. Unlike the other prerequisites this one is OPTIONAL: it is
	// resolved only for a scenario declaring an ACTIVE_STANDBY load
	// balancer, because the Amphora count comes from the flavor's
	// loadbalancer_topology rather than from any per-LB argument. A
	// cluster with no such flavor staged makes those scenarios SKIPPED,
	// never failed (scenariotest.SkipReason).
	FindLBFlavor(ctx context.Context, name string) (id string, err error)
	// CheckKeypair errors if the named Nova keypair does not exist.
	CheckKeypair(ctx context.Context, name string) error
	// FindSecGroup resolves a Neutron security-group name to its ID.
	FindSecGroup(ctx context.Context, name string) (id string, err error)
	// FindExternalNetwork resolves the provider external network name
	// to its ID. DSL external networks resolve to this real network
	// rather than being created.
	FindExternalNetwork(ctx context.Context, name string) (id string, err error)
	// Hypervisors returns the hypervisor hostnames the scheduler
	// knows, for validating [Scenario.Placement].
	Hypervisors(ctx context.Context) (hosts []string, err error)

	// --- projects (admin Identity) ---

	// FindProject looks a project up by exact name.
	FindProject(ctx context.Context, name string) (id string, found bool, err error)
	// CreateProject creates an enabled project and returns its ID.
	CreateProject(ctx context.Context, name string) (id string, err error)
	// GrantAdminRole assigns the authenticated admin user the admin
	// role on projectID, so a project-scoped token can be minted for
	// it (a freshly-created project grants its creator nothing).
	GrantAdminRole(ctx context.Context, projectID string) error

	// --- per-project resource creation ---

	CreateNetwork(ctx context.Context, projectID string, spec NetworkSpec) (id string, err error)
	CreateSubnet(ctx context.Context, projectID string, spec SubnetSpec) (id string, err error)
	CreateRouter(ctx context.Context, projectID string, spec RouterSpec) (id string, err error)
	// CreatePort creates an unbound Neutron port with one fixed IP.
	CreatePort(ctx context.Context, projectID string, spec PortSpec) (id string, err error)
	// PortMAC returns a port's MAC address (admin view). The mac-reuse
	// scenario reads a VM's Neutron-assigned MAC before deleting it, so
	// the reborn port can pin the same address.
	PortMAC(ctx context.Context, portID string) (mac string, err error)
	// AddRouterInterface attaches a subnet (Neutron picks the gateway
	// IP) or an explicit port (for a non-gateway interface IP, e.g. a
	// transit subnet) to a router. Exactly one of subnetID/portID is
	// set.
	AddRouterInterface(ctx context.Context, projectID, routerID, subnetID, portID string) error
	// SetRouterRoutes replaces a router's static (extra) routes. Also
	// the mid-run extraroute-mutation vehicle (SetRouterRoutesStep).
	SetRouterRoutes(ctx context.Context, projectID, routerID string, routes []RouteSpec) error
	// SetRouterGateway replaces (or, with an empty network id, clears) a
	// router's external gateway — the re-gateway mutation of the
	// router-regateway scenario (SetRouterGatewayStep).
	SetRouterGateway(ctx context.Context, projectID, routerID, externalNetworkID string) error
	// CreateServer boots a Nova server on a pre-created port.
	CreateServer(ctx context.Context, projectID string, spec ServerSpec) (id string, err error)
	// WaitServerActive blocks until the server reports ACTIVE or the
	// context deadline fires; ERROR status fails fast.
	WaitServerActive(ctx context.Context, projectID, serverID string) error
	// CreateFIP allocates a floating IP and (when PortID is set) binds
	// it, returning the allocation ID and the assigned address.
	CreateFIP(ctx context.Context, projectID string, spec FIPCreateSpec) (id, addr string, err error)

	// --- Octavia load balancers (docs/architecture/octavia.md) ---
	//
	// Every mutation is followed by a [Cloud.WaitLBActive]: Octavia
	// serialises work per load balancer and rejects a second request
	// while the first is PENDING_*, so realize gates each step rather
	// than pipelining them.

	// CreateLoadBalancer creates a load balancer on a VIP subnet and
	// returns its ID plus the VIP address Octavia assigned. The returned
	// address is what clients target — see [VIPTarget].
	CreateLoadBalancer(ctx context.Context, projectID string, spec LBSpec) (id, vip string, err error)
	// CreateListener adds a listener (the client-facing port) to a load
	// balancer.
	CreateListener(ctx context.Context, projectID string, spec ListenerSpec) (id string, err error)
	// CreatePool adds a backend pool to a listener.
	CreatePool(ctx context.Context, projectID string, spec PoolSpec) (id string, err error)
	// CreateMember adds one backend to a pool. SubnetID matters
	// operationally, not just descriptively: naming a subnet the Amphora
	// is not attached to makes Octavia plug it in there, growing the
	// Amphora a new data port — the shape the attribution join must
	// cover.
	CreateMember(ctx context.Context, projectID string, spec MemberSpec) (id string, err error)
	// WaitLBActive blocks until the load balancer reports
	// provisioning_status ACTIVE or the context deadline fires; ERROR
	// fails fast.
	WaitLBActive(ctx context.Context, projectID, lbID string) error
	// ListAmphorae returns the Amphorae serving a load balancer. The
	// assert phase reads it to learn which Nova instances (and so which
	// taps) the load balancer actually runs on — an ACTIVE_STANDBY pair
	// yields two.
	ListAmphorae(ctx context.Context, lbID string) ([]AmphoraRef, error)

	// --- live migration (MigrateStep) ---

	// ServerHost returns the compute host currently running the server
	// (OS-EXT-SRV-ATTR:host — the same name the hypervisor list and
	// [Scenario.Placement] use). Needs the admin role the scoped token
	// carries.
	ServerHost(ctx context.Context, projectID, serverID string) (host string, err error)
	// LiveMigrateServer asks Nova to live-migrate the server; empty
	// targetHost lets the scheduler choose. Returns once Nova accepts
	// the action — callers poll [Cloud.ServerHost] /
	// [Cloud.WaitServerActive] for completion.
	LiveMigrateServer(ctx context.Context, projectID, serverID, targetHost string) error

	// --- server NIC hot-plug (AttachPortStep / ReattachPortStep /
	// DetachPortStep) ---

	// AttachInterface hot-plugs a pre-created, unbound port onto a
	// running server (Nova os-interface attach). The kernel-side tap
	// appears asynchronously — callers gate on the agents'
	// attached-interfaces gauge, exactly like a boot.
	AttachInterface(ctx context.Context, projectID, serverID, portID string) error
	// DetachInterface unplugs a port from a server (Nova os-interface
	// detach), leaving the port alive and unbound — reattachable or
	// deletable by the caller.
	DetachInterface(ctx context.Context, projectID, serverID, portID string) error

	// --- teardown (every delete is 404-tolerant: removing the
	// already-gone succeeds, so `down` re-runs converge) ---
	//
	// Deliberately NO project deletion method: projects are never
	// torn down by policy, and leaving the verb off the interface
	// makes that unrepresentable.

	// DeleteLoadBalancer deletes a load balancer and everything under it
	// (listeners, pools, members) in one cascade, then waits for it to
	// disappear. Octavia owns the Amphora VMs and their ports, so this
	// is the ONLY way to reclaim them — deleting the ports directly
	// leaves Octavia's records dangling.
	DeleteLoadBalancer(ctx context.Context, projectID, id string) error
	// DeleteFIP releases a floating IP by exact allocation ID.
	DeleteFIP(ctx context.Context, projectID, id string) error
	// DeleteServer requests deletion; pair with WaitServerGone.
	DeleteServer(ctx context.Context, projectID, id string) error
	// WaitServerGone blocks until Nova no longer knows the server or
	// the context deadline fires.
	WaitServerGone(ctx context.Context, projectID, id string) error
	// DeletePort deletes a Neutron port.
	DeletePort(ctx context.Context, projectID, id string) error
	// ClearRouterRoutes removes all of a router's static (extra)
	// routes. Teardown calls it before detaching interfaces: a route
	// pins the interface its next-hop sits on, and Neutron 409s the
	// detach with RouterInterfaceInUseByRoute otherwise. Unlike the
	// realize-side SetRouterRoutes, it is 404-tolerant and a no-op on a
	// route-free router, so a converging re-run stays idempotent.
	ClearRouterRoutes(ctx context.Context, projectID, routerID string) error
	// RemoveRouterInterface detaches a subnet or port from a router
	// (exactly one of subnetID/portID set). Neutron deletes the
	// interface port itself. Also 404-tolerant for "not an interface".
	RemoveRouterInterface(ctx context.Context, projectID, routerID, subnetID, portID string) error
	// DeleteRouter deletes a router. Neutron removes the external
	// gateway port automatically; internal interfaces must already be
	// detached.
	DeleteRouter(ctx context.Context, projectID, id string) error
	// ListNetworkPorts returns the IDs of every port still on a
	// network (admin view) — the residual sweep for platform-created
	// ports (e.g. CubeCOS `cube:mgr`) that block subnet/network
	// deletion and appear in no run-state.
	ListNetworkPorts(ctx context.Context, networkID string) ([]string, error)
	// ListProjectServers returns the ID and name of every Nova server
	// in projectID (through a project-scoped token, so only that
	// project's servers are visible). It backs the residual server
	// sweep: a server Nova accepted in the create→save window is
	// recorded nowhere, and `down` recognises it by its exact mangled
	// name. The name comes back so `down` can match the run's own
	// prefix and never touch a sibling run reusing the same project.
	ListProjectServers(ctx context.Context, projectID string) ([]ServerRef, error)
	// DeleteSubnet deletes a subnet.
	DeleteSubnet(ctx context.Context, projectID, id string) error
	// DeleteNetwork deletes a network.
	DeleteNetwork(ctx context.Context, projectID, id string) error
}

// NetworkSpec describes a Neutron network to create. External DSL
// markers normally resolve to the provider external network instead of
// being created; the exception is [Scenario.CreateExternalNets], whose
// networks are created with `router:external=true` (External here) —
// segmentless, so they allocate FIPs and take router gateways but
// carry no wire traffic, which is exactly what an attribution scenario
// needs.
type NetworkSpec struct {
	Name     string
	Shared   bool
	External bool
}

// SubnetSpec describes an IPv4 subnet. GatewayIP is passed verbatim
// from the DSL; empty means "let Neutron pick the gateway".
type SubnetSpec struct {
	Name      string
	NetworkID string
	CIDR      string
	GatewayIP string
}

// RouterSpec describes a router. ExternalNetworkID, when set, is the
// resolved provider external network the router gateways to.
type RouterSpec struct {
	Name              string
	ExternalNetworkID string
}

// PortSpec describes a single-fixed-IP Neutron port. SecGroupID is
// optional; empty leaves the port in the network's default group.
// MACAddress is optional; empty lets Neutron assign one (the normal
// case — only the mac-reuse scenario pins it, and Neutron rejects a
// MAC already in use on the same network).
type PortSpec struct {
	Name       string
	NetworkID  string
	SubnetID   string
	FixedIP    string
	SecGroupID string
	MACAddress string
	// PortSecurityOff creates the port with port_security_enabled=false
	// and NO security groups (Neutron requires the two together) — the
	// spoofed-MAC scenarios' escape hatch from MAC/IP anti-spoofing.
	PortSecurityOff bool
	// AllowedPairs populates allowed_address_pairs — the VRRP-style
	// (IP, MAC) grants that let a guest source traffic from a virtual
	// MAC with port security still on.
	AllowedPairs []AddressPair
}

// AddressPair is one allowed_address_pairs entry on a port.
type AddressPair struct {
	IP  string
	MAC string
}

// ServerSpec describes a Nova boot on one or more pre-created ports.
// AvailabilityZone carries the optional "nova:<host>" host pin.
// There is no security-group field: the port already carries it, and
// Nova ignores boot-time secgroups for pre-existing ports.
type ServerSpec struct {
	Name     string
	FlavorID string
	ImageID  string
	// PortID is the primary NIC (eth0), the one a FIP fronts.
	PortID string
	// ExtraPortIDs are additional NICs for a multi-homed VM, attached
	// in order after the primary (eth1, eth2…). Nil for the common
	// single-NIC boot, which is byte-identical to before.
	ExtraPortIDs     []string
	KeypairName      string
	AvailabilityZone string
}

// FIPCreateSpec describes a floating IP allocation. PortID and
// FixedIP bind it to a VM port; FloatingIP requests a specific
// address (else the pool assigns one).
type FIPCreateSpec struct {
	ExternalNetworkID string
	PortID            string
	FixedIP           string
	FloatingIP        string
}

// LBSpec describes an Octavia load balancer to create. FlavorID is
// optional: empty takes the deployment default (a STANDALONE Amphora),
// and a flavor whose profile sets loadbalancer_topology=ACTIVE_STANDBY
// is what produces a MASTER/BACKUP pair. Resolved from
// prerequisites.lb_flavor_name at preflight; never created.
type LBSpec struct {
	Name        string
	VIPSubnetID string
	FlavorID    string
}

// ListenerSpec describes a listener on a load balancer.
type ListenerSpec struct {
	Name           string
	LoadBalancerID string
	Protocol       string
	ProtocolPort   int
}

// PoolSpec describes a backend pool on a listener. LBAlgorithm is
// passed verbatim (e.g. "ROUND_ROBIN") so a scenario can pin the
// distribution it asserts against.
type PoolSpec struct {
	Name        string
	ListenerID  string
	Protocol    string
	LBAlgorithm string
}

// MemberSpec describes one pool member. SubnetID is the subnet the
// member's address lives on; see [Cloud.CreateMember] for why it is
// load-bearing rather than cosmetic.
type MemberSpec struct {
	Name         string
	PoolID       string
	Address      string
	ProtocolPort int
	SubnetID     string
}

// AmphoraRef is one Amphora serving a load balancer, as seen by
// [Cloud.ListAmphorae]. ComputeID is the Nova instance UUID — the join
// key every one of the Amphora's Neutron ports carries as its
// device_id (docs/architecture/octavia.md); LBNetworkIP identifies the
// management port that must NOT be billed to a tenant; Role is
// STANDALONE, MASTER, or BACKUP.
type AmphoraRef struct {
	ID          string
	ComputeID   string
	LBNetworkIP string
	Role        string
}

// RouteSpec is one static route on a router (docs/architecture/trie-construction.md#the-static-route-resolver extraroute).
type RouteSpec struct {
	Destination string
	Nexthop     string
}

// ServerRef is one live Nova server seen by [Cloud.ListProjectServers]:
// its ID (to delete by) and Name (to match against the run's mangled
// prefix). Deliberately minimal — the residual server sweep needs
// nothing more.
type ServerRef struct {
	ID   string
	Name string
}
