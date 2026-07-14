package scenariotest

import "context"

// Cloud is the live OpenStack surface that scenariotest's preflight
// and realize steps consume. The gophercloud-backed implementation is
// [OpenStack]; unit tests substitute a recording fake. Read-only
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
	// SetRouterRoutes replaces a router's static (extra) routes.
	SetRouterRoutes(ctx context.Context, projectID, routerID string, routes []RouteSpec) error
	// CreateServer boots a Nova server on a pre-created port.
	CreateServer(ctx context.Context, projectID string, spec ServerSpec) (id string, err error)
	// WaitServerActive blocks until the server reports ACTIVE or the
	// context deadline fires; ERROR status fails fast.
	WaitServerActive(ctx context.Context, projectID, serverID string) error
	// CreateFIP allocates a floating IP and (when PortID is set) binds
	// it, returning the allocation ID and the assigned address.
	CreateFIP(ctx context.Context, projectID string, spec FIPCreateSpec) (id, addr string, err error)

	// --- teardown (every delete is 404-tolerant: removing the
	// already-gone succeeds, so `down` re-runs converge) ---
	//
	// Deliberately NO project deletion method: projects are never
	// torn down by policy, and leaving the verb off the interface
	// makes that unrepresentable.

	// DeleteFIP releases a floating IP by exact allocation ID.
	DeleteFIP(ctx context.Context, projectID, id string) error
	// DeleteServer requests deletion; pair with WaitServerGone.
	DeleteServer(ctx context.Context, projectID, id string) error
	// WaitServerGone blocks until Nova no longer knows the server or
	// the context deadline fires.
	WaitServerGone(ctx context.Context, projectID, id string) error
	// DeletePort deletes a Neutron port.
	DeletePort(ctx context.Context, projectID, id string) error
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
	// DeleteSubnet deletes a subnet.
	DeleteSubnet(ctx context.Context, projectID, id string) error
	// DeleteNetwork deletes a network.
	DeleteNetwork(ctx context.Context, projectID, id string) error
}

// NetworkSpec describes a Neutron network to create. External
// networks are never created — they resolve to the provider external
// network — so this spec carries only Shared.
type NetworkSpec struct {
	Name   string
	Shared bool
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
}

// ServerSpec describes a Nova boot on a pre-created port.
// AvailabilityZone carries the optional "nova:<host>" host pin.
// There is no security-group field: the port already carries it, and
// Nova ignores boot-time secgroups for pre-existing ports.
type ServerSpec struct {
	Name             string
	FlavorID         string
	ImageID          string
	PortID           string
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

// RouteSpec is one static route on a router (DESIGN §5.3 extraroute).
type RouteSpec struct {
	Destination string
	Nexthop     string
}
