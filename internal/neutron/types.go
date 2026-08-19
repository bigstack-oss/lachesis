package neutron

// The types below mirror only the subset of Neutron v2.0 responses the
// agent consumes, so the schema dependency is explicit in one file.
//
// Neutron emits both `project_id` (canonical) and `tenant_id`
// (legacy); the list adapters prefer the former and fall back.

// Network is the trie-builder view of a Neutron network. Name is
// the operator-assigned label; unused by trie classification but
// surfaced in /debug pages.
type Network struct {
	ID        string
	ProjectID string
	Name      string
	// Shared indicates the network can be attached to by any
	// project. Used by Step 3 of the trie builder (shared networks
	// contribute OTHER_TENANT entries rather than per-tenant
	// entries) — except when also flagged IsExternal, in which case
	// the catchall handles them as EXTERNAL.
	//
	// Full rationale: docs/architecture/trie-construction.md#the-five-step-algorithm
	Shared bool
	// IsExternal mirrors `router:external`. Subnets on such networks
	// are deliberately omitted from trie Steps 2/3 — they must
	// classify EXTERNAL, which the Step-1 catchall already does.
	IsExternal bool
}

// Subnet is the trie-builder view of a Neutron subnet.
type Subnet struct {
	ID        string
	NetworkID string
	ProjectID string
	// CIDR is the subnet's IPv4 or IPv6 prefix in standard CIDR
	// form (e.g. "10.0.0.0/24"). The trie builder parses this with
	// net/netip.
	CIDR      string
	GatewayIP string
	IPVersion int
}

// Port is the trie-builder view of a Neutron port.
type Port struct {
	ID         string
	NetworkID  string
	ProjectID  string
	MACAddress string
	// DeviceOwner classifies the port's role: "compute:nova" for
	// VMs, "network:router_interface" / "network:router_gateway" /
	// "network:distributed" for OVN router ports, etc. Step 4 of the
	// trie builder inspects this to decide whether a port belongs to
	// a VM or to infrastructure.
	//
	// Full rationale: docs/architecture/trie-construction.md#the-five-step-algorithm
	DeviceOwner string
	// DeviceID identifies the bound resource (Nova instance UUID
	// for VMs, router UUID for router ports). Used by the trie
	// builder to join ports to routers when device_owner indicates
	// a router interface.
	DeviceID string
	// FixedIPs is the list of (subnet, address) bindings on this
	// port. A port may have multiple fixed IPs when multi-subnet
	// or dual-stack.
	FixedIPs []FixedIP
}

// FixedIP is a (subnet, IP) binding on a port.
type FixedIP struct {
	SubnetID  string
	IPAddress string
}

// FloatingIP is the agent's view of a Neutron floating IP: which port
// it is bound to (empty when unassociated) and which external network
// it draws from. Consumed by [ExternalNetworkByPort] to give a
// FIP-holding VM its external_network attribution; unbound FIPs are
// carried but ignored there.
type FloatingIP struct {
	ID                string
	PortID            string
	FloatingNetworkID string
}

// Project is the agent's view of a Keystone project. Carried in
// [Snapshot.Projects] so the /debug pages can show human-readable
// names alongside the UUIDs the Neutron resources reference.
type Project struct {
	ID   string
	Name string
}

// Server is the agent's view of a Nova server, carried so the info
// collector can emit lachesis_server_info for dashboard name joins.
// Fetched BEST-EFFORT: a Nova failure leaves the list empty and the
// series absent, never failing the sync.
type Server struct {
	ID        string
	Name      string
	ProjectID string
}

// LoadBalancer is the agent's view of an Octavia load balancer. Only
// the attribution join needs it ([AmphoraOwnerByPort]): ProjectID is
// the tenant the LB's traffic bills to, and Provider gates the join to
// the amphora provider — the OVN provider has no Amphora VM and a
// different traffic shape (docs/architecture/octavia.md).
//
// Fetched best-effort ([Client.ListLoadBalancers]) alongside
// [Snapshot.Amphorae]: a deployment without Octavia leaves both lists
// empty and every Amphora port keeps its own (service-project)
// attribution, exactly as before the subsystem existed.
type LoadBalancer struct {
	ID        string
	ProjectID string
	Provider  string
}

// Amphora is the agent's view of one Octavia Amphora — the VM running
// HAProxy for a load balancer. Three fields carry the whole join:
//
//   - LoadBalancerID resolves the owning tenant via [Snapshot.LoadBalancers].
//   - ComputeID is the Nova instance UUID, which every one of the
//     Amphora's Neutron ports carries as its `device_id`. Enumerating by
//     it catches the VIP-network vrrp port AND any member-network ports
//     Octavia plugs when a pool member lives on another subnet — those
//     are created by Nova on interface-attach and carry no distinguishing
//     marker of their own (verified against the Octavia amphora driver).
//   - LBNetworkIP is the address on the Octavia management network. The
//     port holding it carries health-manager heartbeats, not tenant
//     traffic, and is excluded from the rewrite so no tenant is billed
//     for control-plane chatter.
type Amphora struct {
	ID             string
	LoadBalancerID string
	ComputeID      string
	LBNetworkIP    string
	// Status is the Octavia lifecycle state (BOOTING, ALLOCATED,
	// READY, PENDING_DELETE, DELETED, ERROR). [AmphoraOwnerByPort]
	// skips DELETED rows so a torn-down LB stops claiming ports.
	Status string
}

// Router is the trie-builder view of a Neutron router. Name is the
// operator-assigned label; not used by trie classification but
// surfaced in /debug pages to make sense of which router is which.
//
// The external-gateway and extra-routes fields are populated only
// when present in the API response; absence is the common case for
// internal-only routers.
type Router struct {
	ID        string
	ProjectID string
	Name      string
	// ExternalNetworkID is the router's upstream network when it
	// has a `gateway_info.network_id` set; empty otherwise. The
	// builder uses this to attribute traffic leaving the cluster.
	ExternalNetworkID string
	// Routes are operator-configured static routes. Empty on most
	// routers. BuildTrie walks these through the multi-hop
	// static-route resolver, emitting one trie row per route
	// (EXTERNAL when the next hop cannot be resolved).
	//
	// Full rationale: docs/architecture/trie-construction.md#the-static-route-resolver
	Routes []Route
}

// Route is one entry in a router's static-routes list.
type Route struct {
	Destination string // CIDR (e.g. "10.99.0.0/16")
	Nexthop     string // IP address
}
