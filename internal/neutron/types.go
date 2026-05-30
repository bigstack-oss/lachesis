package neutron

// The types below mirror the subset of Neutron v2.0 API responses
// the trie builder consumes. They are intentionally narrower than
// gophercloud's full structs: fields the agent never touches
// (Tags, RevisionNumber, AdminStateUp, Description, …) are
// omitted. Keeping the agent's view of Neutron minimal makes the
// schema dependencies explicit in this one file.
//
// Neutron v2.0 transitionally emits both `project_id` (modern,
// canonical) and `tenant_id` (legacy) for owner attribution.
// The list-call adapters in list.go prefer ProjectID and fall back
// to TenantID when only the legacy field is populated.

// Network is the trie-builder view of a Neutron network.
type Network struct {
	ID        string
	ProjectID string
	Name      string
	// Shared indicates the network can be attached to by any
	// project. Used by §5.2 Step 3 of the trie builder (shared
	// networks contribute OTHER_TENANT entries rather than per-tenant
	// entries) — except when also flagged IsExternal, in which case
	// the catchall handles them as EXTERNAL.
	Shared bool
	// IsExternal mirrors Neutron's `router:external` attribute. True
	// for the operator-managed networks that routers use as upstream
	// gateways (floating-IP pools, transit-to-internet networks).
	// Subnets on external networks are intentionally omitted from
	// the trie's Step 2 / Step 3 — they should classify as EXTERNAL,
	// which is what the Step-1 catchall returns by default. See
	// docs/DESIGN.md §5.3 `zone_for`.
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
	// "network:distributed" for OVN router ports, etc. §5.2 Step 4
	// inspects this to decide whether a port belongs to a VM or to
	// infrastructure.
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

// Router is the trie-builder view of a Neutron router. The
// external-gateway and extra-routes fields are populated only when
// present in the API response; absence is the common case for
// internal-only routers.
type Router struct {
	ID        string
	ProjectID string
	// ExternalNetworkID is the router's upstream network when it
	// has a `gateway_info.network_id` set; empty otherwise. The
	// builder uses this to attribute traffic leaving the cluster.
	ExternalNetworkID string
	// Routes are operator-configured static routes. Empty on most
	// routers. BuildTrie walks these through the multi-hop
	// static-route resolver (DESIGN §5.3), emitting one trie row per
	// route (EXTERNAL when the next hop cannot be resolved).
	Routes []Route
}

// Route is one entry in a router's static-routes list.
type Route struct {
	Destination string // CIDR (e.g. "10.99.0.0/16")
	Nexthop     string // IP address
}
