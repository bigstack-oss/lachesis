// schema.go gathers package neutron's package-level constants, well-known
// prefixes, and the pure-data holders (Snapshot, TrieEntry, SyncResult,
// the anomaly hit records). The Neutron resource record types live in
// types.go; the resolver, trie builder, API client, and sync pass that
// consume this vocabulary live in resolve.go / trie.go / client.go /
// sync.go.

package neutron

import (
	"net/netip"

	"github.com/bigstack-oss/lachesis/internal/bpf"
)

// Snapshot is one consistent read of the Neutron resource lists plus
// the Keystone project list. Fields are in API-iteration order with no
// sorting guarantee — consumers needing stability sort their own
// derived output.
type Snapshot struct {
	Networks []Network
	Subnets  []Subnet
	Ports    []Port
	Routers  []Router
	// FloatingIPs carries every FIP the agent's project can see.
	// Fetched for external-network attribution ([ExternalNetworkByPort]):
	// a FIP bound to a VM port pins that VM's egress to the FIP's
	// network, taking precedence over the router-gateway path.
	FloatingIPs []FloatingIP
	// Projects is the Keystone project list. Carried alongside the
	// Neutron resources because Neutron returns project_id as a bare
	// UUID; consumers that need a human-readable label (the /debug
	// pages, log enrichment) resolve through this slice.
	Projects []Project
	// Servers is the Nova server list, fetched best-effort so the
	// info-metric collector can emit lachesis_server_info for dashboard
	// name(id) joins. Empty when the Nova fetch failed or compute is
	// unavailable — the info series is then simply absent
	// ([Client.ListServers], [InfoCollector]).
	Servers []Server
	// LoadBalancers and Amphorae are the Octavia lists feeding
	// [AmphoraOwnerByPort], which re-attributes an Amphora's ports from
	// the Octavia service project to the load balancer's owning tenant
	// (docs/architecture/octavia.md). Fetched best-effort like Servers:
	// an Octavia-less deployment, or one whose credentials cannot read
	// the admin-only amphora list, leaves both empty and every port keeps
	// its own attribution.
	LoadBalancers []LoadBalancer
	Amphorae      []Amphora
}

// TrieEntry is one row destined for the kernel `subnet_zone_trie`:
// the tenant whose perspective the entry applies to, the IPv4
// prefix to match, and the resolved zone code. TenantID is the
// Keystone project UUID; the u32 mapping the kernel actually keys
// on is handled by a separate interner closer to the map writer.
type TrieEntry struct {
	TenantID string
	Prefix   netip.Prefix
	Zone     bpf.ZoneCode
}

// SyncResult is everything one [Neutron.Sync] pass produces: the
// raw resource snapshot, the trie rows built from it, the resolver's
// ambiguity and cycle hits, and the anomaly aggregate over all of
// them. Pure data — nothing is retained until the caller hands the
// value to [Neutron.Commit], after the kernel maps have acknowledged
// the new state.
type SyncResult struct {
	Snapshot    Snapshot
	Entries     []TrieEntry
	Ambiguities []AmbiguityHit
	Cycles      []CycleHit
	Anomalies   Anomalies
}

// AmbiguityHit records a resolver stop where several candidate networks
// with distinct owners cover the same destination CIDR, so no zone can
// be picked honestly. The resolver falls back to EXTERNAL; strict mode
// refuses the boot on any hit. [CycleHit] is the sibling for a revisited
// router.
//
// docs/architecture/trie-construction.md#ambiguity-after-scoping
type AmbiguityHit struct {
	SourceTenant string
	RouterID     string
	Destination  netip.Prefix
	Owners       []string
}

// CycleHit records a static-route chain that revisits an already-seen
// router; the resolver fell back to EXTERNAL. SourceRouter started the
// trace, LoopRouter is the one it tried to revisit.
type CycleHit struct {
	SourceTenant string
	SourceRouter string
	Destination  netip.Prefix
	LoopRouter   string
}

// DanglingRoute records an extraroute whose immediate nexthop does
// not match any port in the snapshot. Detected as a post-pass over
// the routes — the resolver itself silently returns EXTERNAL for
// this case, so without the explicit check the misconfig is
// invisible.
type DanglingRoute struct {
	SourceTenant string
	SourceRouter string
	Destination  string
	Nexthop      string
}

// ZeroTrieTenant flags a tenant that owns at least one network,
// router, or VM-like port but has zero rows in the trie. The
// likely causes are a cold-start ordering gap (trie built before
// the tenant's subnets were visible) or a builder bug that filtered
// the tenant out.
type ZeroTrieTenant struct {
	TenantID string
	Networks int // count of owned networks
	Routers  int // count of owned routers
	Ports    int // count of VM-like ports (IsVMPort)
}

// DuplicateRouterMAC flags router_interface ports sharing a MAC.
// PortIDs are sorted ascending so successive Detect calls produce
// identical output on identical input; RouterIDs is the deduped
// set of routers those ports belong to.
type DuplicateRouterMAC struct {
	MAC       string
	PortIDs   []string
	RouterIDs []string
}

// MultiExternalPathHit records a VM port with several external paths
// within one attribution tier. A FIP on a different network than the
// router gateway is NOT a hit — the FIP tier wins outright. Attribution
// picks one network deterministically, so per-network external billing
// for this VM is approximate.
type MultiExternalPathHit struct {
	PortID     string
	ServerID   string
	ProjectID  string
	Candidates []string // sorted distinct external-network labels
	Picked     string   // the label ExternalNetworkByPort attributes
}

// ResourceMatch is the result of looking up an IP or MAC against
// the Neutron snapshot. Any field may be nil — see [LookupResource]
// and [LookupPortByMAC] for which combinations are produced.
type ResourceMatch struct {
	Subnet  *Subnet
	Network *Network
	Port    *Port
}

// componentNeutron is the slog `component` attribute for all
// Neutron-subsystem log calls. Matches the per-package convention
// the rest of the codebase follows.
const componentNeutron = "neutron"

// endpoint* are the `endpoint` label values for
// lachesis_neutron_api_errors_total. The [Neutron.Sync] auth and
// fetch paths pass these to [Metrics.RecordAPIError]; [NewMetrics]
// seeds each at zero (with the codeNetwork code class) so the
// counter is visible before any error occurs.
const (
	endpointKeystone    = "keystone"
	endpointNetworks    = "networks"
	endpointSubnets     = "subnets"
	endpointPorts       = "ports"
	endpointRouters     = "routers"
	endpointProjects    = "projects"
	endpointFloatingIPs = "floatingips"
	endpointServers     = "servers"
	// endpointLoadBalancers / endpointAmphorae are Octavia, not
	// Neutron. They share the counter because the agent treats
	// "OpenStack metadata fetch" as one subsystem — an operator
	// debugging a stale attribution wants one place to look.
	endpointLoadBalancers = "loadbalancers"
	endpointAmphorae      = "amphorae"
)

// providerAmphora and providerAmphoraAlias are the Octavia provider
// names whose traffic shape [AmphoraOwnerByPort] models: a VM running
// HAProxy, terminating the client connection and originating a fresh
// one to the backend (docs/architecture/octavia.md). "octavia" is the
// deprecated alias of the same driver, still reported by Yoga's
// provider list. The OVN provider preserves the source IP end-to-end
// as a single segment and has no Amphora VM at all — a different shape
// that this subsystem deliberately leaves alone.
const (
	providerAmphora      = "amphora"
	providerAmphoraAlias = "octavia"
)

// amphoraStatusDeleted is the Octavia lifecycle state whose rows no
// longer own any port. [AmphoraOwnerByPort] skips them so a torn-down
// load balancer cannot keep claiming a recycled Nova instance UUID.
const amphoraStatusDeleted = "DELETED"

// anomalyClass* are the `class` label values for the
// lachesis_neutron_anomalies gauge — one per [Anomalies] field.
// [NewMetrics] seeds each at zero so a healthy agent reads 0
// instead of "No data"; [Metrics.SetAnomalies] replaces all five
// on every detection pass.
const (
	anomalyClassCycle              = "cycle"
	anomalyClassAmbiguity          = "ambiguity"
	anomalyClassDanglingRoute      = "dangling_route"
	anomalyClassZeroTrieTenant     = "zero_trie_tenant"
	anomalyClassDuplicateRouterMAC = "duplicate_router_mac"
	anomalyClassMultiExternalPath  = "multi_external_path"
)

// codeNetwork is the `code` label class for connection-level
// failures (refused, DNS, TLS, parse) — everything that never got an
// HTTP status. errCodeLabel maps such errors here; NewMetrics uses
// it as the seed code because it is the one class every endpoint can
// hit regardless of server behaviour.
const codeNetwork = "network"

// defaultInterface is the Keystone endpoint-catalog interface the
// agent picks when the operator does not override it. Compute-node
// agents talk to OpenStack over the internal interface; public is
// only meaningful for off-cluster clients.
const defaultInterface = "internal"

// defaultMaxStaticRouteHops bounds the trace for the argument-free
// [BuildTrie]. Real deployments rarely exceed 3–4 hops. The production
// path does not read this — [Neutron.Sync] passes the hot tunable.
const defaultMaxStaticRouteHops = 16

// Neutron device_owner vocabulary. All three prefixes are matched as
// prefixes, never literals — Nova writes `compute:<az-name>`, so
// `compute:nova` is just the default AZ.
//
// docs/architecture/trie-construction.md#port-classification-device_owner
const (
	deviceOwnerNetworkPrefix   = "network:"
	deviceOwnerComputePrefix   = "compute:"
	deviceOwnerTrunkPrefix     = "trunk:"
	DeviceOwnerRouterInterface = "network:router_interface"
)

// Trie-builder step labels for the
// lachesis_neutron_builder_step_duration_seconds{step=...} histogram.
// The label-value set is the metric's contract with dashboards, so the
// step calls in [buildTrie] and the catalogue in metrics.go reference
// these consts rather than re-typing the strings.
const (
	stepCatchall    = "1_catchall"
	stepOwned       = "2_owned"
	stepShared      = "3_shared"
	stepInfra       = "4_infra"
	stepExtraRoutes = "5_extraroutes"
)

// metadataPrefix is the cloud-init / Nova metadata service IP. Always
// INFRA from every tenant's perspective (trie Step 4).
//
// Full rationale: docs/architecture/trie-construction.md#the-five-step-algorithm
var metadataPrefix = netip.MustParsePrefix("169.254.169.254/32")

// catchall is the 0.0.0.0/0 → EXTERNAL Step-1 entry. Every uncovered
// destination falls through to this row.
var catchall = netip.MustParsePrefix("0.0.0.0/0")
