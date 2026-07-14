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

// Snapshot is the four Neutron resource lists the agent consumes
// together at cold-start and at every full-resync triggered by the
// Kafka updater, plus the Keystone project list. Bundled into one
// type so callers can pass it around as a single value instead of
// parallel slices.
//
// The fields are slices in API-iteration order — no sorting
// guarantee. Downstream consumers that need stable ordering
// (e.g. the trie builder) sort their own derived outputs.
type Snapshot struct {
	Networks []Network
	Subnets  []Subnet
	Ports    []Port
	Routers  []Router
	// Projects is the Keystone project list. Carried alongside the
	// Neutron resources because Neutron returns project_id as a bare
	// UUID; consumers that need a human-readable label (the /debug
	// pages, log enrichment) resolve through this slice.
	Projects []Project
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

// AmbiguityHit records a Step C ambiguity-after-scoping incident
// (docs/DESIGN.md §5.6): the resolver reached a router where
// multiple candidate networks with distinct owners cover the same
// destination CIDR, so no single zone can be picked honestly. The
// resolver returns ZoneExternal and surfaces this struct to its
// caller; BuildTrie collects every hit across all routes so the
// boot path can refuse to start under strict-mode policy.
//
// CycleHit is the sibling type for "trace revisited a router on
// the path"; both are aggregated into [Anomalies] by
// [DetectAnomalies].
type AmbiguityHit struct {
	SourceTenant string
	RouterID     string
	Destination  netip.Prefix
	Owners       []string
}

// CycleHit records a static-route cycle the resolver encountered
// while tracing one (router, destination) pair. The destination is
// reachable only via a router-interface chain that revisits an
// already-seen router; the resolver fell back to EXTERNAL.
//
// SourceRouter is the router whose Routes entry triggered the
// trace; LoopRouter is the router we attempted to revisit (the
// already-seen one). On a two-router A↔B cycle both fields name A
// or B depending on which router's extraroute initiated the trace.
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
// cubecos_neutron_api_errors_total. The [Neutron.Sync] auth and
// fetch paths pass these to [Metrics.RecordAPIError]; [NewMetrics]
// seeds each at zero (with the codeNetwork code class) so the
// counter is visible before any error occurs.
const (
	endpointKeystone = "keystone"
	endpointNetworks = "networks"
	endpointSubnets  = "subnets"
	endpointPorts    = "ports"
	endpointRouters  = "routers"
	endpointProjects = "projects"
)

// anomalyClass* are the `class` label values for the
// cubecos_neutron_anomalies gauge — one per [Anomalies] field.
// [NewMetrics] seeds each at zero so a healthy agent reads 0
// instead of "No data"; [Metrics.SetAnomalies] replaces all five
// on every detection pass.
const (
	anomalyClassCycle              = "cycle"
	anomalyClassAmbiguity          = "ambiguity"
	anomalyClassDanglingRoute      = "dangling_route"
	anomalyClassZeroTrieTenant     = "zero_trie_tenant"
	anomalyClassDuplicateRouterMAC = "duplicate_router_mac"
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

// maxStaticRouteHops bounds the multi-hop trace. Real OpenStack
// deployments rarely exceed 3–4 hops; 16 is generous and an
// exceedance almost certainly indicates a routing misconfig (per
// docs/DESIGN.md §5.3).
const maxStaticRouteHops = 16

// Neutron device_owner vocabulary. deviceOwnerNetworkPrefix is the
// reserved `network:` namespace that [IsInfraPort] / [IsVMPort] use to
// partition infra ports from VM-like ports; deviceOwnerComputePrefix
// is Nova's namespace — Nova writes `compute:<az-name>` ("nova" is
// only the default AZ's name), so [IsComputePort] matches the prefix;
// deviceOwnerTrunkPrefix is the namespace Neutron's trunk extension
// writes on subports, matched by [IsTrunkSubport];
// DeviceOwnerRouterInterface is the specific owner the static-route
// resolver follows hop-to-hop (exported: the /debug topology builders
// classify attachments with it too).
const (
	deviceOwnerNetworkPrefix   = "network:"
	deviceOwnerComputePrefix   = "compute:"
	deviceOwnerTrunkPrefix     = "trunk:"
	DeviceOwnerRouterInterface = "network:router_interface"
)

// Trie-builder step labels for the
// cubecos_neutron_builder_step_duration_seconds{step=...} histogram.
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
// INFRA from every tenant's perspective (docs/DESIGN.md §5.2 Step 4).
var metadataPrefix = netip.MustParsePrefix("169.254.169.254/32")

// catchall is the 0.0.0.0/0 → EXTERNAL Step-1 entry. Every uncovered
// destination falls through to this row.
var catchall = netip.MustParsePrefix("0.0.0.0/0")
