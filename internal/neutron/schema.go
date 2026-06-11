// schema.go gathers package neutron's package-level constants, well-known
// prefixes, and the pure-data Snapshot / AmbiguityHit holders. The Neutron
// resource record types live in types.go; the resolver, trie builder, and
// API client that consume this vocabulary live in resolve.go / trie.go /
// client.go.

package neutron

import "net/netip"

// Snapshot is the four Neutron resource lists the agent consumes
// together at cold-start and at every full-resync triggered by the
// Kafka updater. Bundled into one type so callers can pass it
// around as a single value instead of four parallel slices.
//
// The fields are slices in API-iteration order — no sorting
// guarantee. Downstream consumers that need stable ordering
// (e.g. the trie builder) sort their own derived outputs.
type Snapshot struct {
	Networks []Network
	Subnets  []Subnet
	Ports    []Port
	Routers  []Router
}

// AmbiguityHit records a Step C ambiguity-after-scoping incident
// (docs/DESIGN.md §5.6): the resolver reached a router where
// multiple candidate networks with distinct owners cover the same
// destination CIDR, so no single zone can be picked honestly. The
// resolver returns ZoneExternal and surfaces this struct to its
// caller; BuildTrie collects every hit across all routes so the
// boot path can refuse to start under strict-mode policy.
type AmbiguityHit struct {
	SourceTenant string
	RouterID     string
	Destination  netip.Prefix
	Owners       []string
}

// componentNeutron is the slog `component` attribute for all
// Neutron-subsystem log calls. Matches the per-package convention
// the rest of the codebase follows.
const componentNeutron = "neutron"

// Endpoint* are the `endpoint` label values for
// cubecos_neutron_api_errors_total. Callers of
// [Metrics.RecordAPIError] pass these; [NewMetrics] seeds each at
// zero (with the codeNetwork code class) so the counter is visible
// before any error occurs.
const (
	EndpointKeystone = "keystone"
	EndpointNetworks = "networks"
	EndpointSubnets  = "subnets"
	EndpointPorts    = "ports"
	EndpointRouters  = "routers"
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

// defaultDomain is the Keystone v3 domain assumed for the user and
// project when an openrc file omits OS_USER_DOMAIN_NAME /
// OS_PROJECT_DOMAIN_NAME — "default" is the standard single-domain
// deployment name.
const defaultDomain = "default"

// maxStaticRouteHops bounds the multi-hop trace. Real OpenStack
// deployments rarely exceed 3–4 hops; 16 is generous and an
// exceedance almost certainly indicates a routing misconfig (per
// docs/DESIGN.md §5.3).
const maxStaticRouteHops = 16

// Neutron device_owner vocabulary. deviceOwnerNetworkPrefix is the
// reserved `network:` namespace that [IsInfraPort] / [IsVMPort] use to
// partition infra ports from VM-like ports; deviceOwnerRouterInterface
// is the specific owner the static-route resolver follows hop-to-hop.
const (
	deviceOwnerNetworkPrefix   = "network:"
	deviceOwnerRouterInterface = "network:router_interface"
)

// BuildTrie step labels for the
// cubecos_neutron_builder_step_duration_seconds{step=...} histogram.
// The label-value set is the metric's contract with dashboards, so the
// call sites in BuildTrie and the catalogue in metrics.go reference
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
