// schema.go gathers package debug's package-level constants and the
// method-less view models the page builders emit. Models double as
// the JSON wire shape (`?format=json`) and the html/template data,
// so every field carries a json tag. The Server, handlers, and
// builders that consume this vocabulary live in debug.go and the
// per-page files.

package debug

import "time"

// componentDebug is the slog `component` attribute for all
// debug-subsystem log calls. Matches the per-package convention the
// rest of the codebase follows.
const componentDebug = "debug"

// paramFormat / formatJSON select the response encoding: every HTML
// page returns its view model as indented JSON when the request
// carries `?format=json`, so operators can curl|jq the exact data
// the page renders.
const (
	paramFormat = "format"
	formatJSON  = "json"
)

// syncStaleThreshold is the age above which the pages render the
// sync badge in the warn style. Picked at 5× the typical resync
// cadence so a healthy cluster never shows warn during quiet
// periods, but a broken updater surfaces within a couple of minutes.
const syncStaleThreshold = 5 * time.Minute

// extrarouteOut / extrarouteIn are the [extrarouteRow] Direction
// vocabulary: whether the extraroute sits on the focused tenant's own
// router ("out") or points at it from another tenant's ("in"). Route
// relationship, not packet direction — deliberately distinct from
// [bpf.Direction]'s "tx"/"rx".
const (
	extrarouteOut = "out"
	extrarouteIn  = "in"
)

// indexModel is the /debug index view: sync recency, resource
// counts, per-class anomaly counts with links into the detail
// pages, and the inline lookup form state.
type indexModel struct {
	Synced      bool      `json:"synced"`
	LastSync    time.Time `json:"last_sync"`
	SyncAgeText string    `json:"sync_age,omitempty"`
	SyncStale   bool      `json:"sync_stale"`

	Counts    indexCounts   `json:"counts"`
	Anomalies anomalyCounts `json:"anomalies"`

	// Lookup form state. LookupQuery pre-fills the form inputs;
	// LookupResult or LookupError populates the inline result
	// section. Pointer-typed so the template's `{{ if }}` guards
	// work without coupling to zero-value semantics.
	LookupQuery  lookupQuery   `json:"-"`
	LookupResult *lookupResult `json:"lookup,omitempty"`
	LookupError  string        `json:"lookup_error,omitempty"`
}

// indexCounts is the health strip: how much of the cluster the
// agent's retained snapshot covers.
type indexCounts struct {
	Tenants  int `json:"tenants"`
	Networks int `json:"networks"`
	Subnets  int `json:"subnets"`
	Ports    int `json:"ports"`
	Routers  int `json:"routers"`
	TrieRows int `json:"trie_rows"`
}

// anomalyCounts mirrors the five [neutron.Anomalies] classes as
// counts. Field order matches the cubecos_neutron_anomalies class
// label set.
type anomalyCounts struct {
	Total               int `json:"total"`
	Cycles              int `json:"cycles"`
	Ambiguities         int `json:"ambiguities"`
	DanglingRoutes      int `json:"dangling_routes"`
	ZeroTrieTenants     int `json:"zero_trie_tenants"`
	DuplicateRouterMACs int `json:"duplicate_router_macs"`
}

// anomaliesModel is the /debug/anomalies view: the five anomaly
// classes flattened to display rows, with project names resolved
// where the snapshot knows them.
type anomaliesModel struct {
	Total               int            `json:"total"`
	Cycles              []cycleRow     `json:"cycles"`
	Ambiguities         []ambiguityRow `json:"ambiguities"`
	DanglingRoutes      []danglingRow  `json:"dangling_routes"`
	ZeroTrieTenants     []zeroTrieRow  `json:"zero_trie_tenants"`
	DuplicateRouterMACs []dupMACRow    `json:"duplicate_router_macs"`
}

type cycleRow struct {
	SourceTenant     string `json:"source_tenant"`
	SourceTenantName string `json:"source_tenant_name,omitempty"`
	SourceRouter     string `json:"source_router"`
	Destination      string `json:"destination"`
	LoopRouter       string `json:"loop_router"`
}

type ambiguityRow struct {
	SourceTenant     string   `json:"source_tenant"`
	SourceTenantName string   `json:"source_tenant_name,omitempty"`
	RouterID         string   `json:"router_id"`
	Destination      string   `json:"destination"`
	Owners           []string `json:"owners"`
	// OwnersDisplay pre-joins Owners with resolved names for the
	// HTML table; the JSON consumer uses the raw Owners slice.
	OwnersDisplay string `json:"-"`
}

type danglingRow struct {
	SourceTenant     string `json:"source_tenant"`
	SourceTenantName string `json:"source_tenant_name,omitempty"`
	SourceRouter     string `json:"source_router"`
	Destination      string `json:"destination"`
	Nexthop          string `json:"nexthop"`
}

type zeroTrieRow struct {
	TenantID   string `json:"tenant_id"`
	TenantName string `json:"tenant_name,omitempty"`
	Networks   int    `json:"networks"`
	Routers    int    `json:"routers"`
	Ports      int    `json:"ports"`
}

type dupMACRow struct {
	MAC       string   `json:"mac"`
	PortIDs   []string `json:"port_ids"`
	RouterIDs []string `json:"router_ids"`
	// PortsDisplay / RoutersDisplay pre-join the ID slices for the
	// HTML table; the JSON consumer uses the raw slices.
	PortsDisplay   string `json:"-"`
	RoutersDisplay string `json:"-"`
}

// lookupResult is the /debug/lookup JSON envelope, also rendered
// inline on the index page. Each sub-section corresponds to one
// independently-resolved question: zone classification, owning
// Neutron resource, MAC→tenant map entry. A query populates the
// sections relevant to its inputs; the others are omitted.
type lookupResult struct {
	Query   lookupQuery     `json:"query"`
	Zone    *lookupZone     `json:"zone,omitempty"`
	Neutron *lookupNeutron  `json:"neutron,omitempty"`
	MAC     *lookupMACEntry `json:"mac_tenant_map,omitempty"`
}

type lookupQuery struct {
	IP     string `json:"ip,omitempty"`
	MAC    string `json:"mac,omitempty"`
	Tenant string `json:"tenant,omitempty"`
}

// lookupZone reports the trie row the kernel would match for the
// queried IP. Via is "tenant" when a per-tenant row matched, or
// "global" when the catchall / sentinel rows did.
type lookupZone struct {
	Code  string        `json:"code"`
	Via   string        `json:"via"`
	Match lookupTrieRow `json:"matched_row"`
}

type lookupTrieRow struct {
	TenantID   string `json:"tenant_id"`
	TenantName string `json:"tenant_name,omitempty"`
	Prefix     string `json:"prefix"`
	Zone       string `json:"zone"`
}

// lookupNeutron describes which Neutron resources own the queried
// address. Any field may be nil — see [neutron.LookupResource] and
// [neutron.LookupPortByMAC] for which combinations are produced.
type lookupNeutron struct {
	Subnet  *lookupSubnet  `json:"subnet,omitempty"`
	Network *lookupNetwork `json:"network,omitempty"`
	Port    *lookupPort    `json:"port,omitempty"`
	Owner   *lookupTenant  `json:"owner,omitempty"`
}

type lookupSubnet struct {
	ID        string `json:"id"`
	CIDR      string `json:"cidr"`
	GatewayIP string `json:"gateway_ip,omitempty"`
}

type lookupNetwork struct {
	ID         string `json:"id"`
	Name       string `json:"name,omitempty"`
	Shared     bool   `json:"shared,omitempty"`
	IsExternal bool   `json:"external,omitempty"`
}

type lookupPort struct {
	ID          string `json:"id"`
	MAC         string `json:"mac,omitempty"`
	DeviceOwner string `json:"device_owner,omitempty"`
	DeviceID    string `json:"device_id,omitempty"`
}

type lookupTenant struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

// lookupMACEntry reports what the userspace `mac_tenant_map`
// mirror has for the queried MAC. Found=false with an otherwise
// empty struct distinguishes "MAC absent from the map" from "no
// MAC query made" — the latter omits the whole section.
type lookupMACEntry struct {
	Found      bool   `json:"found"`
	TenantID   string `json:"tenant_id,omitempty"`
	TenantName string `json:"tenant_name,omitempty"`
	IsAmphora  bool   `json:"is_amphora,omitempty"`
}

// zonesModel is the /debug/zones view: the LPM trie as the kernel
// sees it, one row per (tenant, prefix, zone).
type zonesModel struct {
	Synced   bool      `json:"synced"`
	LastSync time.Time `json:"last_sync"`
	// Tenants feeds the HTML filter dropdown; the JSON consumer
	// derives the set from the rows.
	Tenants []tenantOption `json:"-"`
	Rows    []zoneRow      `json:"rows"`
}

// tenantOption is one entry in the tenant filter dropdown. ID is the
// raw TenantID used by the JS row filter; Label is the human-readable
// string shown to the operator ("acme-prod (abc12345…)" or "(global)").
type tenantOption struct {
	ID    string
	Label string
}

// zoneRow is one (tenant, prefix, zone) line in the zones table.
// Zone carries the canonical [bpf.ZoneCode.String] form — the same
// vocabulary as the /metrics zone label.
type zoneRow struct {
	Tenant     string `json:"tenant_id"`
	TenantName string `json:"tenant_name,omitempty"`
	Prefix     string `json:"prefix"`
	Zone       string `json:"zone"`
}

// topologyDirectoryModel is the /debug/topology view — the
// per-tenant directory table. The page deliberately renders no
// graph: at production scale (36 tenants, 130+ networks) a global
// canvas is unreadable. Operators drill into a tenant via the
// linked detail view.
type topologyDirectoryModel struct {
	Synced   bool           `json:"synced"`
	LastSync time.Time      `json:"last_sync"`
	Rows     []directoryRow `json:"rows"`
}

// directoryRow summarises one tenant's footprint plus its
// cross-tenant edge counts. CrossTotal is the default sort key
// (descending) so hubs surface first.
type directoryRow struct {
	TenantID   string `json:"tenant_id"`
	TenantName string `json:"tenant_name,omitempty"`
	Networks   int    `json:"networks"`
	Routers    int    `json:"routers"`
	OutAttach  int    `json:"attach_out"`     // my routers attach to other tenants' networks
	InAttach   int    `json:"attach_in"`      // other tenants' routers attach to my networks
	OutExtra   int    `json:"extraroute_out"` // my routers extraroute via other tenants' routers
	InExtra    int    `json:"extraroute_in"`  // other tenants' routers extraroute via my routers
	CrossTotal int    `json:"cross_total"`    // sum of the four cross-tenant counts
}

// topologyTenantModel is the /debug/topology/{tenant} view.
// Text-first layout: tables for networks / routers / extraroutes.
// Cross-tenant rows are marked inline; cycles and ambiguities — the
// anomalies that actually need attention — live on /debug/anomalies.
type topologyTenantModel struct {
	Synced     bool      `json:"synced"`
	LastSync   time.Time `json:"last_sync"`
	TenantID   string    `json:"tenant_id"`
	TenantName string    `json:"tenant_name,omitempty"`
	// NotFound is true when the tenant owns no Neutron resources
	// and no cross-tenant edge touches it.
	NotFound bool          `json:"not_found,omitempty"`
	Summary  tenantSummary `json:"summary"`

	Networks    []tenantNetworkRow `json:"networks"`
	Routers     []tenantRouterCard `json:"routers"`
	Extraroutes []extrarouteRow    `json:"cross_extraroutes"`
}

// tenantSummary is the counts strip rendered under the page header.
type tenantSummary struct {
	Networks        int `json:"networks"`
	Routers         int `json:"routers"`
	Attachments     int `json:"attachments"`      // total router_interface attachments (internal + cross)
	Extraroutes     int `json:"extraroutes"`      // total extraroutes
	CrossAttach     int `json:"cross_attach"`     // cross-tenant attachments only
	CrossExtraroute int `json:"cross_extraroute"` // cross-tenant extraroutes only
}

// tenantNetworkRow is one row in the per-tenant Networks table.
type tenantNetworkRow struct {
	ID    string   `json:"id"`
	Name  string   `json:"name"`
	CIDRs []string `json:"cidrs,omitempty"`
	Kind  string   `json:"kind,omitempty"` // "" (regular) / "shared" / "external"
}

// tenantRouterCard groups one router's metadata with its inline
// attachment + extraroute lists.
type tenantRouterCard struct {
	ID                  string                `json:"id"`
	Name                string                `json:"name,omitempty"`
	ExternalGatewayID   string                `json:"external_gateway_id,omitempty"`
	ExternalGatewayName string                `json:"external_gateway_name,omitempty"`
	Attachments         []routerAttachmentRow `json:"attachments"`
	Extraroutes         []routerExtrarouteRow `json:"extraroutes"`
}

// routerAttachmentRow describes one router_interface attachment from
// a particular router's perspective. CrossTenant is true when the
// router and the network have different ProjectIDs.
type routerAttachmentRow struct {
	NetworkID         string `json:"network_id"`
	NetworkName       string `json:"network_name"`
	NetworkTenantID   string `json:"network_tenant_id"`
	NetworkTenantName string `json:"network_tenant_name,omitempty"`
	IP                string `json:"ip,omitempty"`
	CrossTenant       bool   `json:"cross_tenant"`
}

// routerExtrarouteRow is one extraroute entry. NextRouterID is empty
// when the nexthop IP did not resolve to a known router_interface
// port (e.g. nexthop is a VM appliance or a dangling reference).
type routerExtrarouteRow struct {
	Destination          string `json:"destination"`
	Nexthop              string `json:"nexthop"`
	NextRouterID         string `json:"next_router_id,omitempty"`
	NextRouterTenantID   string `json:"next_router_tenant_id,omitempty"`
	NextRouterTenantName string `json:"next_router_tenant_name,omitempty"`
	CrossTenant          bool   `json:"cross_tenant"`
}

// extrarouteRow is the flat cross-tenant extraroutes table at the
// page bottom — each cross-tenant extraroute (outgoing or incoming)
// gets one row regardless of which router it belongs to.
type extrarouteRow struct {
	Direction        string `json:"direction"` // extrarouteOut (my router) or extrarouteIn (other tenant's router)
	SourceRouterID   string `json:"source_router_id"`
	SourceTenantID   string `json:"source_tenant_id"`
	SourceTenantName string `json:"source_tenant_name,omitempty"`
	Destination      string `json:"destination"`
	Nexthop          string `json:"nexthop"`
	TargetRouterID   string `json:"target_router_id"`
	TargetTenantID   string `json:"target_tenant_id"`
	TargetTenantName string `json:"target_tenant_name,omitempty"`
}
