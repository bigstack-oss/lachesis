// schema.go gathers package bpf's package-level constants and exported
// type vocabulary in one place: the Go mirrors of the kernel types, the
// zone, direction, and stat-reason enums, the program and map name
// strings, the compiled-in map sizes — all of which mirror
// bpf/telemetry.c and must stay in lockstep with it — plus the
// Prometheus label keys. The helpers and loader that consume this
// vocabulary (MACKey, LpmKeyForPrefix, LoadTelemetry, ValidateMapSizes)
// and the package overview live in abi.go; the telemetry_stats reader
// lives in stats.go.

package bpf

import "strconv"

// FlowKey is the Go-side mirror of the BPF flow_key map key. It is
// the 16-byte composite key written by the classifier into
// telemetry_map.
//
// INVARIANT — no u32 tenant_id in the key.
//
// FlowKey carries only MAC pairs, EtherType, direction, and the
// resolved zone code. It does NOT and MUST NOT carry the u32
// `tenant_id` that the kernel `mac_tenant_map` / `subnet_zone_trie`
// use internally. That u32 is interned fresh on every agent boot
// (see internal/metadata.TenantInterner), so embedding it here
// would invalidate every WAL-restored
// GlobalState entry on restart: the same logical flow would be
// keyed under a stale u32 and never merge with new traffic.
// The zone code already encodes the *classification* (SAME / OTHER
// / INFRA / EXTERNAL / SHARED) without referencing the specific
// tenant identifier, which is what makes restart-merge work. See
// docs/DESIGN.md §3.1 for the broader rationale.
type FlowKey = telemetryFlowKey

// FlowMetrics is the Go-side mirror of the BPF flow_metrics map value.
// One instance per CPU is stored in telemetry_map (PERCPU_HASH).
type FlowMetrics = telemetryFlowMetrics

// LpmKey is the Go-side mirror of the BPF lpm_key. It keys subnet_zone_trie
// with (prefixlen, tenant_id, ip) so longest-prefix matching can resolve
// a remote IP to a zone code relative to the source VM's tenant.
type LpmKey = telemetryLpmKey

// ZoneCode is the enum stored in [FlowKey.DstZone]. See [ZoneExternal] and
// the other Zone constants for the set of valid values.
type ZoneCode = telemetryZoneCode

// Direction is the enum stored in [FlowKey.Direction]. See [DirectionIngress]
// and [DirectionEgress] for the set of valid values.
type Direction = telemetryTcDirection

// ZoneExternal through ZoneShared are the zone codes stored in
// [FlowKey.DstZone]. The values are stable across releases: they are
// persisted to the WAL and read back on restart.
//
// ZoneShared exists because the LPM trie cannot disambiguate per-VM
// ownership inside a shared-network /24. Rather than guess SAME vs
// OTHER for the trie-fallback path on shared networks, the
// cold-start builder emits a distinct ZoneShared row; the billing
// engine treats it as its own category. See docs/DESIGN.md §5.2
// Step 3.
const (
	ZoneExternal    = telemetryZoneCodeZONE_EXTERNAL
	ZoneSameTenant  = telemetryZoneCodeZONE_SAME_TENANT
	ZoneOtherTenant = telemetryZoneCodeZONE_OTHER_TENANT
	ZoneInfra       = telemetryZoneCodeZONE_INFRA
	ZoneMiss        = telemetryZoneCodeZONE_MISS
	ZoneShared      = telemetryZoneCodeZONE_SHARED
)

// String returns the canonical name of the zone code — "external",
// "same_tenant", etc. This is the single vocabulary for every
// rendering of the enum: the `zone` label on lachesis_bytes_total /
// lachesis_packets_total (pinned by dashboards), /debug pages, and
// log enrichment. Unknown codes fall back to the numeric encoding
// so a future kernel-side addition is still visible rather than
// silently misclassified. Returns constant strings for all known
// codes — safe inside the zero-allocation Collect() hot path.
func (z ZoneCode) String() string {
	switch z {
	case ZoneExternal:
		return "external"
	case ZoneSameTenant:
		return "same_tenant"
	case ZoneOtherTenant:
		return "other_tenant"
	case ZoneInfra:
		return "infra"
	case ZoneMiss:
		return "miss"
	case ZoneShared:
		return "shared"
	}
	return strconv.FormatUint(uint64(z), 10)
}

// DirectionIngress and DirectionEgress are the TC hook direction values
// stored in [FlowKey.Direction]. The names are hook-frame: the TC hooks
// sit on the tap interface (host side), so the tap's ingress hook sees
// frames the VM transmits — DirectionIngress means the VM is sending,
// DirectionEgress means the VM is receiving.
const (
	DirectionIngress = telemetryTcDirectionTC_DIR_INGRESS
	DirectionEgress  = telemetryTcDirectionTC_DIR_EGRESS
)

// String returns the canonical name of the direction — "tx" for
// [DirectionIngress] (VM sending) and "rx" for [DirectionEgress]
// (VM receiving). These strings are the metric-label contract: the
// `direction` label on lachesis_bytes_total / lachesis_packets_total
// (pinned by dashboards), /debug pages, and log enrichment all render
// through here — the same single-vocabulary contract as
// [ZoneCode.String]. The vocabulary is deliberately VM-frame and
// NIC-conventional, not the raw hook names: the tap hooks are
// host-side, so exporting "ingress"/"egress" would invert the
// cloud-billing convention where egress means data leaving the VM
// (see docs/DESIGN.md §11.4). Unknown values fall back to the numeric
// encoding. Returns constant strings for all known values — safe
// inside the zero-allocation Collect() hot path.
func (d Direction) String() string {
	switch d {
	case DirectionIngress:
		return "tx"
	case DirectionEgress:
		return "rx"
	}
	return strconv.FormatUint(uint64(d), 10)
}

// StatReason indexes a slot in the kernel `telemetry_stats`
// PERCPU_ARRAY. See [StatUpdateFailure] and [StatSkippedEthertype]
// for the set of valid values.
type StatReason uint32

// StatUpdateFailure and StatSkippedEthertype are the telemetry_stats
// slot indices. Values mirror `enum stat_reason` in bpf/telemetry.c
// and must stay in lockstep with it — the kernel increments by these
// indices and userspace reads by them.
const (
	StatUpdateFailure    StatReason = 0
	StatSkippedEthertype StatReason = 1
)

// statReasonCount mirrors STAT_REASON_MAX in bpf/telemetry.c. It sizes
// [StatCounts] and, via [MapTelemetryStatsMaxEntries], the map itself —
// so a C-side reason added without updating the Go mirror fails
// [ValidateMapSizes] at boot instead of silently skewing slots.
const statReasonCount = 2

// String returns the canonical name of the stat reason —
// "update_failure" or "skipped_ethertype". Same single-vocabulary
// contract as [ZoneCode.String]: these are the `reason` label values
// on lachesis_bpf_update_failures_total, pinned by dashboards and
// alert rules. Unknown values fall back to the numeric encoding.
func (r StatReason) String() string {
	switch r {
	case StatUpdateFailure:
		return "update_failure"
	case StatSkippedEthertype:
		return "skipped_ethertype"
	}
	return strconv.FormatUint(uint64(r), 10)
}

// StatCounts holds one CPU-summed cumulative counter per [StatReason],
// indexed by it: counts[StatUpdateFailure]. Produced by
// [StatsReader.Read]; consumed by [Metrics.SetUpdateFailures].
type StatCounts [statReasonCount]uint64

// ProgramIngress and ProgramEgress are the SEC("tc") function names
// of the ingress and egress telemetry programs in bpf/telemetry.c.
// Loaders use these names to look up [*ebpf.Program] handles from a
// loaded [*ebpf.Collection]; the strings cross the C↔Go boundary
// and must match the C symbol exactly.
const (
	ProgramIngress = "tc_telemetry_in"
	ProgramEgress  = "tc_telemetry_out"
)

// MapTelemetry, MapSubnetZoneTrie, MapMacTenant, and MapTelemetryStats
// are the SEC(".maps") names of the maps in bpf/telemetry.c. Same C↔Go
// contract as the program names above: loaders look up [*ebpf.Map]
// handles by these strings on a loaded [*ebpf.Collection], and a typo
// on either side becomes a missing-map panic at boot.
const (
	MapTelemetry      = "telemetry_map"
	MapSubnetZoneTrie = "subnet_zone_trie"
	MapMacTenant      = "mac_tenant_map"
	MapTelemetryStats = "telemetry_stats"
)

// MapSubnetZoneTrieMaxEntries and MapMacTenantMaxEntries mirror the
// `max_entries` values compiled into bpf/telemetry.c. They are
// exposed for two reasons:
//
//  1. Load-time assertions can check the kernel spec matches what
//     userspace expects, catching a stale `.o` build before the
//     agent silently writes into an undersized map.
//  2. The lachesis_bpf_map_max_entries gauge needs the denominator
//     so dashboards can compute "% of map occupied" against
//     lachesis_bpf_map_current_entries.
//
// Sizing rationale lives in bpf/telemetry.c above each map decl.
//
// MapTelemetryMaxEntries mirrors telemetry_map's max_entries. It is
// the denominator for the pressure-relief GC fill-ratio (docs/DESIGN.md
// §3.1), so a stale `.o` that changed it would skew the >80% eviction
// trigger — hence it is drift-checked alongside the other two.
//
// MapTelemetryStatsMaxEntries mirrors STAT_REASON_MAX: one slot per
// [StatReason], fixed regardless of deployment scale. Drift-checking
// it makes [ValidateMapSizes] double as the stat-reason enum lockstep
// guard (see [statReasonCount]).
const (
	MapTelemetryMaxEntries      = 65536
	MapSubnetZoneTrieMaxEntries = 16384
	MapMacTenantMaxEntries      = 8192
	MapTelemetryStatsMaxEntries = statReasonCount
)

// LpmKeyTenantBits is the constant Prefixlen contribution from the
// tenant_id field. The kernel LPM trie matches `tenant_id` exactly
// (all 32 bits) before walking the IP portion, so every entry adds
// 32 to the IP prefix length to produce the full key prefixlen.
const LpmKeyTenantBits uint32 = 32

// labelMap is the Prometheus label key naming the BPF map in the
// lachesis_bpf_map_max_entries / lachesis_bpf_map_current_entries gauges
// (see metrics.go).
const labelMap = "map"

// labelReason is the Prometheus label key naming the kernel-side
// failure/skip reason on lachesis_bpf_update_failures_total (see
// metrics.go); values come from [StatReason.String].
const labelReason = "reason"
