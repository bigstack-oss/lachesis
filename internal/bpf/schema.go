// schema.go gathers package bpf's constants and type vocabulary: the Go
// mirrors of the kernel types, the enums, the map and program names, and
// the compiled-in map sizes. Every value here mirrors bpf/telemetry.c
// and must stay in lockstep with it.

package bpf

import "strconv"

// FlowKey is the Go-side mirror of the BPF flow_key, the 16-byte key
// the classifier writes into telemetry_map.
//
// INVARIANT — never add the u32 tenant_id to this key. It is interned
// fresh each boot, so a WAL-restored row would key under a stale value
// and never merge with new traffic. The zone code already carries the
// classification without naming a tenant.
//
// docs/architecture/data-structures.md#kernel-side-bpf-maps
type FlowKey = telemetryFlowKey

// FlowMetrics is the Go-side mirror of the BPF flow_metrics map value.
// One instance per CPU is stored in telemetry_map (PERCPU_HASH).
type FlowMetrics = telemetryFlowMetrics

// LpmKey is the Go-side mirror of the BPF lpm_key. It keys subnet_zone_trie
// with (prefixlen, tenant_id, ip) so longest-prefix matching can resolve
// a remote IP to a zone code relative to the source VM's tenant.
type LpmKey = telemetryLpmKey

// AmphoraKey is the Go-side mirror of the BPF amphora_key. It keys
// `amphora_base_ip` with (tenant_id, ip) — tenant-scoped because private
// CIDRs overlap across projects, so a bare-IP set would let one tenant's
// Amphora address reclassify another's traffic. Build with
// [AmphoraKeyForIP].
type AmphoraKey = telemetryAmphoraKey

// ZoneCode is the enum stored in [FlowKey.DstZone]. See [ZoneExternal] and
// the other Zone constants for the set of valid values.
type ZoneCode = telemetryZoneCode

// Direction is the enum stored in [FlowKey.Direction]. See [DirectionIngress]
// and [DirectionEgress] for the set of valid values.
type Direction = telemetryTcDirection

// ZoneExternal through ZoneMulticast are the zone codes stored in
// [FlowKey.DstZone]. Values are stable across releases — they are
// persisted to the WAL and read back on restart.
//
// docs/architecture/trie-construction.md#the-five-step-algorithm
const (
	ZoneExternal    = telemetryZoneCodeZONE_EXTERNAL
	ZoneSameTenant  = telemetryZoneCodeZONE_SAME_TENANT
	ZoneOtherTenant = telemetryZoneCodeZONE_OTHER_TENANT
	ZoneInfra       = telemetryZoneCodeZONE_INFRA
	ZoneMiss        = telemetryZoneCodeZONE_MISS
	ZoneShared      = telemetryZoneCodeZONE_SHARED
	ZoneMulticast   = telemetryZoneCodeZONE_MULTICAST
)

// String returns the canonical zone name. This is the single
// vocabulary behind the `zone` metric label (pinned by dashboards),
// /debug and logs. Unknown codes render numerically rather than
// silently misclassifying. Constant strings only — safe in the
// zero-allocation Collect() path.
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
	case ZoneMulticast:
		return "multicast"
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

// String returns the canonical direction name: "tx" for
// [DirectionIngress] (VM sending), "rx" for [DirectionEgress] (VM
// receiving). Deliberately VM-frame, not the host-side hook names —
// exporting "ingress"/"egress" would invert the cloud-billing
// convention. Constant strings only, for the hot path.
//
// docs/architecture/metrics.md
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
	MapAmphoraBaseIP  = "amphora_base_ip"
)

// These mirror the `max_entries` compiled into bpf/telemetry.c, which
// is where the sizing rationale lives. [ValidateMapSizes] fails the
// boot on drift, so a stale `.o` cannot silently undersize a map or
// skew the pressure-relief fill ratio.
//
// docs/architecture/data-structures.md#kernel-side-bpf-maps
const (
	MapTelemetryMaxEntries      = 65536
	MapSubnetZoneTrieMaxEntries = 16384
	MapMacTenantMaxEntries      = 8192
	MapTelemetryStatsMaxEntries = statReasonCount
	MapAmphoraBaseIPMaxEntries  = 1024
)

// TenantAmphoraFlag and TenantIDMask mirror the packing of a
// `mac_tenant_map` value in bpf/telemetry.c: the top bit marks an Octavia
// Amphora data port, the low 31 bits carry the interned tenant id.
//
// The kernel masks the id off before comparing tenants and before using it
// as the `subnet_zone_trie` key, and returns ZONE_INFRA when either end of
// an L2-adjacent flow carries the flag — that is Segment 2, load-balancer
// plumbing rather than tenant traffic (docs/architecture/octavia.md).
// Userspace sets the bit in [kernelwriter.WriteMacTenantMap] and the
// reconciler's per-MAC writer; use [TenantValue] rather than open-coding
// the OR, so there is one place the C and Go sides must agree.
//
// The mask bounds a deployment at 2^31-1 tenants. [metadata.TenantInterner]
// assigns from 1 and a large cluster reaches thousands, so the ceiling is
// unreachable — it is documented, not enforced.
const (
	TenantAmphoraFlag uint32 = 0x8000_0000
	TenantIDMask      uint32 = 0x7fff_ffff
)

// TenantValue packs an interned tenant id and the Amphora marker into the
// u32 a `mac_tenant_map` entry stores. See [TenantAmphoraFlag].
func TenantValue(tenantID uint32, isAmphora bool) uint32 {
	if isAmphora {
		return tenantID | TenantAmphoraFlag
	}
	return tenantID
}

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
