// Package bpf exposes the kernel↔userspace ABI for the telemetry agent.
//
// The map specs, program entry points, and low-level loader are generated
// by bpf2go from bpf/telemetry.c into telemetry_bpfel.go. Those generated
// names are intentionally unexported (the bpf2go prefix is lowercase). This
// file is the only public surface of the package: callers use FlowKey,
// LoadTelemetry, ZoneSameTenant, etc., never the generated identifiers.
//
// All declarations here must stay in lockstep with bpf/telemetry.c. The
// struct layouts and constant values cross the kernel↔userspace boundary;
// silent skew between sides produces incorrect metrics.
package bpf

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"
)

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
// (see internal/metadata.TenantInterner, landing in Sprint 4a.6),
// so embedding it here would invalidate every WAL-restored
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
// OTHER for the trie-fallback path on shared networks, the cold-start
// builder emits a distinct ZoneShared row; the billing engine treats
// it as its own category. See docs/DESIGN.md §5.2 Step 3.
const (
	ZoneExternal    = telemetryZoneCodeZONE_EXTERNAL
	ZoneSameTenant  = telemetryZoneCodeZONE_SAME_TENANT
	ZoneOtherTenant = telemetryZoneCodeZONE_OTHER_TENANT
	ZoneInfra       = telemetryZoneCodeZONE_INFRA
	ZoneMiss        = telemetryZoneCodeZONE_MISS
	ZoneShared      = telemetryZoneCodeZONE_SHARED
)

// DirectionIngress and DirectionEgress are the TC hook direction values
// stored in [FlowKey.Direction].
const (
	DirectionIngress = telemetryTcDirectionTC_DIR_INGRESS
	DirectionEgress  = telemetryTcDirectionTC_DIR_EGRESS
)

// ProgramIngress and ProgramEgress are the SEC("tc") function names
// of the ingress and egress telemetry programs in bpf/telemetry.c.
// Loaders use these names to look up [*ebpf.Program] handles from a
// loaded [*ebpf.Collection]; the strings cross the C↔Go boundary
// and must match the C symbol exactly.
const (
	ProgramIngress = "tc_telemetry_in"
	ProgramEgress  = "tc_telemetry_out"
)

// MapTelemetry, MapSubnetZoneTrie, and MapMacTenant are the
// SEC(".maps") names of the three load-bearing maps in
// bpf/telemetry.c. Same C↔Go contract as the program names above:
// loaders look up [*ebpf.Map] handles by these strings on a loaded
// [*ebpf.Collection], and a typo on either side becomes a missing-
// map panic at boot.
const (
	MapTelemetry      = "telemetry_map"
	MapSubnetZoneTrie = "subnet_zone_trie"
	MapMacTenant      = "mac_tenant_map"
)

// MapSubnetZoneTrieMaxEntries and MapMacTenantMaxEntries mirror the
// `max_entries` values compiled into bpf/telemetry.c. They are
// exposed for two reasons:
//
//  1. Load-time assertions can check the kernel spec matches what
//     userspace expects, catching a stale `.o` build before the
//     agent silently writes into an undersized map.
//  2. Health metrics (cubecos_bpf_map_fill_ratio) need the
//     denominator to compute "% of map occupied".
//
// Sizing rationale lives in bpf/telemetry.c above each map decl.
const (
	MapSubnetZoneTrieMaxEntries = 16384
	MapMacTenantMaxEntries      = 8192
)

// MACKey packs a 6-byte MAC into the low 48 bits of a u64, big-endian.
// Mirrors the C-side `mac_to_u64` in bpf/telemetry.c — both sides
// must agree exactly, or `mac_tenant_map` lookups will silently miss.
// `mac[0]` is the OUI / most-significant byte, `mac[5]` the least.
func MACKey(mac [6]uint8) uint64 {
	return uint64(mac[0])<<40 | uint64(mac[1])<<32 |
		uint64(mac[2])<<24 | uint64(mac[3])<<16 |
		uint64(mac[4])<<8 | uint64(mac[5])
}

// LpmKeyTenantBits is the constant Prefixlen contribution from the
// tenant_id field. The kernel LPM trie matches `tenant_id` exactly
// (all 32 bits) before walking the IP portion, so every entry adds
// 32 to the IP prefix length to produce the full key prefixlen.
const LpmKeyTenantBits uint32 = 32

// LpmKeyForPrefix constructs an [LpmKey] for the kernel
// `subnet_zone_trie` from an interned tenant ID and an IPv4 prefix.
//
// # Prefixlen
//
// Encoded as `LpmKeyTenantBits + prefix.Bits()` — the kernel walks
// 32 bits of `tenant_id` (always exact-matched) plus 0–32 bits of
// the IPv4 address.
//
// # IP byte order
//
// `Ip` is written so its in-memory layout matches the wire (network)
// byte order of the IPv4 address. The kernel LPM trie walks the key
// data byte-by-byte, MSB-first within each byte — so for CIDR
// matching to work the MSB of the IPv4 must lead the byte walk.
// `binary.NativeEndian.Uint32(addr.As4())` produces a uint32 whose
// in-memory bytes equal the wire bytes regardless of host
// endianness; cilium/ebpf serialises the struct via a memcpy of
// host layout, so kernel and userspace agree on the byte pattern.
//
// The C side at bpf/telemetry.c assigns `lk.ip = remote_ip_be`
// (no ntohl): both sides preserve wire order in memory.
//
// Panics if prefix is IPv6 — the kernel trie is IPv4-only and the
// caller is expected to filter upstream (e.g. [internal/neutron.BuildTrie]
// skips IPv6 subnets).
func LpmKeyForPrefix(tenantID uint32, prefix netip.Prefix) LpmKey {
	addr := prefix.Addr()
	if !addr.Is4() {
		panic(fmt.Sprintf("LpmKeyForPrefix: IPv6 prefix unsupported: %s", prefix))
	}
	bytes := addr.As4()
	return LpmKey{
		Prefixlen: LpmKeyTenantBits + uint32(prefix.Bits()),
		TenantId:  tenantID,
		Ip:        binary.NativeEndian.Uint32(bytes[:]),
	}
}

// LoadTelemetry returns the CollectionSpec for the telemetry BPF program,
// ready to be loaded into the kernel.
func LoadTelemetry() (*ebpf.CollectionSpec, error) {
	return loadTelemetry()
}
