// Package bpf exposes the kernel↔userspace ABI for the telemetry agent.
//
// The map specs, program entry points, and low-level loader are generated
// by bpf2go from bpf/telemetry.c into telemetry_bpfel.go. Those generated
// names are intentionally unexported (the bpf2go prefix is lowercase). The
// hand-written files abi.go and schema.go are the only public surface of
// the package: callers use FlowKey, LoadTelemetry, ZoneSameTenant, etc.,
// never the generated identifiers. schema.go holds the pure ABI vocabulary
// (types, enum/name constants, map sizes); abi.go holds the helpers and
// loader (MACKey, LpmKeyForPrefix, LoadTelemetry, ValidateMapSizes).
//
// All declarations here must stay in lockstep with bpf/telemetry.c. The
// struct layouts and constant values cross the kernel↔userspace boundary;
// silent skew between sides produces incorrect metrics.
//
// Layering: this package is L1, but its pure ABI surface — the FlowKey /
// FlowMetrics / LpmKey types, the Zone* and Direction constants, and MACKey
// — is a dependency-free kernel↔userspace data contract that L2 (metadata,
// neutron), L3 (state) and L4 (metrics, wal) all import by design. Those
// imports are NOT L*→L1 layer violations: the types are a shared schema,
// not the data plane. Only the loader half (LoadTelemetry, ValidateMapSizes,
// the Map* name constants, Metrics) touches L1 machinery, and it is used
// solely by the agent composition root. So: don't "fix" the cross-layer
// imports by hiding the ABI types, and never hand-copy the generated struct
// layouts — silent skew corrupts metrics, per the lockstep rule above.
package bpf

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"
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

// ValidateMapSizes ensures the compiled BPF spec's `max_entries`
// values for `telemetry_map`, `mac_tenant_map`, and `subnet_zone_trie`
// match the Go-side intent in [MapTelemetryMaxEntries],
// [MapMacTenantMaxEntries], and [MapSubnetZoneTrieMaxEntries].
//
// Mismatch indicates a stale BPF object — typically a developer
// who bumped the size in bpf/telemetry.c without re-running
// `task generate`, or the reverse. Either direction is a
// drift symptom and the agent refuses to start; the operator
// regenerates and retries.
//
// Returns nil when sizes agree, or a multi-line error naming every
// map whose size differs and the expected value.
func ValidateMapSizes(spec *ebpf.CollectionSpec) error {
	if spec == nil {
		return fmt.Errorf("bpf: ValidateMapSizes called with nil spec")
	}
	type check struct {
		name string
		want uint32
	}
	var problems []string
	for _, c := range []check{
		{MapTelemetry, MapTelemetryMaxEntries},
		{MapMacTenant, MapMacTenantMaxEntries},
		{MapSubnetZoneTrie, MapSubnetZoneTrieMaxEntries},
	} {
		m, ok := spec.Maps[c.name]
		if !ok {
			problems = append(problems, fmt.Sprintf("%s: not present in spec", c.name))
			continue
		}
		if m.MaxEntries != c.want {
			problems = append(problems,
				fmt.Sprintf("%s: spec.MaxEntries=%d, want %d (Go-side authority)",
					c.name, m.MaxEntries, c.want))
		}
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("bpf: map-size drift (run `task generate`): %v", problems)
}
