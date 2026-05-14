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

import "github.com/cilium/ebpf"

// FlowKey is the Go-side mirror of the BPF flow_key map key. It is the
// 16-byte composite key written by the classifier into telemetry_map.
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

// ZoneExternal through ZoneMiss are the zone codes stored in [FlowKey.DstZone].
// The values are stable across releases: they are persisted to the WAL and
// read back on restart.
const (
	ZoneExternal    = telemetryZoneCodeZONE_EXTERNAL
	ZoneSameTenant  = telemetryZoneCodeZONE_SAME_TENANT
	ZoneOtherTenant = telemetryZoneCodeZONE_OTHER_TENANT
	ZoneInfra       = telemetryZoneCodeZONE_INFRA
	ZoneMiss        = telemetryZoneCodeZONE_MISS
)

// DirectionIngress and DirectionEgress are the TC hook direction values
// stored in [FlowKey.Direction].
const (
	DirectionIngress = telemetryTcDirectionTC_DIR_INGRESS
	DirectionEgress  = telemetryTcDirectionTC_DIR_EGRESS
)

// LoadTelemetry returns the CollectionSpec for the telemetry BPF program,
// ready to be loaded into the kernel.
func LoadTelemetry() (*ebpf.CollectionSpec, error) {
	return loadTelemetry()
}
