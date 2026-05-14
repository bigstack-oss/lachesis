// Package bpf exposes the kernel↔userspace ABI for the telemetry agent.
//
// The map specs, program entry points, and low-level loader live in the
// bpf2go-generated files (telemetry_bpfel.go). This file adds the
// hand-written constants and struct mirrors that production code and
// tests use, so the values are declared in exactly one place.
//
// All declarations here must stay in lockstep with bpf/telemetry.c.
// The struct layouts and constant values cross the kernel↔userspace
// boundary; silent skew between sides produces incorrect metrics.
package bpf

// FlowKey is the Go-side mirror of the BPF flow_key map key. It is the
// 16-byte composite key written by the classifier into telemetry_map.
type FlowKey = TelemetryFlowKey

// FlowMetrics is the Go-side mirror of the BPF flow_metrics map value.
// One instance per CPU is stored in telemetry_map (PERCPU_HASH).
type FlowMetrics = TelemetryFlowMetrics

// LpmKey is the Go-side mirror of the BPF lpm_key. It keys subnet_zone_trie
// with (prefixlen, tenant_id, ip) so longest-prefix matching can resolve
// a remote IP to a zone code relative to the source VM's tenant.
type LpmKey = TelemetryLpmKey

// ZoneCode is the enum stored in [FlowKey.DstZone]. See [ZoneExternal] and
// the other Zone constants for the set of valid values.
type ZoneCode = TelemetryZoneCode

// Direction is the enum stored in [FlowKey.Direction]. See [DirectionIngress]
// and [DirectionEgress] for the set of valid values.
type Direction = TelemetryTcDirection

// ZoneExternal through ZoneMiss are the zone codes stored in [FlowKey.DstZone].
// The values are stable across releases: they are persisted to the WAL and
// read back on restart.
const (
	ZoneExternal    = TelemetryZoneCodeZONE_EXTERNAL
	ZoneSameTenant  = TelemetryZoneCodeZONE_SAME_TENANT
	ZoneOtherTenant = TelemetryZoneCodeZONE_OTHER_TENANT
	ZoneInfra       = TelemetryZoneCodeZONE_INFRA
	ZoneMiss        = TelemetryZoneCodeZONE_MISS
)

// DirectionIngress and DirectionEgress are the TC hook direction values
// stored in [FlowKey.Direction].
const (
	DirectionIngress = TelemetryTcDirectionTC_DIR_INGRESS
	DirectionEgress  = TelemetryTcDirectionTC_DIR_EGRESS
)
