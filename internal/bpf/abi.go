// Package bpf exposes the kernel↔userspace ABI for the telemetry agent.
//
// Source of truth: bpf/telemetry.c. The enums and structs there are
// compiled with BTF; bpf2go reads the BTF and emits the Go mirrors you
// see in telemetry_bpfel.go (TelemetryFlowKey, TelemetryZoneCode,
// TelemetryTcDirection, TelemetryFlowMetrics, ...).
//
// This file re-exports those under shorter, project-local names. Use
// bpf.FlowKey, bpf.ZoneSameTenant, bpf.DirectionIngress, etc. in
// production code and tests — never redeclare them.
//
// Changing a value here means changing it in bpf/telemetry.c too, since
// the constants here are aliases to the generated ones. The build will
// fail loudly if they drift.
package bpf

// Struct aliases — re-exports of the bpf2go-generated map key/value types.
type (
	FlowKey     = TelemetryFlowKey
	FlowMetrics = TelemetryFlowMetrics
	LpmKey      = TelemetryLpmKey
	ZoneCode    = TelemetryZoneCode
	Direction   = TelemetryTcDirection
)

// Zone codes stored in flow_key.dst_zone. Values are stable: persisted to
// the WAL across restarts.
const (
	ZoneExternal    = TelemetryZoneCodeZONE_EXTERNAL
	ZoneSameTenant  = TelemetryZoneCodeZONE_SAME_TENANT
	ZoneOtherTenant = TelemetryZoneCodeZONE_OTHER_TENANT
	ZoneInfra       = TelemetryZoneCodeZONE_INFRA
	ZoneMiss        = TelemetryZoneCodeZONE_MISS
)

// TC hook direction stored in flow_key.direction.
const (
	DirectionIngress = TelemetryTcDirectionTC_DIR_INGRESS
	DirectionEgress  = TelemetryTcDirectionTC_DIR_EGRESS
)
