//go:build linux

// schema.go gathers package tcattach's exported vocabulary: the clsact
// hook Direction enum, the fixed filter handle, the telemetry filter
// names, and the Hooks table that single-sources the (name, parent) pairs
// the agent attaches. The whole package is //go:build linux, so this file
// carries the tag too. The attach logic (Replace, AttachTelemetry,
// LinkAttacher, IsTelemetryFilterName) lives in tcattach.go.

package tcattach

import "github.com/vishvananda/netlink"

// Direction selects which clsact hook a filter attaches to.
type Direction int

// Ingress and Egress are the clsact hook positions a BPF filter can
// occupy on a link.
const (
	Ingress Direction = iota
	Egress
)

// FilterHandle is the TC filter handle the agent and testenv use
// for their direct-action filters. Kept fixed so a re-attach
// (FilterReplace) always lands on the same slot rather than piling
// up parallel filters.
const FilterHandle = 1

// FilterIngressName and FilterEgressName are the labels the agent
// installs on its clsact ingress and egress filters. Constants are
// exported because both the zombie hunter and the netlink-driven
// dynamic attacher need the same vocabulary to recognise filters
// the agent owns.
//
// Changing either name silently breaks zombie cleanup and dynamic
// attach. The [Hooks] table below pairs them with their parent
// handles as the single source of truth the consumers iterate.
const (
	FilterIngressName = "telemetry_in"
	FilterEgressName  = "telemetry_out"
)

// Hook describes one clsact filter the agent attaches: the filter
// Name and the kernel Parent handle it lives under.
type Hook struct {
	Name   string
	Parent uint32
}

// Hooks is the fixed set of clsact filters [AttachTelemetry] installs,
// in attach order (ingress, egress). It is the single source of truth
// for the (name, parent) pairs the zombie hunter and the dynamic
// attacher match on, so a hook-location or name change is a one-place
// edit here rather than a coordinated change across packages.
var Hooks = []Hook{
	{Name: FilterIngressName, Parent: netlink.HANDLE_MIN_INGRESS},
	{Name: FilterEgressName, Parent: netlink.HANDLE_MIN_EGRESS},
}
