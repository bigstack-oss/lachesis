//go:build linux

// schema.go gathers package tcattach's constants: the clsact hook
// Direction enum, the fixed filter handle and priority, the telemetry
// filter names, the Hooks table that single-sources the (name, parent)
// pairs the agent attaches, and the slog component label. The whole
// package is //go:build linux, so this file carries the tag too. The
// attach logic (Replace, AttachTelemetry, LinkAttacher,
// IsTelemetryFilterName) lives in tcattach.go.

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

// FilterPriority is the TC filter priority (preference) the agent's
// filters install at. It must be a fixed non-zero value: at priority
// 0 the kernel auto-allocates a fresh priority on every call, so a
// FilterReplace never matches the previous filter — each re-attach
// stacks another copy and every packet is counted once per copy.
// Pinning the full (parent, priority, handle) triple makes
// FilterReplace genuinely idempotent and lets FilterDel address the
// exact filter the agent installed.
const FilterPriority = 1

// component is the slog attribute identifying this package's log
// records, one vocabulary with the agent's metric registration labels.
const component = "tcattach"

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
