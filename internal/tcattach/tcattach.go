//go:build linux

// Package tcattach binds BPF programs to a netlink link via the
// kernel's TC clsact qdisc and a direct-action filter at the
// ingress or egress hook.
//
// The production agent and the test infrastructure both need the
// same two netlink calls (clsact qdisc replace, BPF filter replace).
// Centralising them here keeps the agent's attach path and the
// testenv-side attach for veth pairs from drifting.
package tcattach

import (
	"errors"
	"fmt"
	"log/slog"
	"slices"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Replace installs (or replaces) the clsact qdisc on link and binds
// prog as a BPF filter at the named direction with the given filter
// name. The qdisc and filter are both replaced rather than added,
// so a second call with the same direction/name is idempotent.
func Replace(link netlink.Link, prog *ebpf.Program, dir Direction, name string) error {
	if err := ensureClsact(link); err != nil {
		return err
	}
	return replaceFilter(link, prog, dir, name)
}

// AttachTelemetry installs the clsact qdisc on link and binds both
// telemetry programs in one call — ingress under [FilterIngressName],
// egress under [FilterEgressName] — so callers cannot mis-pair a
// direction with the wrong filter name (which would silently break
// zombie cleanup, since the hunter matches filters by these names).
//
// Attach is all-or-nothing: if the egress filter fails after the
// ingress filter is installed, the ingress filter is rolled back
// before returning, so a partial attach never leaves the link
// carrying one telemetry filter while callers (e.g. the netlink
// subscriber's Registry) record it as unattached. The rollback is
// best-effort: a rollback failure is logged at warn, and the zombie
// hunter reaps the stray filter on the next agent start.
func AttachTelemetry(link netlink.Link, ingress, egress *ebpf.Program) error {
	if err := Replace(link, ingress, Ingress, FilterIngressName); err != nil {
		return err
	}
	if err := Replace(link, egress, Egress, FilterEgressName); err != nil {
		if rerr := removeFilter(link, Ingress); rerr != nil {
			slog.Warn("ingress rollback failed after egress attach error",
				"component", component,
				"iface", link.Attrs().Name,
				"err", rerr)
		}
		return err
	}
	return nil
}

// IsTelemetryFilterName reports whether name is one the agent installs
// on a clsact hook (see [Hooks]). The zombie hunter uses it to
// recognise orphaned telemetry filters left by a previous crash.
func IsTelemetryFilterName(name string) bool {
	for _, h := range Hooks {
		if name == h.Name {
			return true
		}
	}
	return false
}

// TelemetryFilters returns the BPF filters on link's clsact hooks that
// carry one of the agent's telemetry names, wherever they sit on the
// hook. A hook whose filters cannot be listed contributes nothing —
// most links have no clsact qdisc, and FilterList errors for them. A
// dump that stays interrupted contributes what it returned.
func TelemetryFilters(link netlink.Link) []*netlink.BpfFilter {
	var out []*netlink.BpfFilter
	for _, h := range Hooks {
		fs, _ := hookFilters(link, h.Parent)
		out = append(out, fs...)
	}
	return out
}

// HasTelemetry reports whether link carries both telemetry filters in
// the exact slot [AttachTelemetry] installs them: the hook's own name
// at [FilterHandle] and [FilterPriority]. A same-named filter in any
// other slot does not count, so a link holding only that is reported
// unattached and a re-attach installs the real pair.
//
// A non-nil error means the answer is unknown: the kernel kept
// interrupting the filter dump (concurrent tc changes), so a missing
// filter may only be missing from the partial result.
func HasTelemetry(link netlink.Link) (bool, error) {
	for _, h := range Hooks {
		fs, err := hookFilters(link, h.Parent)
		if err != nil {
			return false, err
		}
		if !slices.ContainsFunc(fs, func(f *netlink.BpfFilter) bool {
			return f.Name == h.Name &&
				f.Handle == FilterHandle &&
				f.Priority == FilterPriority
		}) {
			return false, nil
		}
	}
	return true, nil
}

// hookFilters lists the BPF filters under parent on link whose name is
// a telemetry filter name. A dump the kernel interrupted is retried
// once; if it is still interrupted, the partial result comes back with
// netlink.ErrDumpInterrupted. Any other listing error yields no filters
// and no error (see [TelemetryFilters]).
func hookFilters(link netlink.Link, parent uint32) ([]*netlink.BpfFilter, error) {
	filters, err := netlink.FilterList(link, parent)
	if errors.Is(err, netlink.ErrDumpInterrupted) {
		filters, err = netlink.FilterList(link, parent)
	}
	if err != nil && !errors.Is(err, netlink.ErrDumpInterrupted) {
		return nil, nil
	}
	var out []*netlink.BpfFilter
	for _, f := range filters {
		if bf, ok := telemetryFilter(f); ok {
			out = append(out, bf)
		}
	}
	return out, err
}

// telemetryFilter reports whether f is a BPF filter carrying one of
// the agent's telemetry names. Any other filter (u32, generic, a BPF
// filter of another program) is not ours.
func telemetryFilter(f netlink.Filter) (*netlink.BpfFilter, bool) {
	bf, ok := f.(*netlink.BpfFilter)
	if !ok || !IsTelemetryFilterName(bf.Name) {
		return nil, false
	}
	return bf, true
}

// LinkAttacher attaches the telemetry programs to a link and reports
// whether a link carries them. It adapts this package to the netlink
// subscriber's consumer-defined seam so the L3 subscriber can drive
// attach without importing this (L1) package or holding *ebpf.Program
// — the agent composition root wires a LinkAttacher in as that
// interface.
type LinkAttacher struct {
	ingress, egress *ebpf.Program
}

// NewLinkAttacher returns a LinkAttacher bound to the ingress and
// egress telemetry programs.
func NewLinkAttacher(ingress, egress *ebpf.Program) *LinkAttacher {
	return &LinkAttacher{ingress: ingress, egress: egress}
}

// Attach attaches both telemetry programs to link via
// [AttachTelemetry] (all-or-nothing).
func (a *LinkAttacher) Attach(link netlink.Link) error {
	return AttachTelemetry(link, a.ingress, a.egress)
}

// Attached reports whether link carries both telemetry filters
// ([HasTelemetry]); a non-nil error means the answer is unknown.
func (a *LinkAttacher) Attached(link netlink.Link) (bool, error) {
	return HasTelemetry(link)
}

// clsactHandle is the kernel-reserved TC handle for the clsact
// qdisc. The 0xffff:0 pair is defined as TC_H_CLSACT in the kernel
// header include/uapi/linux/pkt_sched.h; the kernel matches on it
// to recognise *the* clsact slot on a link as opposed to an
// ordinary user-created qdisc. Any other handle here would leave
// the qdisc unable to host ingress/egress filters.
var clsactHandle = netlink.MakeHandle(0xffff, 0)

// ensureClsact installs the clsact qdisc on link at the reserved
// clsact slot. Clsact is the modern, lockless TC qdisc used for
// BPF programs at the ingress and egress hooks; filters attached
// to it land at HANDLE_MIN_INGRESS / HANDLE_MIN_EGRESS.
func ensureClsact(link netlink.Link) error {
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    clsactHandle,
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscReplace(qdisc); err != nil {
		return fmt.Errorf("tcattach: clsact qdisc on %s: %w", link.Attrs().Name, err)
	}
	return nil
}

// parentTCHandle maps a Direction to the clsact parent handle the
// kernel files ingress/egress filters under. Shared by replaceFilter
// and removeFilter so the two never disagree on where a filter lives.
func parentTCHandle(dir Direction) (uint32, error) {
	switch dir {
	case Ingress:
		return netlink.HANDLE_MIN_INGRESS, nil
	case Egress:
		return netlink.HANDLE_MIN_EGRESS, nil
	default:
		return 0, fmt.Errorf("tcattach: bad direction %d", dir)
	}
}

// replaceFilter binds prog as a direct-action BPF filter on link at
// the given hook position. Direct-action lets the BPF program
// return TC_ACT_OK / TC_ACT_SHOT directly without a separate
// action chain.
func replaceFilter(link netlink.Link, prog *ebpf.Program, dir Direction, name string) error {
	parent, err := parentTCHandle(dir)
	if err != nil {
		return err
	}
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    parent,
			Handle:    FilterHandle,
			Priority:  FilterPriority,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           prog.FD(),
		Name:         name,
		DirectAction: true,
	}
	if err := netlink.FilterReplace(filter); err != nil {
		return fmt.Errorf("tcattach: attach %s on %s: %w", name, link.Attrs().Name, err)
	}
	return nil
}

// removeFilter deletes the telemetry filter at the given hook on link,
// used to roll back a partial [AttachTelemetry]. It identifies the
// filter by the fixed [FilterHandle], [FilterPriority] and hook
// parent, matching what replaceFilter installed.
func removeFilter(link netlink.Link, dir Direction) error {
	parent, err := parentTCHandle(dir)
	if err != nil {
		return err
	}
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    parent,
			Handle:    FilterHandle,
			Priority:  FilterPriority,
			Protocol:  unix.ETH_P_ALL,
		},
	}
	if err := netlink.FilterDel(filter); err != nil {
		return fmt.Errorf("tcattach: remove filter on %s: %w", link.Attrs().Name, err)
	}
	return nil
}
