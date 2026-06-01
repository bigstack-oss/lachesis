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
	"fmt"

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
// best-effort; if it too fails, the zombie hunter reaps the stray
// filter on the next agent start.
func AttachTelemetry(link netlink.Link, ingress, egress *ebpf.Program) error {
	if err := Replace(link, ingress, Ingress, FilterIngressName); err != nil {
		return err
	}
	if err := Replace(link, egress, Egress, FilterEgressName); err != nil {
		_ = removeFilter(link, Ingress)
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

// LinkAttacher attaches the telemetry programs to an interface looked
// up by name. It adapts the by-name attach to a single-method seam so
// the L3 netlink subscriber can drive attach through an interface
// without importing this (L1) package or holding *ebpf.Program — the
// agent composition root wires a LinkAttacher in as that interface.
type LinkAttacher struct {
	ingress, egress *ebpf.Program
}

// NewLinkAttacher returns a LinkAttacher bound to the ingress and
// egress telemetry programs.
func NewLinkAttacher(ingress, egress *ebpf.Program) *LinkAttacher {
	return &LinkAttacher{ingress: ingress, egress: egress}
}

// AttachLink looks up the named interface and attaches both telemetry
// programs via [AttachTelemetry] (all-or-nothing). Returns an error if
// the interface is missing or either attach fails.
func (a *LinkAttacher) AttachLink(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("tcattach: lookup interface %s: %w", name, err)
	}
	return AttachTelemetry(link, a.ingress, a.egress)
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
// filter by the fixed [FilterHandle] and hook parent, matching what
// replaceFilter installed.
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
			Protocol:  unix.ETH_P_ALL,
		},
	}
	if err := netlink.FilterDel(filter); err != nil {
		return fmt.Errorf("tcattach: remove filter on %s: %w", link.Attrs().Name, err)
	}
	return nil
}
