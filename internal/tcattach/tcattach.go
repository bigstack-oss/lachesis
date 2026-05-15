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

// ensureClsact installs the clsact qdisc on link (parent
// HANDLE_CLSACT, handle 0xffff:0). Clsact is the modern, lockless
// TC qdisc used for BPF programs at the ingress and egress hooks.
func ensureClsact(link netlink.Link) error {
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscReplace(qdisc); err != nil {
		return fmt.Errorf("tcattach: clsact qdisc on %s: %w", link.Attrs().Name, err)
	}
	return nil
}

// replaceFilter binds prog as a direct-action BPF filter on link at
// the given hook position. Direct-action lets the BPF program
// return TC_ACT_OK / TC_ACT_SHOT directly without a separate
// action chain.
func replaceFilter(link netlink.Link, prog *ebpf.Program, dir Direction, name string) error {
	var parent uint32
	switch dir {
	case Ingress:
		parent = netlink.HANDLE_MIN_INGRESS
	case Egress:
		parent = netlink.HANDLE_MIN_EGRESS
	default:
		return fmt.Errorf("tcattach: bad direction %d", dir)
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
