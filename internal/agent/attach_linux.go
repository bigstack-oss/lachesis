//go:build linux

package agent

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// AttachClsact installs a TC clsact qdisc on the named interface and
// attaches the ingress and egress telemetry programs in direct-action
// mode. Idempotent: replaces an existing clsact qdisc and any prior
// telemetry_in / telemetry_out filters.
//
// Sprint 2 wires a single interface attach with no zombie cleanup and
// no netlink-driven auto-attach. Both land in Sprint 5.
func AttachClsact(ifaceName string, ingress, egress *ebpf.Program) error {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("agent: lookup interface %s: %w", ifaceName, err)
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscReplace(qdisc); err != nil {
		return fmt.Errorf("agent: clsact qdisc on %s: %w", ifaceName, err)
	}
	if err := attachFilter(link, ingress, netlink.HANDLE_MIN_INGRESS, "telemetry_in"); err != nil {
		return err
	}
	if err := attachFilter(link, egress, netlink.HANDLE_MIN_EGRESS, "telemetry_out"); err != nil {
		return err
	}
	return nil
}

func attachFilter(link netlink.Link, prog *ebpf.Program, parent uint32, name string) error {
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    parent,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           prog.FD(),
		Name:         name,
		DirectAction: true,
	}
	if err := netlink.FilterReplace(filter); err != nil {
		return fmt.Errorf("agent: attach %s on %s: %w", name, link.Attrs().Name, err)
	}
	return nil
}
