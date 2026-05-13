//go:build linux

package netns

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// TCDirection selects which clsact hook to attach to.
type TCDirection int

const (
	TCIngress TCDirection = iota
	TCEgress
)

// AttachBPF attaches prog to link via TC clsact. Idempotent: installs the
// clsact qdisc if missing and replaces any existing filter with name.
//
// Test-only helper — Sprint 5 builds the production attach path with zombie
// hunter, error recovery, and retries.
func AttachBPF(link netlink.Link, prog *ebpf.Program, dir TCDirection, name string) error {
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscReplace(qdisc); err != nil {
		return fmt.Errorf("netns: clsact qdisc on %s: %w", link.Attrs().Name, err)
	}

	var parent uint32
	switch dir {
	case TCIngress:
		parent = netlink.HANDLE_MIN_INGRESS
	case TCEgress:
		parent = netlink.HANDLE_MIN_EGRESS
	default:
		return fmt.Errorf("netns: bad direction %d", dir)
	}

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
		return fmt.Errorf("netns: attach %s on %s: %w", name, link.Attrs().Name, err)
	}
	return nil
}
