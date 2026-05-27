//go:build linux

package agent

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/tcattach"
)

// AttachClsact installs a TC clsact qdisc on the named interface and
// attaches the ingress and egress telemetry programs in direct-action
// mode. Idempotent: replaces any existing clsact qdisc and the prior
// telemetry filters. The filter names come from [tcattach] so the
// zombie hunter recognises them as the agent's own.
//
// Today this is a single-interface attach with no netlink-driven
// auto-attach; that arrives in Sprint 5c.
func AttachClsact(ifaceName string, ingress, egress *ebpf.Program) error {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("agent: lookup interface %s: %w", ifaceName, err)
	}
	if err := tcattach.Replace(link, ingress, tcattach.Ingress, tcattach.FilterIngressName); err != nil {
		return err
	}
	if err := tcattach.Replace(link, egress, tcattach.Egress, tcattach.FilterEgressName); err != nil {
		return err
	}
	return nil
}
