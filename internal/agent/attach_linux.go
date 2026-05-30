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
// This backs the deprecated static single-interface attach
// ([config.BPFConfig.AttachInterface]); dynamic, netlink-driven
// attach of new interfaces is handled by the netlink subscriber.
func AttachClsact(ifaceName string, ingress, egress *ebpf.Program) error {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("agent: lookup interface %s: %w", ifaceName, err)
	}
	return tcattach.AttachTelemetry(link, ingress, egress)
}
