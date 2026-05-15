//go:build linux

package agent

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/tcattach"
)

// telemetryFilterIngress and telemetryFilterEgress are the TC filter
// names the agent uses on the host interface. Fixed so reattach
// replaces the same slot.
const (
	telemetryFilterIngress = "telemetry_in"
	telemetryFilterEgress  = "telemetry_out"
)

// AttachClsact installs a TC clsact qdisc on the named interface and
// attaches the ingress and egress telemetry programs in direct-action
// mode. Idempotent: replaces any existing clsact qdisc and the prior
// telemetry filters.
//
// Today this is a single-interface attach with no zombie cleanup
// and no netlink-driven auto-attach; both are planned.
func AttachClsact(ifaceName string, ingress, egress *ebpf.Program) error {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("agent: lookup interface %s: %w", ifaceName, err)
	}
	if err := tcattach.Replace(link, ingress, tcattach.Ingress, telemetryFilterIngress); err != nil {
		return err
	}
	if err := tcattach.Replace(link, egress, tcattach.Egress, telemetryFilterEgress); err != nil {
		return err
	}
	return nil
}
