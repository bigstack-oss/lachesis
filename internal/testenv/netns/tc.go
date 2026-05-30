//go:build linux

package netns

import (
	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/tcattach"
)

// TCDirection mirrors [tcattach.Direction] so existing tests can
// keep their netns-package imports unchanged.
type TCDirection = tcattach.Direction

// Clsact hook directions accepted by AttachBPF. Aliased to the
// constants in [tcattach] so the test-side and production-side
// enums never drift.
const (
	TCIngress = tcattach.Ingress
	TCEgress  = tcattach.Egress
)

// AttachBPF attaches prog to link via TC clsact at the given
// direction with the given filter name. Idempotent: installs the
// clsact qdisc if missing and replaces any existing filter with the
// same name.
//
// Thin wrapper over [tcattach.Replace]; intended for tests only.
// Production code attaches both directions together with rollback via
// [tcattach.AttachTelemetry] / [tcattach.LinkAttacher].
func AttachBPF(link netlink.Link, prog *ebpf.Program, dir TCDirection, name string) error {
	return tcattach.Replace(link, prog, dir, name)
}
