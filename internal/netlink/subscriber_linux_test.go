//go:build linux

package netlink

import (
	"errors"
	"math"
	"net"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// failingAttacher fails every attach with err.
type failingAttacher struct{ err error }

func (a failingAttacher) AttachLink(string) error { return a.err }

// TestOnNewLink_AttachFailureCounting pins which attach failures move
// lachesis_tc_attach_failures_total: a NEWLINK whose interface is gone
// by the time the attach runs (the source side of a live migration)
// is a skip, while a failure on a still-present interface counts. The
// presence check hits the real kernel: lo exists in every netns, and
// no interface holds ifindex MaxInt32.
func TestOnNewLink_AttachFailureCounting(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatalf("lookup lo: %v", err)
	}
	cases := []struct {
		name    string
		index   int
		wantTap string
	}{
		{name: "vanished interface is not a failure", index: math.MaxInt32, wantTap: "0"},
		{name: "present interface failure counts", index: lo.Index, wantTap: "1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			registry := NewRegistry()
			metrics := NewMetrics(registry.Len)
			s := &linuxSubscriber{
				opts: Options{
					Attacher: failingAttacher{err: errors.New("attach failed")},
					Prefixes: []string{"tap"},
					Registry: registry,
					Metrics:  metrics,
				},
			}

			s.handle(netlink.LinkUpdate{
				Header: unix.NlMsghdr{Type: unix.RTM_NEWLINK},
				Link:   &netlink.Tuntap{LinkAttrs: netlink.LinkAttrs{Name: "tap29a0c4f7-85", Index: tc.index}},
			})

			if registry.IsAttached("tap29a0c4f7-85") {
				t.Error("failed attach left the interface registered")
			}
			reg := prometheus.NewPedanticRegistry()
			reg.MustRegister(metrics.Collectors()...)
			want := `
# HELP lachesis_tc_attach_failures_total TC clsact attach failures from the netlink subscriber, labelled by iface_kind ("tap" for prefix-matched, "other" for explicit-list entries).
# TYPE lachesis_tc_attach_failures_total counter
lachesis_tc_attach_failures_total{iface_kind="other"} 0
lachesis_tc_attach_failures_total{iface_kind="tap"} ` + tc.wantTap + `
`
			if err := testutil.GatherAndCompare(reg, strings.NewReader(want),
				"lachesis_tc_attach_failures_total"); err != nil {
				t.Errorf("metric mismatch:\n%v", err)
			}
		})
	}
}
