//go:build integration

package netlink_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"
	vnl "github.com/vishvananda/netlink"

	cnetlink "github.com/bigstack-oss/cube-cos-network-telemetry/internal/netlink"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/tcattach"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/testenv/bpfunit"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/testenv/bpfunit/fixtures"
	tns "github.com/bigstack-oss/cube-cos-network-telemetry/internal/testenv/netns"
)

// TestSubscriber_AttachesNewTap verifies the production guarantee:
// when a tap-named interface appears, the subscriber attaches
// telemetry filters to it within a small budget.
//
// The subscriber runs inside a fresh netns so its host-wide
// LinkSubscribe scan is scoped to the test's veth pair (plus lo).
func TestSubscriber_AttachesNewTap(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("rlimit: %v", err)
	}
	spec, err := fixtures.LoadNoop()
	if err != nil {
		t.Fatalf("load noop spec: %v", err)
	}
	drv, err := bpfunit.New(spec)
	if err != nil {
		t.Fatalf("driver: %v", err)
	}
	defer drv.Close()

	prog := drv.Program(fixtures.ProgNoopIn)
	if prog == nil {
		t.Fatal("tc_noop_in missing")
	}

	ns, err := tns.New()
	if err != nil {
		t.Fatalf("new ns: %v", err)
	}
	defer ns.Close()

	registry := cnetlink.NewRegistry()
	sub, err := cnetlink.New(cnetlink.Options{
		Attacher: tcattach.NewLinkAttacher(prog, prog),
		Prefixes: []string{"tap-"},
		Registry: registry,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	subErr := make(chan error, 1)
	go func() {
		// Subscriber must run inside the netns so its LinkSubscribe
		// sees the test's veth events, not the host's.
		subErr <- ns.Do(func() error { return sub.Run(ctx) })
	}()

	// Give the subscriber a moment to set up its socket. Without
	// this small wait the AddVeth NEWLINK can race the subscribe
	// call itself (LinkSubscribeWithOptions(ListExisting:true)
	// handles the post-subscribe case, but the very first ms is
	// still racy).
	time.Sleep(50 * time.Millisecond)

	innerMAC, _ := net.ParseMAC("aa:bb:cc:dd:f0:01")
	outerMAC, _ := net.ParseMAC("aa:bb:cc:dd:f0:02")
	innerIP := &net.IPNet{IP: net.IPv4(10, 80, 0, 1), Mask: net.CIDRMask(30, 32)}
	outerIP := &net.IPNet{IP: net.IPv4(10, 80, 0, 2), Mask: net.CIDRMask(30, 32)}

	host, err := ns.AddVeth(tns.VethSpec{
		InnerName: "tap-nlsub", OuterName: "tap-out",
		InnerMAC: innerMAC, OuterMAC: outerMAC,
		InnerIP: innerIP, OuterIP: outerIP,
	})
	if err != nil {
		t.Fatalf("add veth: %v", err)
	}
	defer vnl.LinkDel(host)

	if !waitFor(2*time.Second, func() bool {
		return registry.IsAttached("tap-nlsub")
	}) {
		t.Fatalf("subscriber did not attach tap-nlsub within budget; registry=%v", registry.Snapshot())
	}

	if got := countTelemetryFiltersInNS(t, ns, "tap-nlsub"); got != 2 {
		t.Errorf("post-attach filter count = %d, want 2 (ingress + egress)", got)
	}

	cancel()
	select {
	case err := <-subErr:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("Run returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("subscriber did not exit within 2s of cancel")
	}
}

// TestSubscriber_ForgetsOnDelLink verifies that the registry stays
// in sync when a tap goes away: a DELLINK event must remove the
// entry. The kernel removes the qdisc and filters automatically,
// so we only assert on the registry side.
func TestSubscriber_ForgetsOnDelLink(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("rlimit: %v", err)
	}
	spec, err := fixtures.LoadNoop()
	if err != nil {
		t.Fatalf("load noop spec: %v", err)
	}
	drv, err := bpfunit.New(spec)
	if err != nil {
		t.Fatalf("driver: %v", err)
	}
	defer drv.Close()
	prog := drv.Program(fixtures.ProgNoopIn)

	ns, err := tns.New()
	if err != nil {
		t.Fatalf("new ns: %v", err)
	}
	defer ns.Close()

	registry := cnetlink.NewRegistry()
	sub, err := cnetlink.New(cnetlink.Options{
		Attacher: tcattach.NewLinkAttacher(prog, prog),
		Prefixes: []string{"tap-"},
		Registry: registry,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	subErr := make(chan error, 1)
	go func() {
		subErr <- ns.Do(func() error { return sub.Run(ctx) })
	}()
	time.Sleep(50 * time.Millisecond)

	innerMAC, _ := net.ParseMAC("aa:bb:cc:dd:f1:01")
	outerMAC, _ := net.ParseMAC("aa:bb:cc:dd:f1:02")
	innerIP := &net.IPNet{IP: net.IPv4(10, 81, 0, 1), Mask: net.CIDRMask(30, 32)}
	outerIP := &net.IPNet{IP: net.IPv4(10, 81, 0, 2), Mask: net.CIDRMask(30, 32)}

	host, err := ns.AddVeth(tns.VethSpec{
		InnerName: "tap-gone", OuterName: "tap-gone-out",
		InnerMAC: innerMAC, OuterMAC: outerMAC,
		InnerIP: innerIP, OuterIP: outerIP,
	})
	if err != nil {
		t.Fatalf("add veth: %v", err)
	}

	if !waitFor(2*time.Second, func() bool {
		return registry.IsAttached("tap-gone")
	}) {
		t.Fatalf("attach did not land in time")
	}

	if err := vnl.LinkDel(host); err != nil {
		t.Fatalf("link del: %v", err)
	}

	if !waitFor(2*time.Second, func() bool {
		return !registry.IsAttached("tap-gone")
	}) {
		t.Errorf("registry still has tap-gone after DELLINK")
	}

	cancel()
	<-subErr
}

// TestSubscriber_IgnoresNonAllowlist verifies the matcher: an
// interface whose name is outside the prefix + explicit allowlist
// must not be attached.
func TestSubscriber_IgnoresNonAllowlist(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("rlimit: %v", err)
	}
	spec, err := fixtures.LoadNoop()
	if err != nil {
		t.Fatalf("load noop spec: %v", err)
	}
	drv, err := bpfunit.New(spec)
	if err != nil {
		t.Fatalf("driver: %v", err)
	}
	defer drv.Close()
	prog := drv.Program(fixtures.ProgNoopIn)

	ns, err := tns.New()
	if err != nil {
		t.Fatalf("new ns: %v", err)
	}
	defer ns.Close()

	registry := cnetlink.NewRegistry()
	sub, err := cnetlink.New(cnetlink.Options{
		Attacher: tcattach.NewLinkAttacher(prog, prog),
		Prefixes: []string{"tap-"},
		Registry: registry,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	subErr := make(chan error, 1)
	go func() {
		subErr <- ns.Do(func() error { return sub.Run(ctx) })
	}()
	time.Sleep(50 * time.Millisecond)

	innerMAC, _ := net.ParseMAC("aa:bb:cc:dd:f2:01")
	outerMAC, _ := net.ParseMAC("aa:bb:cc:dd:f2:02")
	innerIP := &net.IPNet{IP: net.IPv4(10, 82, 0, 1), Mask: net.CIDRMask(30, 32)}
	outerIP := &net.IPNet{IP: net.IPv4(10, 82, 0, 2), Mask: net.CIDRMask(30, 32)}

	host, err := ns.AddVeth(tns.VethSpec{
		InnerName: "eth-not-tap", OuterName: "eth-not-tap-out",
		InnerMAC: innerMAC, OuterMAC: outerMAC,
		InnerIP: innerIP, OuterIP: outerIP,
	})
	if err != nil {
		t.Fatalf("add veth: %v", err)
	}
	defer vnl.LinkDel(host)

	// Give the subscriber a generous window to attach (it
	// shouldn't), then assert the registry stays empty of this
	// name. 250 ms is empirically more than enough for a NEWLINK
	// round-trip when the matcher would have attached.
	time.Sleep(250 * time.Millisecond)
	if registry.IsAttached("eth-not-tap") {
		t.Errorf("registry attached eth-not-tap despite prefix-mismatch; snapshot=%v", registry.Snapshot())
	}

	cancel()
	<-subErr
}

// waitFor polls cond every 10 ms up to budget. Returns true if cond
// went true within the budget.
func waitFor(budget time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}

// countTelemetryFiltersInNS counts BPF filters with the agent's
// telemetry names on a link inside ns.
func countTelemetryFiltersInNS(t *testing.T, ns *tns.NS, linkName string) int {
	t.Helper()
	var n int
	err := ns.Do(func() error {
		link, err := vnl.LinkByName(linkName)
		if err != nil {
			return err
		}
		for _, parent := range []uint32{vnl.HANDLE_MIN_INGRESS, vnl.HANDLE_MIN_EGRESS} {
			filters, ferr := vnl.FilterList(link, parent)
			if ferr != nil {
				continue
			}
			for _, f := range filters {
				bf, ok := f.(*vnl.BpfFilter)
				if !ok {
					continue
				}
				if bf.Name == tcattach.FilterIngressName || bf.Name == tcattach.FilterEgressName {
					n++
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}
