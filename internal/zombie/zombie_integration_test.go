//go:build integration

package zombie_test

import (
	"net"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"

	"github.com/bigstack-oss/lachesis/internal/tcattach"
	"github.com/bigstack-oss/lachesis/internal/testenv/bpfunit"
	"github.com/bigstack-oss/lachesis/internal/testenv/bpfunit/fixtures"
	tns "github.com/bigstack-oss/lachesis/internal/testenv/netns"
	"github.com/bigstack-oss/lachesis/internal/zombie"
)

// TestHunt_DeletesOrphanFilters proves the production guarantee:
// after Hunt, any TC filter that uses the agent's telemetry names is
// gone. The test runs entirely inside a fresh netns so Hunt's
// host-wide LinkList() scan doesn't touch the developer's machine.
//
// Topology:
//
//	netns/lo
//	netns/vm-zb  <-- inner veth, BPF orphan filters attached here
//	host/tap-zb  <-- outer veth (in caller's ns); not relevant
func TestHunt_DeletesOrphanFilters(t *testing.T) {
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

	ns, err := tns.New()
	if err != nil {
		t.Fatalf("new ns: %v", err)
	}
	defer ns.Close()

	innerMAC, _ := net.ParseMAC("aa:bb:cc:dd:e3:01")
	outerMAC, _ := net.ParseMAC("aa:bb:cc:dd:e3:02")
	innerIP := &net.IPNet{IP: net.IPv4(10, 78, 0, 1), Mask: net.CIDRMask(30, 32)}
	outerIP := &net.IPNet{IP: net.IPv4(10, 78, 0, 2), Mask: net.CIDRMask(30, 32)}

	host, err := ns.AddVeth(tns.VethSpec{
		InnerName: "vm-zb", OuterName: "tap-zb",
		InnerMAC: innerMAC, OuterMAC: outerMAC,
		InnerIP: innerIP, OuterIP: outerIP,
	})
	if err != nil {
		t.Fatalf("add veth: %v", err)
	}
	defer netlink.LinkDel(host)

	prog := drv.Program(fixtures.ProgNoopIn)
	if prog == nil {
		t.Fatal("tc_noop_in program missing from collection")
	}

	if err := ns.Do(func() error {
		link, err := netlink.LinkByName("vm-zb")
		if err != nil {
			return err
		}
		if err := tns.AttachBPF(link, prog, tns.TCIngress, tcattach.FilterIngressName); err != nil {
			return err
		}
		return tns.AttachBPF(link, prog, tns.TCEgress, tcattach.FilterEgressName)
	}); err != nil {
		t.Fatalf("attach orphans: %v", err)
	}

	if got := countTelemetryFiltersInNS(t, ns, "vm-zb"); got != 2 {
		t.Fatalf("pre-hunt filter count = %d, want 2", got)
	}

	var (
		cleaned int
		huntErr error
	)
	if err := ns.Do(func() error {
		cleaned, huntErr = zombie.Hunt()
		return nil
	}); err != nil {
		t.Fatalf("Do(Hunt): %v", err)
	}
	if huntErr != nil {
		t.Fatalf("Hunt: %v", huntErr)
	}
	if cleaned != 2 {
		t.Errorf("cleaned = %d, want 2", cleaned)
	}
	if got := countTelemetryFiltersInNS(t, ns, "vm-zb"); got != 0 {
		t.Errorf("post-hunt telemetry filter count = %d, want 0", got)
	}
}

// TestHunt_LeavesUnrelatedFiltersAlone proves Hunt is targeted —
// only filters whose name matches the agent's slots are removed.
// A BPF filter installed under a different name must survive.
func TestHunt_LeavesUnrelatedFiltersAlone(t *testing.T) {
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

	ns, err := tns.New()
	if err != nil {
		t.Fatalf("new ns: %v", err)
	}
	defer ns.Close()

	innerMAC, _ := net.ParseMAC("aa:bb:cc:dd:e4:01")
	outerMAC, _ := net.ParseMAC("aa:bb:cc:dd:e4:02")
	innerIP := &net.IPNet{IP: net.IPv4(10, 79, 0, 1), Mask: net.CIDRMask(30, 32)}
	outerIP := &net.IPNet{IP: net.IPv4(10, 79, 0, 2), Mask: net.CIDRMask(30, 32)}

	host, err := ns.AddVeth(tns.VethSpec{
		InnerName: "vm-other", OuterName: "tap-other",
		InnerMAC: innerMAC, OuterMAC: outerMAC,
		InnerIP: innerIP, OuterIP: outerIP,
	})
	if err != nil {
		t.Fatalf("add veth: %v", err)
	}
	defer netlink.LinkDel(host)

	prog := drv.Program(fixtures.ProgNoopIn)
	if prog == nil {
		t.Fatal("tc_noop_in program missing")
	}

	if err := ns.Do(func() error {
		link, err := netlink.LinkByName("vm-other")
		if err != nil {
			return err
		}
		return tns.AttachBPF(link, prog, tns.TCIngress, "not_telemetry")
	}); err != nil {
		t.Fatalf("attach unrelated: %v", err)
	}

	var cleaned int
	if err := ns.Do(func() error {
		c, herr := zombie.Hunt()
		cleaned = c
		return herr
	}); err != nil {
		t.Fatalf("Hunt: %v", err)
	}
	if cleaned != 0 {
		t.Errorf("cleaned = %d, want 0 (unrelated filter must survive)", cleaned)
	}

	if got := countTelemetryFiltersInNS(t, ns, "vm-other"); got != 0 {
		t.Errorf("telemetry filters present = %d, want 0", got)
	}
	if got := countAnyBPFFiltersInNS(t, ns, "vm-other"); got != 1 {
		t.Errorf("post-hunt BPF filters = %d, want 1 (unrelated must remain)", got)
	}
}

// countTelemetryFiltersInNS returns the number of clsact ingress +
// egress BPF filters on link whose name is one of the agent's two.
func countTelemetryFiltersInNS(t *testing.T, ns *tns.NS, linkName string) int {
	t.Helper()
	var n int
	err := ns.Do(func() error {
		link, err := netlink.LinkByName(linkName)
		if err != nil {
			return err
		}
		for _, parent := range []uint32{netlink.HANDLE_MIN_INGRESS, netlink.HANDLE_MIN_EGRESS} {
			filters, ferr := netlink.FilterList(link, parent)
			if ferr != nil {
				continue
			}
			for _, f := range filters {
				bf, ok := f.(*netlink.BpfFilter)
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
		t.Fatalf("count telemetry filters: %v", err)
	}
	return n
}

// countAnyBPFFiltersInNS returns the number of clsact BPF filters of
// any name on link.
func countAnyBPFFiltersInNS(t *testing.T, ns *tns.NS, linkName string) int {
	t.Helper()
	var n int
	err := ns.Do(func() error {
		link, err := netlink.LinkByName(linkName)
		if err != nil {
			return err
		}
		for _, parent := range []uint32{netlink.HANDLE_MIN_INGRESS, netlink.HANDLE_MIN_EGRESS} {
			filters, ferr := netlink.FilterList(link, parent)
			if ferr != nil {
				continue
			}
			for _, f := range filters {
				if _, ok := f.(*netlink.BpfFilter); ok {
					n++
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("count any BPF filters: %v", err)
	}
	return n
}
