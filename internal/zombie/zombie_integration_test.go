//go:build integration

package zombie_test

import (
	"net"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

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
		cleaned, huntErr = zombie.Hunt(noneAttachable)
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
		c, herr := zombie.Hunt(noneAttachable)
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

func noneAttachable(netlink.Link) bool { return false }

func allAttachable(netlink.Link) bool { return true }

// TestHunt_SparesCanonicalFiltersOnAttachableLink pins issue 334: a
// telemetry filter pair in the canonical slot on a link the new agent
// will attach to survives Hunt, so the old program keeps counting into
// the pinned telemetry_map until the subscriber's FilterReplace swaps
// in the new one. Deleting it opened a 2-4 s uncounted window per VM.
func TestHunt_SparesCanonicalFiltersOnAttachableLink(t *testing.T) {
	ns, prog := huntFixture(t, "vm-spare", 80)

	if err := ns.Do(func() error {
		link, err := netlink.LinkByName("vm-spare")
		if err != nil {
			return err
		}
		return tcattach.AttachTelemetry(link, prog, prog)
	}); err != nil {
		t.Fatalf("attach: %v", err)
	}

	cleaned := huntInNS(t, ns, allAttachable)
	if cleaned != 0 {
		t.Errorf("cleaned = %d, want 0", cleaned)
	}
	if got := countTelemetryFiltersInNS(t, ns, "vm-spare"); got != 2 {
		t.Errorf("post-hunt telemetry filter count = %d, want 2 (canonical pair spared)", got)
	}
}

// TestHunt_DeletesOffSlotFilterOnAttachableLink proves sparing is
// limited to the canonical slot: a telemetry-named filter at another
// priority (an older build's orphan) is never replaced by the
// subscriber's FilterReplace, so leaving it would double-count.
func TestHunt_DeletesOffSlotFilterOnAttachableLink(t *testing.T) {
	ns, prog := huntFixture(t, "vm-offslot", 81)

	if err := ns.Do(func() error {
		link, err := netlink.LinkByName("vm-offslot")
		if err != nil {
			return err
		}
		if err := tcattach.AttachTelemetry(link, prog, prog); err != nil {
			return err
		}
		return netlink.FilterReplace(&netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    netlink.HANDLE_MIN_EGRESS,
				Handle:    tcattach.FilterHandle,
				Priority:  tcattach.FilterPriority + 1,
				Protocol:  unix.ETH_P_ALL,
			},
			Fd:           prog.FD(),
			Name:         tcattach.FilterEgressName,
			DirectAction: true,
		})
	}); err != nil {
		t.Fatalf("attach: %v", err)
	}

	cleaned := huntInNS(t, ns, allAttachable)
	if cleaned != 1 {
		t.Errorf("cleaned = %d, want 1 (only the off-slot filter)", cleaned)
	}
	if got := countTelemetryFiltersInNS(t, ns, "vm-offslot"); got != 2 {
		t.Errorf("post-hunt telemetry filter count = %d, want 2 (canonical pair spared)", got)
	}
}

// TestHunt_DeletesCanonicalFiltersOnNonAttachableLink proves a link
// the new agent will not attach to loses even its canonical pair:
// nothing would ever replace those filters.
func TestHunt_DeletesCanonicalFiltersOnNonAttachableLink(t *testing.T) {
	ns, prog := huntFixture(t, "vm-skip", 82)

	if err := ns.Do(func() error {
		link, err := netlink.LinkByName("vm-skip")
		if err != nil {
			return err
		}
		return tcattach.AttachTelemetry(link, prog, prog)
	}); err != nil {
		t.Fatalf("attach: %v", err)
	}

	cleaned := huntInNS(t, ns, func(l netlink.Link) bool { return l.Attrs().Name != "vm-skip" })
	if cleaned != 2 {
		t.Errorf("cleaned = %d, want 2", cleaned)
	}
	if got := countTelemetryFiltersInNS(t, ns, "vm-skip"); got != 0 {
		t.Errorf("post-hunt telemetry filter count = %d, want 0", got)
	}
}

// huntFixture loads the noop program and builds a netns holding the
// veth end named inner. octet keeps each test's addresses distinct.
func huntFixture(t *testing.T, inner string, octet byte) (*tns.NS, *ebpf.Program) {
	t.Helper()
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
	t.Cleanup(func() { drv.Close() })
	prog := drv.Program(fixtures.ProgNoopIn)
	if prog == nil {
		t.Fatal("tc_noop_in program missing from collection")
	}

	ns, err := tns.New()
	if err != nil {
		t.Fatalf("new ns: %v", err)
	}
	t.Cleanup(func() { ns.Close() })

	innerMAC := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, octet, 0x01}
	outerMAC := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, octet, 0x02}
	host, err := ns.AddVeth(tns.VethSpec{
		InnerName: inner, OuterName: "tap-" + inner[3:],
		InnerMAC: innerMAC, OuterMAC: outerMAC,
		InnerIP: &net.IPNet{IP: net.IPv4(10, octet, 0, 1), Mask: net.CIDRMask(30, 32)},
		OuterIP: &net.IPNet{IP: net.IPv4(10, octet, 0, 2), Mask: net.CIDRMask(30, 32)},
	})
	if err != nil {
		t.Fatalf("add veth: %v", err)
	}
	t.Cleanup(func() { netlink.LinkDel(host) })
	return ns, prog
}

// huntInNS runs Hunt inside ns and returns the cleaned count.
func huntInNS(t *testing.T, ns *tns.NS, attachable func(netlink.Link) bool) int {
	t.Helper()
	var (
		cleaned int
		huntErr error
	)
	if err := ns.Do(func() error {
		cleaned, huntErr = zombie.Hunt(attachable)
		return nil
	}); err != nil {
		t.Fatalf("Do(Hunt): %v", err)
	}
	if huntErr != nil {
		t.Fatalf("Hunt: %v", huntErr)
	}
	return cleaned
}
