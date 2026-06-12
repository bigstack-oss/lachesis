//go:build integration

package tcattach_test

import (
	"net"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/tcattach"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/testenv/bpfunit"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/testenv/bpfunit/fixtures"
	tns "github.com/bigstack-oss/cube-cos-network-telemetry/internal/testenv/netns"
)

// TestAttachTelemetry_ReattachDoesNotStackFilters proves the
// FilterReplace-idempotence guarantee behind [tcattach.FilterPriority]:
// attaching twice to the same link leaves exactly one filter per
// clsact hook, at the pinned priority. Without the fixed priority the
// kernel auto-allocates a fresh one per call, so the second attach
// stacks a duplicate filter and every packet is counted twice.
//
// It then deletes each filter by the pinned (parent, priority, handle)
// triple and asserts both hooks are empty — at priority 0 a FilterDel
// addressed this way cannot find the filter, so the triple being
// fixed is what makes deletion (the rollback path) functional.
func TestAttachTelemetry_ReattachDoesNotStackFilters(t *testing.T) {
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
		t.Fatal("tc_noop_in program missing from collection")
	}

	ns, err := tns.New()
	if err != nil {
		t.Fatalf("new ns: %v", err)
	}
	defer ns.Close()

	innerMAC, _ := net.ParseMAC("aa:bb:cc:dd:e5:01")
	outerMAC, _ := net.ParseMAC("aa:bb:cc:dd:e5:02")
	innerIP := &net.IPNet{IP: net.IPv4(10, 83, 0, 1), Mask: net.CIDRMask(30, 32)}
	outerIP := &net.IPNet{IP: net.IPv4(10, 83, 0, 2), Mask: net.CIDRMask(30, 32)}

	host, err := ns.AddVeth(tns.VethSpec{
		InnerName: "vm-tcidem", OuterName: "tap-tcidem",
		InnerMAC: innerMAC, OuterMAC: outerMAC,
		InnerIP: innerIP, OuterIP: outerIP,
	})
	if err != nil {
		t.Fatalf("add veth: %v", err)
	}
	defer netlink.LinkDel(host)

	if err := ns.Do(func() error {
		link, err := netlink.LinkByName("vm-tcidem")
		if err != nil {
			return err
		}
		if err := tcattach.AttachTelemetry(link, prog, prog); err != nil {
			return err
		}
		return tcattach.AttachTelemetry(link, prog, prog)
	}); err != nil {
		t.Fatalf("attach twice: %v", err)
	}

	for _, hook := range tcattach.Hooks {
		filters := listBPFFiltersInNS(t, ns, "vm-tcidem", hook.Parent)
		if len(filters) != 1 {
			t.Fatalf("hook %s: filter count after double attach = %d, want 1", hook.Name, len(filters))
		}
		if got := filters[0].Name; got != hook.Name {
			t.Errorf("hook %s: filter name = %q, want %q", hook.Name, got, hook.Name)
		}
		if got := filters[0].Priority; got != tcattach.FilterPriority {
			t.Errorf("hook %s: filter priority = %d, want %d", hook.Name, got, tcattach.FilterPriority)
		}
	}

	// Detach by the pinned triple, the same addressing the rollback
	// path uses.
	if err := ns.Do(func() error {
		link, err := netlink.LinkByName("vm-tcidem")
		if err != nil {
			return err
		}
		for _, hook := range tcattach.Hooks {
			if err := netlink.FilterDel(&netlink.BpfFilter{
				FilterAttrs: netlink.FilterAttrs{
					LinkIndex: link.Attrs().Index,
					Parent:    hook.Parent,
					Handle:    tcattach.FilterHandle,
					Priority:  tcattach.FilterPriority,
					Protocol:  unix.ETH_P_ALL,
				},
			}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("detach by pinned triple: %v", err)
	}

	for _, hook := range tcattach.Hooks {
		if got := len(listBPFFiltersInNS(t, ns, "vm-tcidem", hook.Parent)); got != 0 {
			t.Errorf("hook %s: filter count after detach = %d, want 0", hook.Name, got)
		}
	}
}

// TestAttachTelemetry_RollsBackIngressOnEgressFailure proves the
// all-or-nothing guarantee: when the egress attach fails after the
// ingress filter is installed, AttachTelemetry returns an error and
// the ingress filter is actually gone — the link never carries a
// half-attached telemetry pair its caller recorded as unattached.
// The egress failure is forced with a closed program clone, whose
// invalid fd the kernel rejects at FilterReplace.
func TestAttachTelemetry_RollsBackIngressOnEgressFailure(t *testing.T) {
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
		t.Fatal("tc_noop_in program missing from collection")
	}
	broken, err := prog.Clone()
	if err != nil {
		t.Fatalf("clone prog: %v", err)
	}
	if err := broken.Close(); err != nil {
		t.Fatalf("close clone: %v", err)
	}

	ns, err := tns.New()
	if err != nil {
		t.Fatalf("new ns: %v", err)
	}
	defer ns.Close()

	innerMAC, _ := net.ParseMAC("aa:bb:cc:dd:e6:01")
	outerMAC, _ := net.ParseMAC("aa:bb:cc:dd:e6:02")
	innerIP := &net.IPNet{IP: net.IPv4(10, 84, 0, 1), Mask: net.CIDRMask(30, 32)}
	outerIP := &net.IPNet{IP: net.IPv4(10, 84, 0, 2), Mask: net.CIDRMask(30, 32)}

	host, err := ns.AddVeth(tns.VethSpec{
		InnerName: "vm-tcroll", OuterName: "tap-tcroll",
		InnerMAC: innerMAC, OuterMAC: outerMAC,
		InnerIP: innerIP, OuterIP: outerIP,
	})
	if err != nil {
		t.Fatalf("add veth: %v", err)
	}
	defer netlink.LinkDel(host)

	var attachErr error
	if err := ns.Do(func() error {
		link, err := netlink.LinkByName("vm-tcroll")
		if err != nil {
			return err
		}
		attachErr = tcattach.AttachTelemetry(link, prog, broken)
		return nil
	}); err != nil {
		t.Fatalf("Do(AttachTelemetry): %v", err)
	}
	if attachErr == nil {
		t.Fatal("AttachTelemetry with closed egress prog succeeded, want error")
	}

	for _, hook := range tcattach.Hooks {
		if got := len(listBPFFiltersInNS(t, ns, "vm-tcroll", hook.Parent)); got != 0 {
			t.Errorf("hook %s: filter count after failed attach = %d, want 0 (rollback must remove ingress)", hook.Name, got)
		}
	}
}

// listBPFFiltersInNS returns the clsact BPF filters of any name on
// link under the given parent hook, inside ns. Listing every BPF
// filter (rather than name-matching) is deliberate: the stacking
// regression installs duplicates under the same name, so only an
// unfiltered count catches it.
func listBPFFiltersInNS(t *testing.T, ns *tns.NS, linkName string, parent uint32) []*netlink.BpfFilter {
	t.Helper()
	var out []*netlink.BpfFilter
	err := ns.Do(func() error {
		link, err := netlink.LinkByName(linkName)
		if err != nil {
			return err
		}
		filters, ferr := netlink.FilterList(link, parent)
		if ferr != nil {
			// No clsact on this hook — nothing attached.
			return nil
		}
		for _, f := range filters {
			if bf, ok := f.(*netlink.BpfFilter); ok {
				out = append(out, bf)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("list BPF filters on %s: %v", linkName, err)
	}
	return out
}
