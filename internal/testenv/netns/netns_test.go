//go:build integration

package netns_test

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"

	tns "github.com/bigstack-oss/lachesis/internal/testenv/netns"
)

func TestNS_LifecycleAndDo(t *testing.T) {
	ns, err := tns.New()
	if err != nil {
		t.Fatalf("new ns: %v", err)
	}
	defer ns.Close()

	var sawLoopback bool
	if err := ns.Do(func() error {
		links, err := netlink.LinkList()
		if err != nil {
			return err
		}
		for _, l := range links {
			if l.Attrs().Name == "lo" {
				sawLoopback = true
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if !sawLoopback {
		t.Error("expected loopback (lo) inside fresh ns")
	}
}

func TestNS_AddVeth(t *testing.T) {
	ns, err := tns.New()
	if err != nil {
		t.Fatalf("new ns: %v", err)
	}
	defer ns.Close()

	innerMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	outerMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:02")
	innerIP := &net.IPNet{IP: net.IPv4(10, 99, 0, 1), Mask: net.CIDRMask(30, 32)}
	outerIP := &net.IPNet{IP: net.IPv4(10, 99, 0, 2), Mask: net.CIDRMask(30, 32)}

	host, err := ns.AddVeth(tns.VethSpec{
		InnerName: "vm0", OuterName: "tap0",
		InnerMAC: innerMAC, OuterMAC: outerMAC,
		InnerIP: innerIP, OuterIP: outerIP,
	})
	if err != nil {
		t.Fatalf("add veth: %v", err)
	}
	defer netlink.LinkDel(host)

	if got := host.Attrs().Name; got != "tap0" {
		t.Errorf("host side name = %q, want tap0", got)
	}

	// Re-resolve the host link to read its post-up flags.
	host, _ = netlink.LinkByName("tap0")
	if host.Attrs().Flags&net.FlagUp == 0 {
		t.Error("host side veth not up")
	}

	if err := ns.Do(func() error {
		inner, err := netlink.LinkByName("vm0")
		if err != nil {
			return err
		}
		if got := inner.Attrs().HardwareAddr.String(); got != innerMAC.String() {
			t.Errorf("inner MAC = %s, want %s", got, innerMAC)
		}
		if inner.Attrs().Flags&net.FlagUp == 0 {
			t.Error("inner veth not up")
		}
		return nil
	}); err != nil {
		t.Fatalf("Do inner check: %v", err)
	}
}
