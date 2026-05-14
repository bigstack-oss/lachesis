//go:build integration

// Package e2e_test exercises the full test-infrastructure stack: BPF load
// + TC attach + netns + real TCP traffic + map assertion. Verifies that
// every test-environment component composes correctly end to end.
package e2e_test

import (
	"net"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/testenv/bpfunit"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/testenv/bpfunit/fixtures"
	tns "github.com/bigstack-oss/cube-cos-network-telemetry/internal/testenv/netns"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/testenv/traffic"
)

// TestE2E_SingleVM_NoopCounter verifies end-to-end composition:
// netns + veth + TC attach + noop BPF + real TCP all wired together.
//
// Topology:
//
//	netns(vm0, 10.77.0.1/30)  <-->  host(tap0, 10.77.0.2/30) [BPF noop ingress]
//	                                      ^
//	                                      |  TCP sink listening on 0.0.0.0
//
// Traffic: 1 MB stream from netns dialing the host-side IP. Every packet
// crosses tap0 ingress (TC hook), bumping the noop counter.
func TestE2E_SingleVM_NoopCounter(t *testing.T) {
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

	innerMAC, _ := net.ParseMAC("aa:bb:cc:dd:e2:01")
	outerMAC, _ := net.ParseMAC("aa:bb:cc:dd:e2:02")
	innerIP := &net.IPNet{IP: net.IPv4(10, 77, 0, 1), Mask: net.CIDRMask(30, 32)}
	outerIP := &net.IPNet{IP: net.IPv4(10, 77, 0, 2), Mask: net.CIDRMask(30, 32)}

	host, err := ns.AddVeth(tns.VethSpec{
		InnerName: "vm-e2e", OuterName: "tap-e2e",
		InnerMAC: innerMAC, OuterMAC: outerMAC,
		InnerIP: innerIP, OuterIP: outerIP,
	})
	if err != nil {
		t.Fatalf("add veth: %v", err)
	}
	defer netlink.LinkDel(host)

	prog := drv.Program("tc_noop_in")
	if prog == nil {
		t.Fatal("tc_noop_in program missing from collection")
	}
	if err := tns.AttachBPF(host, prog, tns.TCIngress, "noop_in"); err != nil {
		t.Fatalf("attach: %v", err)
	}

	addr, stop := traffic.ServeTCPSink(t)
	defer stop()

	tcpAddr := addr.(*net.TCPAddr)
	const payload = 1 * 1024 * 1024
	if err := traffic.SendTCPStream(ns, outerIP.IP, uint16(tcpAddr.Port), payload); err != nil {
		t.Fatalf("send: %v", err)
	}

	m := drv.Map("run_count")
	var key uint32
	var val uint64
	if err := m.Lookup(&key, &val); err != nil {
		t.Fatalf("counter lookup: %v", err)
	}
	if val == 0 {
		t.Error("noop counter == 0, expected >0 after 1 MB TCP stream")
	}
	t.Logf("noop counter after %d bytes: %d packets through tap0 ingress", payload, val)
}
