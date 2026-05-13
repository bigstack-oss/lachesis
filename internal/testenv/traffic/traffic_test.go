//go:build integration

package traffic_test

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"

	tns "github.com/bigstack-oss/cube-cos-network-telemetry/internal/testenv/netns"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/testenv/traffic"
)

func TestSendTCPStream(t *testing.T) {
	addr, stop := traffic.ServeTCPSink(t)
	defer stop()

	ns, err := tns.New()
	if err != nil {
		t.Fatalf("new ns: %v", err)
	}
	defer ns.Close()

	innerMAC, _ := net.ParseMAC("aa:bb:cc:dd:00:01")
	outerMAC, _ := net.ParseMAC("aa:bb:cc:dd:00:02")
	innerIP := &net.IPNet{IP: net.IPv4(10, 88, 0, 1), Mask: net.CIDRMask(30, 32)}
	outerIP := &net.IPNet{IP: net.IPv4(10, 88, 0, 2), Mask: net.CIDRMask(30, 32)}

	host, err := ns.AddVeth(tns.VethSpec{
		InnerName: "vm-tf", OuterName: "tap-tf",
		InnerMAC: innerMAC, OuterMAC: outerMAC,
		InnerIP: innerIP, OuterIP: outerIP,
	})
	if err != nil {
		t.Fatalf("add veth: %v", err)
	}
	defer netlink.LinkDel(host)

	tcpAddr := addr.(*net.TCPAddr)
	const payload = 64 * 1024
	if err := traffic.SendTCPStream(ns, outerIP.IP, uint16(tcpAddr.Port), payload); err != nil {
		t.Fatalf("send: %v", err)
	}
}
