//go:build integration

package e2e_test

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"

	telemetrybpf "github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/testenv/bpfunit"
	tns "github.com/bigstack-oss/cube-cos-network-telemetry/internal/testenv/netns"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/testenv/traffic"
)

// Zone codes — must match bpf/telemetry.c. Duplicated from the classifier
// test rather than imported via a shared abi package; the duplication is
// 3 lines and keeps test packages independent.
const (
	zoneSameTenant uint8 = 1
)

type hybridFlowKey struct {
	SrcMAC    [6]uint8
	DstMAC    [6]uint8
	EthProto  uint16
	Direction uint8
	DstZone   uint8
}

type hybridFlowMetrics struct {
	Bytes      uint64
	Packets    uint64
	LastSeenNs uint64
}

// TestE2E_HybridZone_SameTenantNoTrie is Sprint 1's "Done when" criterion:
// a same-tenant TCP stream over a real veth pair classifies as SAME_TENANT
// while the LPM trie is empty — proving the MAC-first hybrid path is what
// produced the classification.
//
// Topology:
//
//	netns(vm-h1, 10.88.0.1/30)  <-->  host(tap-h1, 10.88.0.2/30) [TC ingress: tc_telemetry_in]
//	                                         ^
//	                                         |  TCP sink on 0.0.0.0:<auto>
//
// Both MACs are populated into mac_tenant_map under the same tenant_id;
// the LPM trie is left empty.
func TestE2E_HybridZone_SameTenantNoTrie(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("rlimit: %v", err)
	}

	spec, err := telemetrybpf.LoadTelemetry()
	if err != nil {
		t.Fatalf("load telemetry: %v", err)
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

	innerMAC, _ := net.ParseMAC("02:00:00:00:01:01")
	outerMAC, _ := net.ParseMAC("02:00:00:00:01:02")
	innerIP := &net.IPNet{IP: net.IPv4(10, 88, 0, 1), Mask: net.CIDRMask(30, 32)}
	outerIP := &net.IPNet{IP: net.IPv4(10, 88, 0, 2), Mask: net.CIDRMask(30, 32)}

	host, err := ns.AddVeth(tns.VethSpec{
		InnerName: "vm-h1", OuterName: "tap-h1",
		InnerMAC: innerMAC, OuterMAC: outerMAC,
		InnerIP: innerIP, OuterIP: outerIP,
	})
	if err != nil {
		t.Fatalf("add veth: %v", err)
	}
	defer netlink.LinkDel(host)

	const tenant uint32 = 100
	macMap := drv.Map("mac_tenant_map")
	if macMap == nil {
		t.Fatal("mac_tenant_map not loaded")
	}
	for _, m := range []net.HardwareAddr{innerMAC, outerMAC} {
		k := macAddrToU64(m)
		v := tenant
		if err := macMap.Update(&k, &v, ebpf.UpdateAny); err != nil {
			t.Fatalf("populate mac_tenant_map %s: %v", m, err)
		}
	}

	prog := drv.Program("tc_telemetry_in")
	if prog == nil {
		t.Fatal("tc_telemetry_in program missing")
	}
	if err := tns.AttachBPF(host, prog, tns.TCIngress, "telemetry_in"); err != nil {
		t.Fatalf("attach: %v", err)
	}

	addr, stop := traffic.ServeTCPSink(t)
	defer stop()

	tcpAddr := addr.(*net.TCPAddr)
	const payload = 256 * 1024 // a few hundred packets at MTU 1500
	if err := traffic.SendTCPStream(ns, outerIP.IP, uint16(tcpAddr.Port), payload); err != nil {
		t.Fatalf("send: %v", err)
	}

	telMap := drv.Map("telemetry_map")
	if telMap == nil {
		t.Fatal("telemetry_map not loaded")
	}

	// Inner is the VM, outer is the peer. The packet enters tap-h1 ingress,
	// so direction=0; vm_mac=h_source=innerMAC, peer_mac=h_dest=outerMAC.
	var (
		innerArr   = [6]uint8(innerMAC)
		outerArr   = [6]uint8(outerMAC)
		matched    bool
		matchedKey hybridFlowKey
		matchedAgg uint64
	)
	var key hybridFlowKey
	var vals []hybridFlowMetrics
	iter := telMap.Iterate()
	for iter.Next(&key, &vals) {
		if key.SrcMAC == innerArr && key.DstMAC == outerArr && key.Direction == 0 {
			matched = true
			matchedKey = key
			for _, v := range vals {
				matchedAgg += v.Bytes
			}
			break
		}
	}
	if err := iter.Err(); err != nil {
		t.Fatalf("iterate telemetry_map: %v", err)
	}
	if !matched {
		t.Fatal("no telemetry_map entry for inner→outer ingress")
	}
	if matchedKey.DstZone != zoneSameTenant {
		t.Errorf("dst_zone = %d, want %d (SAME_TENANT)", matchedKey.DstZone, zoneSameTenant)
	}
	t.Logf("hybrid path verified: dst_zone=SAME_TENANT, aggregated bytes=%d (trie was empty)", matchedAgg)
}

func macAddrToU64(m net.HardwareAddr) uint64 {
	if len(m) != 6 {
		return 0
	}
	return uint64(binary.BigEndian.Uint16(m[0:2]))<<32 | uint64(binary.BigEndian.Uint32(m[2:6]))
}
