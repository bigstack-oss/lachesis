//go:build integration

// Verifies the kernel's L4 protocol class through BPF_PROG_TEST_RUN: each
// frame shape lands in telemetry_map under the expected l4_proto, with
// the key's pad byte zero, and a non-IP frame creates no entry at all.
//
// docs/adr/0015-l4-protocol-class-in-flow-key.md
package classifier_test

import (
	"net"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/gopacket/gopacket/layers"

	"github.com/bigstack-oss/lachesis/internal/bpf"
	"github.com/bigstack-oss/lachesis/internal/testenv/bpfunit"
)

// Locally-administered MACs, distinct from the other classifier tests.
const (
	l4MacVM   uint64 = 0x02_00_00_00_CC_01
	l4MacPeer uint64 = 0x02_00_00_00_CC_02
)

func TestL4Proto_ClassPerFrameShape(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("rlimit: %v", err)
	}
	spec, err := bpf.LoadTelemetry()
	if err != nil {
		t.Fatalf("load telemetry spec: %v", err)
	}
	drv, err := bpfunit.New(spec)
	if err != nil {
		t.Fatalf("new driver: %v", err)
	}
	defer drv.Close()

	vm, peer := bpfunit.MAC(l4MacVM), bpfunit.MAC(l4MacPeer)
	v4a, v4b := net.ParseIP("10.0.0.5"), net.ParseIP("10.0.0.6")
	v6a, v6b := net.ParseIP("fd00::5"), net.ParseIP("fd00::6")

	cases := []struct {
		name  string
		frame []byte
		want  bpf.L4Proto
	}{
		{"ipv4 tcp", bpfunit.EthIPv4TCP(vm, peer, v4a, v4b, 40000, 443, nil), bpf.L4ProtoTCP},
		{"ipv4 udp", bpfunit.EthIPv4UDP(vm, peer, v4a, v4b, 40000, 53, nil), bpf.L4ProtoUDP},
		{"ipv4 icmp", bpfunit.EthIPv4ICMP(vm, peer, v4a, v4b), bpf.L4ProtoICMP},
		{"ipv4 gre", bpfunit.EthIPv4Raw(vm, peer, v4a, v4b, layers.IPProtocolGRE, []byte{0, 0, 0x08, 0}), bpf.L4ProtoOther},
		{"ipv6 tcp", bpfunit.EthIPv6TCP(vm, peer, v6a, v6b, 40000, 443, nil), bpf.L4ProtoTCP},
		{"ipv6 icmpv6", bpfunit.EthIPv6ICMP(vm, peer, v6a, v6b), bpf.L4ProtoICMP},
		{"ipv6 extension header is not walked", bpfunit.EthIPv6DestOptsTCP(vm, peer, v6a, v6b), bpf.L4ProtoOther},
	}
	tm := drv.Map(bpf.MapTelemetry)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := bpfunit.DrainTelemetryByMACs(tm, l4MacVM, l4MacPeer); err != nil {
				t.Fatal(err)
			}
			if verdict, err := drv.Run(bpf.ProgramIngress, tc.frame); err != nil || verdict != 0 {
				t.Fatalf("run: verdict=%d err=%v, want TC_ACT_OK", verdict, err)
			}
			key, ok, err := bpfunit.FindKey(tm, l4MacVM, l4MacPeer, bpf.DirectionIngress)
			if err != nil {
				t.Fatal(err)
			}
			if !ok {
				t.Fatal("no telemetry_map entry for the frame")
			}
			if key.L4Proto != tc.want {
				t.Errorf("l4_proto = %s, want %s", key.L4Proto, tc.want)
			}
			if key.Pad != 0 {
				t.Errorf("pad = %d, want 0 — a stray byte splits one flow across entries", key.Pad)
			}
		})
	}

	t.Run("arp is not counted", func(t *testing.T) {
		if err := bpfunit.DrainTelemetryByMACs(tm, l4MacVM, l4MacPeer); err != nil {
			t.Fatal(err)
		}
		if _, err := drv.Run(bpf.ProgramIngress, bpfunit.ARPFrame(vm, peer)); err != nil {
			t.Fatal(err)
		}
		if _, ok, err := bpfunit.FindKey(tm, l4MacVM, l4MacPeer, bpf.DirectionIngress); err != nil || ok {
			t.Errorf("ARP created an entry (ok=%v err=%v); non-IP frames stay uncounted", ok, err)
		}
	})
}
