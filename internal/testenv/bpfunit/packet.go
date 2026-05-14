package bpfunit

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// EthIPv4TCP returns a serialized Ethernet + IPv4 + TCP SYN frame.
// payload may be nil. Returned slice is owned by the caller.
func EthIPv4TCP(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    srcIP.To4(),
		DstIP:    dstIP.To4(),
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Window:  65535,
		SYN:     true,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	return serialize(eth, ip, tcp, gopacket.Payload(payload))
}

// EthIPv4UDP returns a serialized Ethernet + IPv4 + UDP frame.
func EthIPv4UDP(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    srcIP.To4(),
		DstIP:    dstIP.To4(),
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	_ = udp.SetNetworkLayerForChecksum(ip)
	return serialize(eth, ip, udp, gopacket.Payload(payload))
}

// EthIPv6TCP returns a serialized Ethernet + IPv6 + TCP SYN frame.
func EthIPv6TCP(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolTCP,
		HopLimit:   64,
		SrcIP:      srcIP.To16(),
		DstIP:      dstIP.To16(),
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Window:  65535,
		SYN:     true,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	return serialize(eth, ip, tcp, gopacket.Payload(payload))
}

// ARPFrame returns a minimal ARP request frame for non-IP pass-through tests.
func ARPFrame(srcMAC, dstMAC net.HardwareAddr) []byte {
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeARP,
	}
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   srcMAC,
		SourceProtAddress: []byte{0, 0, 0, 0},
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte{0, 0, 0, 0},
	}
	return serialize(eth, arp)
}

// MAC builds a hardware address from the low 48 bits of v in big-endian order.
// Convenience for tests already working in u64-as-MAC form.
func MAC(v uint64) net.HardwareAddr {
	var m [6]byte
	binary.BigEndian.PutUint16(m[0:2], uint16(v>>32))
	binary.BigEndian.PutUint32(m[2:6], uint32(v))
	return m[:]
}

// serialize concatenates layers into a wire-format byte slice with lengths
// and checksums filled in. Panics on serialization error, which indicates a
// programming bug in the caller rather than a runtime condition.
func serialize(layers ...gopacket.SerializableLayer) []byte {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buf, opts, layers...); err != nil {
		panic(fmt.Sprintf("bpfunit: serialize: %v", err))
	}
	return buf.Bytes()
}
