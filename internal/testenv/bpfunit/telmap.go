package bpfunit

import (
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
)

// MACBytes converts the low 48 bits of v into a 6-byte array in big-endian
// order — the layout used by [bpf.FlowKey.SrcMac] / [bpf.FlowKey.DstMac].
// Sibling of [MAC] for callers that need the array form rather than the
// [net.HardwareAddr] slice.
func MACBytes(v uint64) [6]byte {
	var b [6]byte
	binary.BigEndian.PutUint16(b[0:2], uint16(v>>32))
	binary.BigEndian.PutUint32(b[2:6], uint32(v))
	return b
}

// FindZone scans telemetry_map for the first entry whose flow_key matches
// (srcMAC, dstMAC, dir) and returns the recorded DstZone. The map is
// PERCPU_HASH; this helper inspects only keys.
func FindZone(m *ebpf.Map, srcMAC, dstMAC uint64, dir bpf.Direction) (bpf.ZoneCode, bool, error) {
	srcB := MACBytes(srcMAC)
	dstB := MACBytes(dstMAC)
	var key bpf.FlowKey
	var vals []bpf.FlowMetrics
	iter := m.Iterate()
	for iter.Next(&key, &vals) {
		if key.SrcMac == srcB && key.DstMac == dstB && key.Direction == dir {
			return key.DstZone, true, nil
		}
	}
	if err := iter.Err(); err != nil {
		return 0, false, fmt.Errorf("bpfunit: iterate telemetry_map: %w", err)
	}
	return 0, false, nil
}

// DrainTelemetryByMACs deletes every telemetry_map entry whose flow_key
// matches the (srcMAC, dstMAC) pair in either direction. Tests call this
// between subcases so a prior /24 hit doesn't carry over to a later case
// sharing the same MAC pair.
func DrainTelemetryByMACs(m *ebpf.Map, srcMAC, dstMAC uint64) error {
	srcB := MACBytes(srcMAC)
	dstB := MACBytes(dstMAC)
	var key bpf.FlowKey
	var vals []bpf.FlowMetrics
	iter := m.Iterate()
	var toDelete []bpf.FlowKey
	for iter.Next(&key, &vals) {
		if key.SrcMac == srcB && key.DstMac == dstB {
			toDelete = append(toDelete, key)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("bpfunit: iterate telemetry_map: %w", err)
	}
	for i := range toDelete {
		if err := m.Delete(&toDelete[i]); err != nil {
			return fmt.Errorf("bpfunit: delete telemetry_map entry: %w", err)
		}
	}
	return nil
}
