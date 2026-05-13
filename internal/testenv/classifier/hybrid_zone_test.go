//go:build integration

// Package classifier_test exercises the production telemetry BPF program
// through BPF_PROG_TEST_RUN with table-driven cases. Verifies §4.3 hybrid
// MAC-first / LPM-fallback zone lookup. No real interfaces, no real traffic;
// see internal/testenv/e2e for that.
package classifier_test

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	telemetrybpf "github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/testenv/bpfunit"
)

// Zone codes — must match bpf/telemetry.c.
const (
	zoneExternal    uint8 = 0
	zoneSameTenant  uint8 = 1
	zoneOtherTenant uint8 = 2
	zoneInfra       uint8 = 3
	zoneMiss        uint8 = 4
)

// Locally-administered MACs (top bit of first byte = 0x02) so we never
// collide with anything real even if a test escapes its sandbox.
const (
	macVMA       uint64 = 0x02_00_00_00_00_01 // tenant A
	macVMB       uint64 = 0x02_00_00_00_00_02 // tenant A
	macVMC       uint64 = 0x02_00_00_00_00_03 // tenant B
	macRouter    uint64 = 0x02_00_00_00_FF_01 // not in mac_tenant_map
	macUnknownVM uint64 = 0x02_00_00_00_FF_02 // not in mac_tenant_map
)

const (
	tenantA uint32 = 100
	tenantB uint32 = 200
)

// flowKey mirrors struct flow_key in bpf/telemetry.c. Layout is 16 bytes,
// __attribute__((packed)) on the C side. Go's natural alignment of these
// fixed-width fields produces the same layout — no padding.
type flowKey struct {
	SrcMAC    [6]uint8
	DstMAC    [6]uint8
	EthProto  uint16 // host order after BPF read; ETH_P_IP = 0x0800
	Direction uint8
	DstZone   uint8
}

// flowMetrics mirrors struct flow_metrics in bpf/telemetry.c. Used as a
// discard buffer when iterating the PERCPU_HASH map — we only assert on the
// key's DstZone here.
type flowMetrics struct {
	Bytes      uint64
	Packets    uint64
	LastSeenNs uint64
}

func TestHybridZoneLookup(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("rlimit: %v", err)
	}
	spec, err := telemetrybpf.LoadTelemetry()
	if err != nil {
		t.Fatalf("load telemetry spec: %v", err)
	}
	drv, err := bpfunit.New(spec)
	if err != nil {
		t.Fatalf("new driver: %v", err)
	}
	defer drv.Close()

	// Populate mac_tenant_map. Intentionally leave the LPM trie empty:
	// the SAME/OTHER cases must succeed without it (the sprint goal).
	macMap := drv.Map("mac_tenant_map")
	if macMap == nil {
		t.Fatal("mac_tenant_map not loaded")
	}
	for mac, tid := range map[uint64]uint32{
		macVMA: tenantA,
		macVMB: tenantA,
		macVMC: tenantB,
	} {
		k, v := mac, tid
		if err := macMap.Update(&k, &v, ebpf.UpdateAny); err != nil {
			t.Fatalf("populate mac_tenant_map mac=%012x tid=%d: %v", mac, tid, err)
		}
	}

	telMap := drv.Map("telemetry_map")
	if telMap == nil {
		t.Fatal("telemetry_map not loaded")
	}

	cases := []struct {
		name     string
		src, dst uint64
		srcIP    net.IP
		dstIP    net.IP
		prog     string // tc_telemetry_in (dir=0) or tc_telemetry_out (dir=1)
		wantDir  uint8
		wantZone uint8
	}{
		// — Hybrid path (MAC-first, LPM not consulted) —
		{
			name: "ingress same-tenant direct L2",
			src:  macVMA, dst: macVMB,
			srcIP: net.IPv4(10, 0, 0, 1), dstIP: net.IPv4(10, 0, 0, 2),
			prog: "tc_telemetry_in", wantDir: 0, wantZone: zoneSameTenant,
		},
		{
			name: "ingress cross-tenant direct L2",
			src:  macVMA, dst: macVMC,
			srcIP: net.IPv4(10, 0, 0, 1), dstIP: net.IPv4(10, 0, 0, 3),
			prog: "tc_telemetry_in", wantDir: 0, wantZone: zoneOtherTenant,
		},
		{
			name: "egress same-tenant direct L2 (directional swap)",
			src:  macVMB, dst: macVMA, // on the wire: B->A; we're at A's tap egress
			srcIP: net.IPv4(10, 0, 0, 2), dstIP: net.IPv4(10, 0, 0, 1),
			prog: "tc_telemetry_out", wantDir: 1, wantZone: zoneSameTenant,
		},

		// — LPM-fallback path (peer not in map; trie empty → MISS) —
		{
			name: "ingress routed peer with empty trie → MISS",
			src:  macVMA, dst: macRouter,
			srcIP: net.IPv4(10, 0, 0, 1), dstIP: net.IPv4(8, 8, 8, 8),
			prog: "tc_telemetry_in", wantDir: 0, wantZone: zoneMiss,
		},

		// — Unknown VM short-circuit (don't even look up peer) —
		{
			name: "ingress unknown vm_mac → MISS",
			src:  macUnknownVM, dst: macVMA,
			srcIP: net.IPv4(10, 0, 0, 99), dstIP: net.IPv4(10, 0, 0, 1),
			prog: "tc_telemetry_in", wantDir: 0, wantZone: zoneMiss,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			frame := bpfunit.EthIPv4TCP(
				bpfunit.MAC(tc.src), bpfunit.MAC(tc.dst),
				tc.srcIP, tc.dstIP, 12345, 80, nil,
			)
			verdict, err := drv.Run(tc.prog, frame)
			if err != nil {
				t.Fatalf("run %s: %v", tc.prog, err)
			}
			if verdict != 0 {
				t.Errorf("verdict = %d, want 0 (TC_ACT_OK)", verdict)
			}

			zone, ok := findZone(telMap, tc.src, tc.dst, tc.wantDir)
			if !ok {
				t.Fatalf("no telemetry_map entry for src=%012x dst=%012x dir=%d",
					tc.src, tc.dst, tc.wantDir)
			}
			if zone != tc.wantZone {
				t.Errorf("dst_zone = %d, want %d", zone, tc.wantZone)
			}
		})
	}
}

// findZone scans telemetry_map for an entry matching (src, dst, direction)
// and returns the recorded DstZone. The map is PERCPU_HASH so the value
// slot is per-CPU; we only care about the key here.
func findZone(m *ebpf.Map, src, dst uint64, dir uint8) (uint8, bool) {
	srcB := macToArr(src)
	dstB := macToArr(dst)
	var key flowKey
	var vals []flowMetrics // discard
	iter := m.Iterate()
	for iter.Next(&key, &vals) {
		if key.SrcMAC == srcB && key.DstMAC == dstB && key.Direction == dir {
			return key.DstZone, true
		}
	}
	return 0, false
}

func macToArr(v uint64) [6]uint8 {
	var b [6]uint8
	binary.BigEndian.PutUint16(b[0:2], uint16(v>>32))
	binary.BigEndian.PutUint32(b[2:6], uint32(v))
	return b
}
