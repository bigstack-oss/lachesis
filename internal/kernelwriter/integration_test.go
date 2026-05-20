//go:build integration

// Integration coverage for kernelwriter: writes mac_tenant_map and
// subnet_zone_trie via the production writers, then exercises the
// classifier through BPF_PROG_TEST_RUN to confirm the written state
// produces the expected zone codes end-to-end.
package kernelwriter_test

import (
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf/rlimit"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/kernelwriter"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/metadata"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/neutron"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/testenv/bpfunit"
)

const (
	macVMA  uint64 = 0x02_00_00_00_AA_01 // VM in projA
	macVMB  uint64 = 0x02_00_00_00_AA_02 // VM in projA (same tenant)
	macVMC  uint64 = 0x02_00_00_00_BB_01 // VM in projB
	macRtr  uint64 = 0x02_00_00_00_FF_01 // router peer — never written to mac_tenant_map
	projA          = "proj-A-uuid"
	projB          = "proj-B-uuid"
)

func TestKernelWriter_RoundTrip(t *testing.T) {
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

	macMap := drv.Map(bpf.MapMacTenant)
	if macMap == nil {
		t.Fatalf("%s not loaded", bpf.MapMacTenant)
	}
	trieMap := drv.Map(bpf.MapSubnetZoneTrie)
	if trieMap == nil {
		t.Fatalf("%s not loaded", bpf.MapSubnetZoneTrie)
	}
	telMap := drv.Map(bpf.MapTelemetry)
	if telMap == nil {
		t.Fatalf("%s not loaded", bpf.MapTelemetry)
	}

	// Build userspace state.
	snap := metadata.New()
	snap.Insert(macVMA, &metadata.TenantMeta{ProjectID: projA})
	snap.Insert(macVMB, &metadata.TenantMeta{ProjectID: projA})
	snap.Insert(macVMC, &metadata.TenantMeta{ProjectID: projB})

	interner := metadata.NewTenantInterner()

	// Push MAC entries via the writer.
	if n, err := kernelwriter.WriteMacTenantMap(macMap, snap, interner); err != nil {
		t.Fatalf("WriteMacTenantMap: %v (wrote=%d)", err, n)
	} else if n != 3 {
		t.Fatalf("WriteMacTenantMap wrote %d entries, want 3", n)
	}

	// Hand-build a TrieEntry slice covering the three LPM regimes
	// in their post-dedup shape:
	//
	//   - SAME_TENANT: per-tenant, written under projA. First
	//     trie lookup (vm_tid=projA) hits directly.
	//   - INFRA + EXTERNAL catchall: global, written at TenantID=""
	//     (interner resolves to tenant_id=0). First lookup
	//     (vm_tid=projA) misses; sentinel fallback (tenant_id=0)
	//     hits — exercises the slice-3 two-lookup path.
	//
	// BuildTrie's output is exercised separately by its own unit
	// tests; this test focuses on the writer + kernel path.
	entries := []neutron.TrieEntry{
		{TenantID: "", Prefix: netip.MustParsePrefix("0.0.0.0/0"), Zone: bpf.ZoneExternal},
		{TenantID: projA, Prefix: netip.MustParsePrefix("10.0.1.0/24"), Zone: bpf.ZoneSameTenant},
		{TenantID: "", Prefix: netip.MustParsePrefix("169.254.169.254/32"), Zone: bpf.ZoneInfra},
	}
	if n, err := kernelwriter.WriteSubnetZoneTrie(trieMap, entries, interner); err != nil {
		t.Fatalf("WriteSubnetZoneTrie: %v (wrote=%d)", err, n)
	} else if n != 3 {
		t.Fatalf("WriteSubnetZoneTrie wrote %d entries, want 3", n)
	}

	cases := []struct {
		name     string
		src, dst uint64
		dstIP    net.IP
		prog     string
		wantDir  bpf.Direction
		wantZone bpf.ZoneCode
	}{
		// MAC-first hybrid path — both peers known.
		{
			name: "intra-tenant L2 via mac_tenant_map", src: macVMA, dst: macVMB,
			dstIP: net.IPv4(10, 0, 1, 5), prog: bpf.ProgramIngress,
			wantDir: bpf.DirectionIngress, wantZone: bpf.ZoneSameTenant,
		},
		{
			name: "cross-tenant L2 via mac_tenant_map", src: macVMA, dst: macVMC,
			dstIP: net.IPv4(10, 0, 2, 1), prog: bpf.ProgramIngress,
			wantDir: bpf.DirectionIngress, wantZone: bpf.ZoneOtherTenant,
		},
		// LPM fallback — peer is the router (not in mac_tenant_map).
		{
			name: "routed dst in /24 → SAME_TENANT", src: macVMA, dst: macRtr,
			dstIP: net.IPv4(10, 0, 1, 99), prog: bpf.ProgramIngress,
			wantDir: bpf.DirectionIngress, wantZone: bpf.ZoneSameTenant,
		},
		{
			name: "routed dst metadata IP → INFRA", src: macVMA, dst: macRtr,
			dstIP: net.IPv4(169, 254, 169, 254), prog: bpf.ProgramIngress,
			wantDir: bpf.DirectionIngress, wantZone: bpf.ZoneInfra,
		},
		{
			name: "routed dst unmatched → EXTERNAL catchall", src: macVMA, dst: macRtr,
			dstIP: net.IPv4(8, 8, 8, 8), prog: bpf.ProgramIngress,
			wantDir: bpf.DirectionIngress, wantZone: bpf.ZoneExternal,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			frame := bpfunit.EthIPv4TCP(
				bpfunit.MAC(tc.src), bpfunit.MAC(tc.dst),
				net.IPv4(10, 0, 1, 1), tc.dstIP, 12345, 80, nil,
			)
			verdict, err := drv.Run(tc.prog, frame)
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			if verdict != 0 {
				t.Errorf("verdict = %d, want 0 (TC_ACT_OK)", verdict)
			}
			zone, ok, err := bpfunit.FindZone(telMap, tc.src, tc.dst, tc.wantDir)
			if err != nil {
				t.Fatalf("find zone: %v", err)
			}
			if !ok {
				t.Fatalf("no telemetry_map entry for src=%012x dst=%012x", tc.src, tc.dst)
			}
			if zone != tc.wantZone {
				t.Errorf("dst_zone = %d, want %d", zone, tc.wantZone)
			}
			// Drain so a /24 hit doesn't carry over to a later case
			// that uses the same (src, dst) pair.
			if err := bpfunit.DrainTelemetryByMACs(telMap, tc.src, tc.dst); err != nil {
				t.Fatalf("drain telemetry_map: %v", err)
			}
		})
	}
}
