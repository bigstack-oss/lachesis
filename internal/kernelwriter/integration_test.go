//go:build integration

// Integration coverage for kernelwriter: writes mac_tenant_map and
// subnet_zone_trie via the production writers, then exercises the
// classifier through BPF_PROG_TEST_RUN to confirm the written state
// produces the expected zone codes end-to-end.
package kernelwriter_test

import (
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf/rlimit"

	"github.com/bigstack-oss/lachesis/internal/bpf"
	"github.com/bigstack-oss/lachesis/internal/kernelwriter"
	"github.com/bigstack-oss/lachesis/internal/metadata"
	"github.com/bigstack-oss/lachesis/internal/neutron"
	"github.com/bigstack-oss/lachesis/internal/testenv/bpfunit"
)

const (
	macVMA uint64 = 0x02_00_00_00_AA_01 // VM in projA
	macVMB uint64 = 0x02_00_00_00_AA_02 // VM in projA (same tenant)
	macVMC uint64 = 0x02_00_00_00_BB_01 // VM in projB
	macRtr uint64 = 0x02_00_00_00_FF_01 // router peer — never written to mac_tenant_map
	projA         = "proj-A-uuid"
	projB         = "proj-B-uuid"
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

// TestKernelWriter_SubnetInfraBeatsTenantSubnet drives the zone a VM's
// own gateway and OVN metadata/DHCP port get through the production
// path: Neutron snapshot → BuildTrie → WriteSubnetZoneTrie → classifier.
// The kernel consults the tenant's rows before the global ones, so the
// infra /32s must win inside the tenant's own /24 in both directions.
func TestKernelWriter_SubnetInfraBeatsTenantSubnet(t *testing.T) {
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
	telMap := drv.Map(bpf.MapTelemetry)

	meta := metadata.New()
	meta.Insert(macVMA, &metadata.TenantMeta{ProjectID: projA})
	interner := metadata.NewTenantInterner()
	if _, err := kernelwriter.WriteMacTenantMap(drv.Map(bpf.MapMacTenant), meta, interner); err != nil {
		t.Fatalf("WriteMacTenantMap: %v", err)
	}

	entries, _, _ := neutron.BuildTrie(neutron.Snapshot{
		Networks: []neutron.Network{{ID: "net-a", ProjectID: projA}},
		Subnets: []neutron.Subnet{{
			ID: "sub-a", NetworkID: "net-a", ProjectID: projA,
			CIDR: "192.168.101.0/24", GatewayIP: "192.168.101.1", IPVersion: 4,
		}},
		Ports: []neutron.Port{
			{DeviceOwner: "network:router_interface", ProjectID: projA,
				FixedIPs: []neutron.FixedIP{{SubnetID: "sub-a", IPAddress: "192.168.101.1"}}},
			{DeviceOwner: "network:distributed", ProjectID: projA,
				FixedIPs: []neutron.FixedIP{{SubnetID: "sub-a", IPAddress: "192.168.101.2"}}},
		},
	})
	if _, err := kernelwriter.WriteSubnetZoneTrie(drv.Map(bpf.MapSubnetZoneTrie), entries, interner); err != nil {
		t.Fatalf("WriteSubnetZoneTrie: %v", err)
	}

	vmIP := net.IPv4(192, 168, 101, 147)
	for _, tc := range []struct {
		name   string
		remote net.IP
		want   bpf.ZoneCode
	}{
		{"gateway", net.IPv4(192, 168, 101, 1), bpf.ZoneInfra},
		{"OVN metadata/DHCP port", net.IPv4(192, 168, 101, 2), bpf.ZoneInfra},
		{"Nova metadata", net.IPv4(169, 254, 169, 254), bpf.ZoneInfra},
		{"routed peer in own subnet", net.IPv4(192, 168, 101, 50), bpf.ZoneSameTenant},
		{"internet", net.IPv4(8, 8, 8, 8), bpf.ZoneExternal},
	} {
		for _, dir := range []bpf.Direction{bpf.DirectionIngress, bpf.DirectionEgress} {
			src, dst, sip, dip, prog := macVMA, macRtr, vmIP, tc.remote, bpf.ProgramIngress
			if dir == bpf.DirectionEgress {
				src, dst, sip, dip, prog = macRtr, macVMA, tc.remote, vmIP, bpf.ProgramEgress
			}
			t.Run(fmt.Sprintf("%s/%s", tc.name, prog), func(t *testing.T) {
				if err := bpfunit.DrainTelemetryByMACs(telMap, src, dst); err != nil {
					t.Fatalf("drain telemetry_map: %v", err)
				}
				if _, err := drv.Run(prog, bpfunit.EthIPv4TCP(bpfunit.MAC(src), bpfunit.MAC(dst), sip, dip, 12345, 80, nil)); err != nil {
					t.Fatalf("run: %v", err)
				}
				zone, ok, err := bpfunit.FindZone(telMap, src, dst, dir)
				if err != nil || !ok {
					t.Fatalf("find zone: ok=%v err=%v", ok, err)
				}
				if zone != tc.want {
					t.Errorf("dst_zone = %d, want %d", zone, tc.want)
				}
			})
		}
	}
}
