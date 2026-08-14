//go:build integration

// Package classifier_test exercises the production telemetry BPF program
// through BPF_PROG_TEST_RUN with table-driven cases. Verifies the docs/architecture/packet-classification.md#the-hybrid-lookup-explained hybrid
// MAC-first / LPM-fallback zone lookup. No real interfaces, no real
// traffic; see internal/testenv/e2e for that.
package classifier_test

import (
	"net"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/bigstack-oss/lachesis/internal/bpf"
	"github.com/bigstack-oss/lachesis/internal/testenv/bpfunit"
)

// Locally-administered MACs (top bit of first byte = 0x02) so we never
// collide with anything real even if a test escapes its sandbox.
const (
	macVMA       uint64 = 0x02_00_00_00_00_01 // tenant A
	macVMB       uint64 = 0x02_00_00_00_00_02 // tenant A
	macVMC       uint64 = 0x02_00_00_00_00_03 // tenant B
	macRouter    uint64 = 0x02_00_00_00_FF_01 // not in mac_tenant_map
	macUnknownVM uint64 = 0x02_00_00_00_FF_02 // not in mac_tenant_map
	macPhysical  uint64 = 0x02_00_00_00_AA_01 // stands in for a physical DC device; not in mac_tenant_map
	macAmphora   uint64 = 0x02_00_00_00_0A_01 // Octavia Amphora data port, tenant A (LB owner)

	// Group-destination MACs (I/G bit set) → ZONE_MULTICAST.
	macMcast uint64 = 0x01_00_5E_7F_FF_FA // IPv4 local-scope multicast (SSDP-style)
	macBcast uint64 = 0xFF_FF_FF_FF_FF_FF // L2 broadcast (DHCP DISCOVER/REQUEST)
)

const (
	tenantA uint32 = 100
	tenantB uint32 = 200
)

func TestHybridZoneLookup(t *testing.T) {
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

	// Populate mac_tenant_map. Intentionally leave the LPM trie empty:
	// the SAME/OTHER cases must succeed without it, resolved by the
	// direct mac_tenant_map lookup alone.
	macMap := drv.Map(bpf.MapMacTenant)
	if macMap == nil {
		t.Fatal("mac_tenant_map not loaded")
	}
	// The Amphora entry carries the packed flag: userspace re-attributed
	// the port to the LB owner (tenant A) and marked it Amphora, so the
	// kernel must mask the id off before comparing and treat L2-adjacent
	// flows through it as Segment 2 plumbing (docs/architecture/octavia.md).
	for mac, tid := range map[uint64]uint32{
		macVMA:     tenantA,
		macVMB:     tenantA,
		macVMC:     tenantB,
		macAmphora: bpf.TenantValue(tenantA, true),
	} {
		k, v := mac, tid
		if err := macMap.Update(&k, &v, ebpf.UpdateAny); err != nil {
			t.Fatalf("populate mac_tenant_map mac=%012x tid=%d: %v", mac, tid, err)
		}
	}

	telMap := drv.Map(bpf.MapTelemetry)
	if telMap == nil {
		t.Fatalf("%s not loaded", bpf.MapTelemetry)
	}

	cases := []struct {
		name     string
		src, dst uint64
		srcIP    net.IP
		dstIP    net.IP
		prog     string // bpf.ProgramIngress (dir=0) or bpf.ProgramEgress (dir=1)
		wantDir  bpf.Direction
		wantZone bpf.ZoneCode
	}{
		// — Hybrid path (MAC-first, LPM not consulted) —
		{
			name: "ingress same-tenant direct L2",
			src:  macVMA, dst: macVMB,
			srcIP: net.IPv4(10, 0, 0, 1), dstIP: net.IPv4(10, 0, 0, 2),
			prog: bpf.ProgramIngress, wantDir: bpf.DirectionIngress, wantZone: bpf.ZoneSameTenant,
		},
		{
			name: "ingress cross-tenant direct L2",
			src:  macVMA, dst: macVMC,
			srcIP: net.IPv4(10, 0, 0, 1), dstIP: net.IPv4(10, 0, 0, 3),
			prog: bpf.ProgramIngress, wantDir: bpf.DirectionIngress, wantZone: bpf.ZoneOtherTenant,
		},
		{
			name: "egress same-tenant direct L2 (directional swap)",
			src:  macVMB, dst: macVMA, // on the wire: B->A; we're at A's tap egress
			srcIP: net.IPv4(10, 0, 0, 2), dstIP: net.IPv4(10, 0, 0, 1),
			prog: bpf.ProgramEgress, wantDir: bpf.DirectionEgress, wantZone: bpf.ZoneSameTenant,
		},

		// — Octavia Segment 2: an L2-adjacent flow with an Amphora on
		//   either end is load-balancer plumbing, zoned INFRA at BOTH
		//   taps so the tx/rx pair of one transfer shares a zone. —
		{
			// At the backend VM's tap: peer is the Amphora.
			name: "ingress backend to Amphora → INFRA",
			src:  macVMB, dst: macAmphora,
			srcIP: net.IPv4(10, 0, 0, 2), dstIP: net.IPv4(10, 0, 0, 10),
			prog: bpf.ProgramIngress, wantDir: bpf.DirectionIngress, wantZone: bpf.ZoneInfra,
		},
		{
			// At the Amphora's own tap: the VM side carries the flag.
			// Same transfer, same zone — without the vm-side check this
			// would read SAME_TENANT and split the pair across two zones.
			name: "ingress Amphora to backend → INFRA",
			src:  macAmphora, dst: macVMB,
			srcIP: net.IPv4(10, 0, 0, 10), dstIP: net.IPv4(10, 0, 0, 2),
			prog: bpf.ProgramIngress, wantDir: bpf.DirectionIngress, wantZone: bpf.ZoneInfra,
		},
		{
			// A cross-tenant peer does not rescue the flow from INFRA:
			// the Amphora flag wins over the tenant comparison.
			name: "ingress Amphora to other-tenant VM → INFRA",
			src:  macAmphora, dst: macVMC,
			srcIP: net.IPv4(10, 0, 0, 10), dstIP: net.IPv4(10, 0, 0, 3),
			prog: bpf.ProgramIngress, wantDir: bpf.DirectionIngress, wantZone: bpf.ZoneInfra,
		},
		{
			// Segment 1 must NOT be caught: an external client's peer is
			// a router interface, absent from mac_tenant_map, so the flow
			// falls past the Amphora branch to the trie. Empty trie here,
			// so MISS stands in for the EXTERNAL a populated trie gives —
			// the point is that it left the direct-L2 branch at all.
			name: "ingress Amphora to routed peer skips the INFRA branch",
			src:  macAmphora, dst: macRouter,
			srcIP: net.IPv4(10, 0, 0, 10), dstIP: net.IPv4(8, 8, 8, 8),
			prog: bpf.ProgramIngress, wantDir: bpf.DirectionIngress, wantZone: bpf.ZoneMiss,
		},

		// — LPM-fallback path (peer not in map; trie empty → MISS) —
		{
			name: "ingress routed peer with empty trie → MISS",
			src:  macVMA, dst: macRouter,
			srcIP: net.IPv4(10, 0, 0, 1), dstIP: net.IPv4(8, 8, 8, 8),
			prog: bpf.ProgramIngress, wantDir: bpf.DirectionIngress, wantZone: bpf.ZoneMiss,
		},

		// — Unknown VM short-circuit (don't even look up peer) —
		{
			name: "ingress unknown vm_mac → MISS",
			src:  macUnknownVM, dst: macVMA,
			srcIP: net.IPv4(10, 0, 0, 99), dstIP: net.IPv4(10, 0, 0, 1),
			prog: bpf.ProgramIngress, wantDir: bpf.DirectionIngress, wantZone: bpf.ZoneMiss,
		},

		// — Group-destination MAC → MULTICAST (lachesis#150). Checked on
		//   the wire dst MAC before the trie, so a group frame never
		//   lands in MISS/EXTERNAL regardless of direction or IP family. —
		{
			// The revenue-leak-SLO bug: platform mDNS/SSDP received on a
			// provider-attached tap. On the egress hook the VM-side MAC is
			// the group dst, so pre-fix it missed mac_tenant_map → MISS.
			name: "egress received platform multicast → MULTICAST",
			src:  macPhysical, dst: macMcast,
			srcIP: net.IPv4(10, 0, 0, 50), dstIP: net.IPv4(239, 255, 255, 250),
			prog: bpf.ProgramEgress, wantDir: bpf.DirectionEgress, wantZone: bpf.ZoneMulticast,
		},
		{
			// VM-originated multicast tx: known VM source, group dst.
			// Pre-fix fell through the trie to the EXTERNAL catchall.
			name: "ingress VM-sent multicast → MULTICAST",
			src:  macVMA, dst: macMcast,
			srcIP: net.IPv4(10, 0, 0, 1), dstIP: net.IPv4(239, 255, 255, 250),
			prog: bpf.ProgramIngress, wantDir: bpf.DirectionIngress, wantZone: bpf.ZoneMulticast,
		},
		{
			name: "ingress broadcast (DHCP discover) → MULTICAST",
			src:  macVMA, dst: macBcast,
			srcIP: net.IPv4(0, 0, 0, 0), dstIP: net.IPv4(255, 255, 255, 255),
			prog: bpf.ProgramIngress, wantDir: bpf.DirectionIngress, wantZone: bpf.ZoneMulticast,
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

			zone, ok, err := bpfunit.FindZone(telMap, tc.src, tc.dst, tc.wantDir)
			if err != nil {
				t.Fatalf("find zone: %v", err)
			}
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
