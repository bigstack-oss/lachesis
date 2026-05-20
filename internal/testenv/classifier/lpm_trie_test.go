//go:build integration

// Verifies subnet_zone_trie LPM behaviour end-to-end through
// BPF_PROG_TEST_RUN: write entries via bpf.LpmKeyForPrefix, generate
// packets at known destinations, assert the resulting flow_key.dst_zone.
//
// The discriminating case is the /24 prefix — it exercises CIDR-prefix
// matching, which only works when the IP field's in-memory layout is
// network byte order. A regression to bpf_ntohl (or any host-order
// encoding) breaks /24 lookups silently; this test pins the contract.
package classifier_test

import (
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/testenv/bpfunit"
)

const trieTenantID uint32 = 7 // arbitrary; matches the value we write into mac_tenant_map below

// Locally-administered MACs. Reuse the existing test's vmA constant
// shape so the suite reads consistently.
const (
	trieMacVM     uint64 = 0x02_00_00_00_AA_01 // VM in tenantTrieID
	trieMacRouter uint64 = 0x02_00_00_00_FF_10 // not in mac_tenant_map; forces LPM fallback
)

func TestSubnetZoneTrie_LPMByteOrder(t *testing.T) {
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

	// VM is in tenantTrieID; the router peer is intentionally absent
	// from mac_tenant_map so every flow falls through to the LPM
	// trie (the path under test).
	macMap := drv.Map(bpf.MapMacTenant)
	if macMap == nil {
		t.Fatalf("%s not loaded", bpf.MapMacTenant)
	}
	k, v := trieMacVM, trieTenantID
	if err := macMap.Update(&k, &v, ebpf.UpdateAny); err != nil {
		t.Fatalf("populate mac_tenant_map: %v", err)
	}

	// Populate the trie with three entries covering the LPM regimes
	// we care about: /0 catchall, /24 CIDR, /32 exact.
	trie := drv.Map(bpf.MapSubnetZoneTrie)
	if trie == nil {
		t.Fatalf("%s not loaded", bpf.MapSubnetZoneTrie)
	}
	type trieRow struct {
		prefix string
		zone   bpf.ZoneCode
	}
	for _, r := range []trieRow{
		{"0.0.0.0/0", bpf.ZoneExternal},
		{"10.0.1.0/24", bpf.ZoneSameTenant},
		{"169.254.169.254/32", bpf.ZoneInfra},
	} {
		key := bpf.LpmKeyForPrefix(trieTenantID, netip.MustParsePrefix(r.prefix))
		zone := uint8(r.zone)
		if err := trie.Update(&key, &zone, ebpf.UpdateAny); err != nil {
			t.Fatalf("trie update %s: %v", r.prefix, err)
		}
	}

	telMap := drv.Map(bpf.MapTelemetry)
	if telMap == nil {
		t.Fatalf("%s not loaded", bpf.MapTelemetry)
	}

	cases := []struct {
		name     string
		dstIP    net.IP
		wantZone bpf.ZoneCode
	}{
		// /24 — THE discriminating case. Requires network-byte-order
		// IP layout in lk.ip. With a buggy bpf_ntohl in the kernel,
		// the trie walks the IP LSB-first and "10.0.1.0/24" never
		// matches 10.0.1.42 — this test would fail.
		{"in /24 hits SAME_TENANT", net.IPv4(10, 0, 1, 42), bpf.ZoneSameTenant},
		{"adjacent /24 misses, falls to catchall", net.IPv4(10, 0, 2, 1), bpf.ZoneExternal},
		// /32 — also exercises full-IP match. Passes under either
		// encoding because all 32 bits get compared; included so a
		// future regression that breaks /32 too is caught.
		{"169.254.169.254/32 hits INFRA", net.IPv4(169, 254, 169, 254), bpf.ZoneInfra},
		// /0 — catchall. Passes when only tenant_id matches; the IP
		// portion is wildcarded. Tests that the catchall row is
		// reachable.
		{"unrelated IP hits EXTERNAL catchall", net.IPv4(8, 8, 8, 8), bpf.ZoneExternal},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			frame := bpfunit.EthIPv4TCP(
				bpfunit.MAC(trieMacVM), bpfunit.MAC(trieMacRouter),
				net.IPv4(10, 0, 0, 5), tc.dstIP, 12345, 80, nil,
			)
			verdict, err := drv.Run(bpf.ProgramIngress, frame)
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			if verdict != 0 {
				t.Errorf("verdict = %d, want 0 (TC_ACT_OK)", verdict)
			}
			zone, ok, err := bpfunit.FindZone(telMap, trieMacVM, trieMacRouter, bpf.DirectionIngress)
			if err != nil {
				t.Fatalf("find zone: %v", err)
			}
			if !ok {
				t.Fatalf("no telemetry_map entry for dst=%s", tc.dstIP)
			}
			if zone != tc.wantZone {
				t.Errorf("dst_zone for %s = %d, want %d", tc.dstIP, zone, tc.wantZone)
			}
			// Drain the entry so the next case starts clean. The
			// flow_key includes dst_zone, so naturally-distinct keys
			// would also work — but explicit drain keeps the test
			// independent of that detail.
			if err := bpfunit.DrainTelemetryByMACs(telMap, trieMacVM, trieMacRouter); err != nil {
				t.Fatalf("drain telemetry_map: %v", err)
			}
		})
	}
}
