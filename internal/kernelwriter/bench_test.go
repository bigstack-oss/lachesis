//go:build integration

// Kernel hot-path microbenchmarks for lookup_zone via
// BPF_PROG_TEST_RUN. Measures the LPM-hit path (single trie
// lookup) and the sentinel-fallback path (two trie lookups);
// the delta is the cost of the trie-dedup rekey + extra
// bpf_map_lookup_elem.
//
// Integration-tagged because BPF_PROG_TEST_RUN requires a real
// Linux kernel. Run via the privileged Docker harness:
//
//	docker run --rm --privileged --platform linux/amd64 -u 0 \
//	    -v "$(pwd)":/app -w /app -e GOWORK=off ebpf-builder \
//	    sh -c "go test -tags integration -bench=BenchmarkHotpath_Lpm \
//	        -run=^$ -benchmem ./internal/kernelwriter/"
//
// The reported ns/op is kernel-measured (RunRepeat amortizes
// Go-side dispatch across the b.N kernel iterations).
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

// BenchmarkHotpath_LpmHit times the single-lookup routed path:
// the destination IP falls inside a per-tenant SAME_TENANT row,
// so the first LPM lookup at (vm_tid, dst_ip) hits and the
// sentinel fallback never runs.
func BenchmarkHotpath_LpmHit(b *testing.B) {
	runLookupBench(b, net.IPv4(10, 0, 1, 99))
}

// BenchmarkHotpath_LpmFallback times the two-lookup routed path:
// the destination IP misses every per-tenant row, so the first
// LPM lookup at (vm_tid, dst_ip) misses and the sentinel
// fallback at (tenant_id=0, dst_ip) hits the catchall row.
//
// Delta(LpmFallback - LpmHit) is the cost of the extra
// bpf_map_lookup_elem on the sentinel rekey. Budget: <50 ns
// (docs/DESIGN.md §11, per-packet cost).
func BenchmarkHotpath_LpmFallback(b *testing.B) {
	runLookupBench(b, net.IPv4(8, 8, 8, 8))
}

func runLookupBench(b *testing.B, dstIP net.IP) {
	b.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		b.Fatalf("rlimit: %v", err)
	}
	spec, err := bpf.LoadTelemetry()
	if err != nil {
		b.Fatalf("load telemetry: %v", err)
	}
	drv, err := bpfunit.New(spec)
	if err != nil {
		b.Fatalf("new driver: %v", err)
	}
	defer drv.Close()

	snap := metadata.New()
	snap.Insert(macVMA, &metadata.TenantMeta{ProjectID: projA})
	interner := metadata.NewTenantInterner()
	if _, err := kernelwriter.WriteMacTenantMap(drv.Map(bpf.MapMacTenant), snap, interner); err != nil {
		b.Fatalf("WriteMacTenantMap: %v", err)
	}
	entries := []neutron.TrieEntry{
		{TenantID: "", Prefix: netip.MustParsePrefix("0.0.0.0/0"), Zone: bpf.ZoneExternal},
		{TenantID: projA, Prefix: netip.MustParsePrefix("10.0.1.0/24"), Zone: bpf.ZoneSameTenant},
	}
	if _, err := kernelwriter.WriteSubnetZoneTrie(drv.Map(bpf.MapSubnetZoneTrie), entries, interner); err != nil {
		b.Fatalf("WriteSubnetZoneTrie: %v", err)
	}

	frame := bpfunit.EthIPv4TCP(
		bpfunit.MAC(macVMA), bpfunit.MAC(macRtr),
		net.IPv4(10, 0, 1, 1), dstIP, 12345, 80, nil,
	)

	b.ReportAllocs()
	b.ResetTimer()
	_, perRun, err := drv.RunRepeat(bpf.ProgramIngress, frame, uint32(b.N))
	if err != nil {
		b.Fatalf("RunRepeat: %v", err)
	}
	// Override the default wall-clock ns/op with the kernel-
	// measured per-run time when the kernel clock has the
	// resolution to report a non-zero value. Skipped on hosts
	// where the kernel rounds to 0 ns (notably macOS Docker
	// virtualization); on those hosts the bench framework's
	// wall-clock reading takes over. b.ReportMetric(0, ...)
	// would suppress the metric entirely.
	if perRun > 0 {
		b.ReportMetric(float64(perRun.Nanoseconds()), "ns/op")
	}
}
