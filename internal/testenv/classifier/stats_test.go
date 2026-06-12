//go:build integration

// Verifies the telemetry_stats kernel counters end-to-end through
// BPF_PROG_TEST_RUN: a non-IP frame increments the skipped-ethertype
// slot, and a telemetry_map insert rejected by a full map increments
// the update-failure slot. Both paths must still return TC_ACT_OK —
// counting the loss never changes packet fate.
package classifier_test

import (
	"net"
	"testing"

	"github.com/cilium/ebpf/rlimit"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/testenv/bpfunit"
)

// Locally-administered MACs, distinct from the other classifier tests.
const (
	statsMacA uint64 = 0x02_00_00_00_BB_01
	statsMacB uint64 = 0x02_00_00_00_BB_02
	statsMacC uint64 = 0x02_00_00_00_BB_03
	statsMacD uint64 = 0x02_00_00_00_BB_04
)

// statsReader wires a bpf.StatsReader over the loaded collection,
// exercising the same reader path the agent's scrape drain uses.
func statsReader(t *testing.T, drv *bpfunit.Driver) *bpf.StatsReader {
	t.Helper()
	r, err := bpf.NewStatsReader(drv.Map(bpf.MapTelemetryStats))
	if err != nil {
		t.Fatalf("NewStatsReader: %v", err)
	}
	return r
}

func TestTelemetryStats_SkippedEthertype(t *testing.T) {
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
	stats := statsReader(t, drv)

	// ARP trips the non-IP ethertype gate; the counter is cumulative,
	// so a second run must land on 2, not stay at 1.
	frame := bpfunit.ARPFrame(bpfunit.MAC(statsMacA), bpfunit.MAC(statsMacB))
	for i := uint64(1); i <= 2; i++ {
		verdict, err := drv.Run(bpf.ProgramIngress, frame)
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if verdict != 0 {
			t.Errorf("run %d: verdict = %d, want 0 (TC_ACT_OK)", i, verdict)
		}
		counts, err := stats.Read()
		if err != nil {
			t.Fatalf("read stats: %v", err)
		}
		if got := counts[bpf.StatSkippedEthertype]; got != i {
			t.Errorf("run %d: skipped_ethertype = %d, want %d", i, got, i)
		}
		if got := counts[bpf.StatUpdateFailure]; got != 0 {
			t.Errorf("run %d: update_failure = %d, want 0", i, got)
		}
	}
}

func TestTelemetryStats_UpdateFailure(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("rlimit: %v", err)
	}
	spec, err := bpf.LoadTelemetry()
	if err != nil {
		t.Fatalf("load telemetry spec: %v", err)
	}
	// Shrink telemetry_map to a single entry before loading, so the
	// second distinct flow_key cannot be inserted (-E2BIG) — the same
	// condition a full 65,536-entry map produces in production.
	spec.Maps[bpf.MapTelemetry].MaxEntries = 1
	drv, err := bpfunit.New(spec)
	if err != nil {
		t.Fatalf("new driver: %v", err)
	}
	defer drv.Close()
	stats := statsReader(t, drv)

	// First flow occupies the only slot.
	frameA := bpfunit.EthIPv4TCP(
		bpfunit.MAC(statsMacA), bpfunit.MAC(statsMacB),
		net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), 12345, 80, nil,
	)
	if _, err := drv.Run(bpf.ProgramIngress, frameA); err != nil {
		t.Fatalf("run frameA: %v", err)
	}
	counts, err := stats.Read()
	if err != nil {
		t.Fatalf("read stats: %v", err)
	}
	if got := counts[bpf.StatUpdateFailure]; got != 0 {
		t.Fatalf("after first flow: update_failure = %d, want 0", got)
	}

	// Second flow has a distinct MAC pair, so a distinct flow_key the
	// full map rejects — once per packet, since the failed insert
	// leaves no entry for the retry to find.
	frameB := bpfunit.EthIPv4TCP(
		bpfunit.MAC(statsMacC), bpfunit.MAC(statsMacD),
		net.IPv4(10, 0, 0, 3), net.IPv4(10, 0, 0, 4), 12345, 80, nil,
	)
	for i := uint64(1); i <= 2; i++ {
		verdict, err := drv.Run(bpf.ProgramIngress, frameB)
		if err != nil {
			t.Fatalf("run frameB %d: %v", i, err)
		}
		if verdict != 0 {
			t.Errorf("run frameB %d: verdict = %d, want 0 (TC_ACT_OK)", i, verdict)
		}
		counts, err := stats.Read()
		if err != nil {
			t.Fatalf("read stats: %v", err)
		}
		if got := counts[bpf.StatUpdateFailure]; got != i {
			t.Errorf("run frameB %d: update_failure = %d, want %d", i, got, i)
		}
		if got := counts[bpf.StatSkippedEthertype]; got != 0 {
			t.Errorf("run frameB %d: skipped_ethertype = %d, want 0", i, got)
		}
	}
}
