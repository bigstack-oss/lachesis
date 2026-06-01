//go:build integration

package bpfunit_test

import (
	"net"
	"testing"

	"github.com/cilium/ebpf/rlimit"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/testenv/bpfunit"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/testenv/bpfunit/fixtures"
)

func TestDriver_RunNoop(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("rlimit: %v", err)
	}

	spec, err := fixtures.LoadNoop()
	if err != nil {
		t.Fatalf("load noop spec: %v", err)
	}
	drv, err := bpfunit.New(spec)
	if err != nil {
		t.Fatalf("new driver: %v", err)
	}
	defer drv.Close()

	frame := bpfunit.EthIPv4TCP(
		bpfunit.MAC(0xAABBCCDDEEFF),
		bpfunit.MAC(0x112233445566),
		net.IPv4(10, 0, 0, 1),
		net.IPv4(10, 0, 0, 2),
		12345, 80, nil,
	)

	verdict, err := drv.Run(fixtures.ProgNoopIn, frame)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if verdict != 0 {
		t.Errorf("verdict = %d, want 0 (TC_ACT_OK)", verdict)
	}

	m := drv.Map(fixtures.MapRunCount)
	if m == nil {
		t.Fatal("run_count map not loaded")
	}
	var key uint32 = 0
	var val uint64
	if err := m.Lookup(&key, &val); err != nil {
		t.Fatalf("map lookup: %v", err)
	}
	if val != 1 {
		t.Errorf("counter = %d, want 1", val)
	}
}

func TestDriver_RunRepeat(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("rlimit: %v", err)
	}

	spec, err := fixtures.LoadNoop()
	if err != nil {
		t.Fatalf("load noop spec: %v", err)
	}
	drv, err := bpfunit.New(spec)
	if err != nil {
		t.Fatalf("new driver: %v", err)
	}
	defer drv.Close()

	frame := bpfunit.EthIPv4TCP(
		bpfunit.MAC(0xAABBCCDDEEFF),
		bpfunit.MAC(0x112233445566),
		net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2),
		12345, 80, nil,
	)

	const count = 100_000
	total, perRun, err := drv.RunRepeat(fixtures.ProgNoopIn, frame, count)
	if err != nil {
		t.Fatalf("run repeat: %v", err)
	}
	// Timing is environment-dependent (Rosetta/QEMU emulation can report
	// near-zero); the correctness signal is the counter check below.
	t.Logf("noop x%d: total=%v per-run=%v", count, total, perRun)

	m := drv.Map(fixtures.MapRunCount)
	var key uint32 = 0
	var val uint64
	if err := m.Lookup(&key, &val); err != nil {
		t.Fatalf("map lookup: %v", err)
	}
	if val != count {
		t.Errorf("counter = %d, want %d", val, count)
	}
}

func TestDriver_NonIP_PassesThrough(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("rlimit: %v", err)
	}

	spec, err := fixtures.LoadNoop()
	if err != nil {
		t.Fatalf("load noop spec: %v", err)
	}
	drv, err := bpfunit.New(spec)
	if err != nil {
		t.Fatalf("new driver: %v", err)
	}
	defer drv.Close()

	frame := bpfunit.ARPFrame(
		bpfunit.MAC(0xAABBCCDDEEFF),
		bpfunit.MAC(0xFFFFFFFFFFFF),
	)
	verdict, err := drv.Run(fixtures.ProgNoopIn, frame)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if verdict != 0 {
		t.Errorf("verdict = %d, want 0 (TC_ACT_OK) for ARP frame", verdict)
	}
}
