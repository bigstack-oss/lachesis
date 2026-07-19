// Package perfbench measures the per-packet runtime of the telemetry
// classifier via BPF_PROG_TEST_RUN. It is driven by the per-packet
// ceiling gate in the package's integration test; there is no
// standalone binary.
//
// Linux + CAP_BPF are required at runtime (BPF_PROG_TEST_RUN is a
// kernel syscall). The package itself is cross-platform — the
// kernel-touching call only happens inside [Run].
package perfbench

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf/rlimit"

	"github.com/bigstack-oss/lachesis/internal/bpf"
	"github.com/bigstack-oss/lachesis/internal/testenv/bpfunit"
)

// Run lifts the memlock rlimit, loads the telemetry classifier, and
// runs cfg.Program through BPF_PROG_TEST_RUN cfg.Repeat times. Returns
// the kernel-measured timing. The maps load empty, so every packet
// takes the lookup-miss path — the measurement covers the parse plus
// the full lookup chain, not the mac-hit fast path.
func Run(cfg Config) (Result, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return Result{}, fmt.Errorf("rlimit: %w", err)
	}

	spec, err := bpf.LoadTelemetry()
	if err != nil {
		return Result{}, fmt.Errorf("load telemetry spec: %w", err)
	}
	drv, err := bpfunit.New(spec)
	if err != nil {
		return Result{}, fmt.Errorf("driver: %w", err)
	}
	defer drv.Close()

	frame := bpfunit.EthIPv4TCP(
		bpfunit.MAC(0xAABBCCDDEEFF),
		bpfunit.MAC(0x112233445566),
		net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2),
		12345, 80, nil,
	)

	total, perRun, err := drv.RunRepeat(cfg.Program, frame, cfg.Repeat)
	if err != nil {
		return Result{}, fmt.Errorf("run: %w", err)
	}

	return Result{
		Program:   cfg.Program,
		FrameSize: len(frame),
		Repeat:    cfg.Repeat,
		TotalNs:   total.Nanoseconds(),
		PerRunNs:  perRun.Nanoseconds(),
	}, nil
}
