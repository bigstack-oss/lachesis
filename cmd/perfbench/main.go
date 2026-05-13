// perfbench reports ns/packet for a loaded BPF program by driving it through
// BPF_PROG_TEST_RUN with a configurable repeat count.
//
// Currently bound to the noop fixture. Sprint 1+ will add a -fixture flag
// to point at the real classifier once it exists.
//
// Output modes:
//   - human (default): readable summary including packets/sec extrapolation
//   - json:            single-line object suitable for CI ingestion
//
// Must run on Linux with CAP_BPF (use `task perfbench`, which wraps the
// privileged Docker invocation).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/cilium/ebpf/rlimit"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/testenv/bpfunit"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/testenv/bpfunit/fixtures"
)

func main() {
	repeat := flag.Uint("repeat", 1_000_000, "number of program executions")
	output := flag.String("output", "human", "output format: human|json")
	progName := flag.String("program", "tc_noop_in", "BPF program name to bench")
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		fail("rlimit: %v", err)
	}

	spec, err := fixtures.LoadNoop()
	if err != nil {
		fail("load noop fixture: %v", err)
	}
	drv, err := bpfunit.New(spec)
	if err != nil {
		fail("driver: %v", err)
	}
	defer drv.Close()

	frame := bpfunit.EthIPv4TCP(
		bpfunit.MAC(0xAABBCCDDEEFF),
		bpfunit.MAC(0x112233445566),
		net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2),
		12345, 80, nil,
	)

	total, perRun, err := drv.RunRepeat(*progName, frame, uint32(*repeat))
	if err != nil {
		fail("run: %v", err)
	}

	r := result{
		Program:   *progName,
		FrameSize: len(frame),
		Repeat:    uint32(*repeat),
		TotalNs:   total.Nanoseconds(),
		PerRunNs:  perRun.Nanoseconds(),
	}

	switch *output {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r); err != nil {
			fail("encode: %v", err)
		}
	case "human":
		printHuman(r)
	default:
		fail("bad -output %q (want human|json)", *output)
	}
}

type result struct {
	Program   string `json:"program"`
	FrameSize int    `json:"frame_size_bytes"`
	Repeat    uint32 `json:"repeat"`
	TotalNs   int64  `json:"total_ns"`
	PerRunNs  int64  `json:"per_run_ns"`
}

func printHuman(r result) {
	fmt.Printf("perfbench v0.1\n")
	fmt.Printf("  program:     %s\n", r.Program)
	fmt.Printf("  frame size:  %d bytes\n", r.FrameSize)
	fmt.Printf("  repeat:      %d\n", r.Repeat)
	fmt.Printf("  total:       %d ns\n", r.TotalNs)
	if r.PerRunNs > 0 {
		fmt.Printf("  per-run:     %d ns\n", r.PerRunNs)
		fmt.Printf("  packets/sec: %.0f (extrapolated)\n", 1e9/float64(r.PerRunNs))
	} else {
		fmt.Printf("  per-run:     0 ns — kernel clock resolution exceeds program runtime.\n")
		fmt.Printf("               Increase -repeat (try 100_000_000) or run on native Linux.\n")
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "perfbench: "+format+"\n", args...)
	os.Exit(1)
}
