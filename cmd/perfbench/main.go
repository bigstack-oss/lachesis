// Perfbench reports ns/packet for a loaded BPF program by driving it
// through BPF_PROG_TEST_RUN with a configurable repeat count.
//
// Output modes:
//
//   - human: readable summary including packets/sec extrapolation (default)
//   - json: single-line object suitable for CI ingestion
//
// Must run on Linux with CAP_BPF. Use `task perfbench`, which wraps
// the privileged Docker invocation.
//
// main is flag parsing + delegate; [bench] runs the measurement and
// [emit] formats the output.
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

// flags bundles the parsed CLI inputs.
type flags struct {
	repeat   uint
	output   string
	progName string
}

func main() {
	f := parseFlags()

	r, err := bench(f)
	if err != nil {
		fail("%v", err)
	}
	if err := emit(f.output, r); err != nil {
		fail("%v", err)
	}
}

func parseFlags() flags {
	var f flags
	flag.UintVar(&f.repeat, "repeat", 1_000_000, "number of program executions")
	flag.StringVar(&f.output, "output", "human", "output format: human|json")
	flag.StringVar(&f.progName, "program", "tc_noop_in", "BPF program name to bench")
	flag.Parse()
	return f
}

// bench runs the named BPF program f.repeat times via
// BPF_PROG_TEST_RUN and returns the kernel-measured timing.
func bench(f flags) (result, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return result{}, fmt.Errorf("rlimit: %w", err)
	}

	spec, err := fixtures.LoadNoop()
	if err != nil {
		return result{}, fmt.Errorf("load noop fixture: %w", err)
	}
	drv, err := bpfunit.New(spec)
	if err != nil {
		return result{}, fmt.Errorf("driver: %w", err)
	}
	defer drv.Close()

	frame := bpfunit.EthIPv4TCP(
		bpfunit.MAC(0xAABBCCDDEEFF),
		bpfunit.MAC(0x112233445566),
		net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2),
		12345, 80, nil,
	)

	total, perRun, err := drv.RunRepeat(f.progName, frame, uint32(f.repeat))
	if err != nil {
		return result{}, fmt.Errorf("run: %w", err)
	}

	return result{
		Program:   f.progName,
		FrameSize: len(frame),
		Repeat:    uint32(f.repeat),
		TotalNs:   total.Nanoseconds(),
		PerRunNs:  perRun.Nanoseconds(),
	}, nil
}

// emit writes r in the requested format to stdout. Unknown formats
// return an error rather than printing a default.
func emit(format string, r result) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r); err != nil {
			return fmt.Errorf("encode: %w", err)
		}
		return nil
	case "human":
		printHuman(r)
		return nil
	default:
		return fmt.Errorf("bad -output %q (want human|json)", format)
	}
}

// result is a single perfbench measurement, rendered as either
// human-readable text or JSON.
type result struct {
	Program   string `json:"program"`
	FrameSize int    `json:"frame_size_bytes"`
	Repeat    uint32 `json:"repeat"`
	TotalNs   int64  `json:"total_ns"`
	PerRunNs  int64  `json:"per_run_ns"`
}

// printHuman writes r to stdout as a multi-line summary, including
// an extrapolated packets-per-second figure when per-run latency is
// measurable.
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

// fail writes a prefixed error message to stderr and exits with status 1.
func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "perfbench: "+format+"\n", args...)
	os.Exit(1)
}
