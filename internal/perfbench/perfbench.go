// Package perfbench measures the per-packet runtime of a BPF
// classifier program via BPF_PROG_TEST_RUN. cmd/perfbench is the
// CLI surface; this package owns the measurement + output formats
// so it can also be driven from CI ingestion or future Go-side
// benchmarks.
//
// Linux + CAP_BPF are required at runtime (BPF_PROG_TEST_RUN is a
// kernel syscall). The package itself is cross-platform — the
// kernel-touching call only happens inside [Run].
package perfbench

import (
	"encoding/json"
	"fmt"
	"io"
	"net"

	"github.com/cilium/ebpf/rlimit"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/testenv/bpfunit"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/testenv/bpfunit/fixtures"
)

// Config bundles the inputs to [Run].
type Config struct {
	// Repeat is the number of BPF_PROG_TEST_RUN executions to
	// average over.
	Repeat uint32
	// Program is the BPF program name to bench (entry-point symbol
	// from the noop fixture, e.g. "tc_noop_in").
	Program string
}

// Result is a single perfbench measurement. JSON tags expose the
// CI-ingestion shape.
type Result struct {
	Program   string `json:"program"`
	FrameSize int    `json:"frame_size_bytes"`
	Repeat    uint32 `json:"repeat"`
	TotalNs   int64  `json:"total_ns"`
	PerRunNs  int64  `json:"per_run_ns"`
}

// Run lifts the memlock rlimit, loads the noop fixture, and runs
// cfg.Program through BPF_PROG_TEST_RUN cfg.Repeat times. Returns
// the kernel-measured timing.
func Run(cfg Config) (Result, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return Result{}, fmt.Errorf("rlimit: %w", err)
	}

	spec, err := fixtures.LoadNoop()
	if err != nil {
		return Result{}, fmt.Errorf("load noop fixture: %w", err)
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

// Emit writes r to w in the named format. Unknown formats return
// an error rather than falling back to a default — CI parsers want
// a hard signal.
func Emit(w io.Writer, format string, r Result) error {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r); err != nil {
			return fmt.Errorf("encode: %w", err)
		}
		return nil
	case "human":
		return writeHuman(w, r)
	default:
		return fmt.Errorf("bad output format %q (want human|json)", format)
	}
}

// writeHuman writes r to w as a multi-line summary, including an
// extrapolated packets-per-second figure when per-run latency is
// measurable.
func writeHuman(w io.Writer, r Result) error {
	if _, err := fmt.Fprintf(w, "perfbench v0.1\n"); err != nil {
		return err
	}
	fmt.Fprintf(w, "  program:     %s\n", r.Program)
	fmt.Fprintf(w, "  frame size:  %d bytes\n", r.FrameSize)
	fmt.Fprintf(w, "  repeat:      %d\n", r.Repeat)
	fmt.Fprintf(w, "  total:       %d ns\n", r.TotalNs)
	if r.PerRunNs > 0 {
		fmt.Fprintf(w, "  per-run:     %d ns\n", r.PerRunNs)
		fmt.Fprintf(w, "  packets/sec: %.0f (extrapolated)\n", 1e9/float64(r.PerRunNs))
	} else {
		fmt.Fprintf(w, "  per-run:     0 ns — kernel clock resolution exceeds program runtime.\n")
		fmt.Fprintf(w, "               Increase Repeat (try 100_000_000) or run on native Linux.\n")
	}
	return nil
}
