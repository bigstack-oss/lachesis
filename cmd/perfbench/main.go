// Perfbench reports ns/packet for a loaded BPF program via
// BPF_PROG_TEST_RUN. The harness lives in [internal/perfbench];
// main is flag parsing + exit codes.
//
// Output modes:
//
//   - human: readable summary including packets/sec extrapolation (default)
//   - json: single-line object suitable for CI ingestion
//
// Must run on Linux with CAP_BPF. Use `task perfbench`, which wraps
// the privileged Docker invocation.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/bigstack-oss/lachesis/internal/perfbench"
	"github.com/bigstack-oss/lachesis/internal/testenv/bpfunit/fixtures"
)

func main() {
	cfg, output := parseFlags()

	r, err := perfbench.Run(cfg)
	if err != nil {
		fail("%v", err)
	}
	if err := perfbench.Emit(os.Stdout, output, r); err != nil {
		fail("%v", err)
	}
}

func parseFlags() (perfbench.Config, string) {
	var (
		repeat  = flag.Uint("repeat", 1_000_000, "number of program executions")
		output  = flag.String("output", "human", "output format: human|json")
		program = flag.String("program", fixtures.ProgNoopIn, "BPF program name to bench")
	)
	flag.Parse()
	return perfbench.Config{
		Repeat:  uint32(*repeat),
		Program: *program,
	}, *output
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "perfbench: "+format+"\n", args...)
	os.Exit(1)
}
