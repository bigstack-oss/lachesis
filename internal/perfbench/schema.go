// schema.go holds package perfbench's pure-data Config and Result types.
// The measurement logic (Run) lives in perfbench.go.

package perfbench

// Config bundles the inputs to [Run].
type Config struct {
	// Repeat is the number of BPF_PROG_TEST_RUN executions to
	// average over.
	Repeat uint32
	// Program is the classifier entry-point symbol to bench:
	// "tc_telemetry_in" (ingress) or "tc_telemetry_out" (egress).
	Program string
}

// Result is a single perfbench measurement.
type Result struct {
	Program   string
	FrameSize int
	Repeat    uint32
	TotalNs   int64
	PerRunNs  int64
}
