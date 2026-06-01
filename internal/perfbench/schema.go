// schema.go holds package perfbench's pure-data Config / Result types and
// the output-format vocabulary. The measurement and emission logic (Run,
// Emit, writeHuman) lives in perfbench.go.

package perfbench

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

// Output-format names accepted by [Emit]. CI parsers depend on the
// exact spelling, so the switch and the flag default share these
// consts rather than open-coding the strings.
const (
	formatJSON  = "json"
	formatHuman = "human"
)
