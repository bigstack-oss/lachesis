// schema.go names the symbols in the noop test fixture
// (bpf/test_fixtures/noop.c) so callers reference a single const instead
// of re-typing the program / map names that must match the compiled
// object (mirrored by the generated noop_bpfel.go).

package fixtures

// ProgNoopIn is the entry-point program symbol of the noop fixture and
// MapRunCount is its per-run counter map. Both must match the SEC names
// in bpf/test_fixtures/noop.c.
const (
	ProgNoopIn  = "tc_noop_in"
	MapRunCount = "run_count"
)
