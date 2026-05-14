#!/usr/bin/env bash
# bench-gate.sh — enforce the zero-allocation contract for hot-path code.
#
# Convention: benchmarks named BenchmarkHotpath_* MUST report 0 allocs/op.
# When no BenchmarkHotpath_* benchmarks exist this gate is a dormant no-op.
#
# Rationale: hot-path allocations compound at the scrape rate and add
# latency tails that are expensive to diagnose in production. Catching
# them at PR time is much cheaper than at production diagnosis time.

set -euo pipefail

LOG=$(mktemp)
trap 'rm -f "$LOG"' EXIT

# -run='^$' disables non-bench tests so we don't pay test-setup cost.
# -count=1 prevents flake-averaging (allocations are deterministic).
# Scope: ./internal/... only.
GOWORK=off go test -bench='^BenchmarkHotpath_' -benchmem -run='^$' -count=1 ./internal/... 2>&1 | tee "$LOG"

# Standard `go test -bench -benchmem` row format:
#   BenchmarkHotpath_Foo-8   1000000   123 ns/op   0 B/op   0 allocs/op
# Match: ...{whitespace}{nonzero}{whitespace}allocs/op at end of line.
if grep -E '^BenchmarkHotpath_.*[[:space:]][1-9][0-9]*[[:space:]]+allocs/op$' "$LOG"; then
    echo
    echo "FAIL: zero-allocation contract violated by one or more BenchmarkHotpath_*" >&2
    echo "Hot-path code must allocate zero memory per call." >&2
    exit 1
fi

if grep -q '^BenchmarkHotpath_' "$LOG"; then
    echo "PASS: all BenchmarkHotpath_ benches at zero allocations"
else
    echo "PASS: no BenchmarkHotpath_ benches exist yet (gate dormant)"
fi
