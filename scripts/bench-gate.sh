#!/usr/bin/env bash
# bench-gate.sh — enforce the zero-allocation contract for hot-path code.
#
# Convention: benchmarks named BenchmarkHotpath_* MUST report 0 allocs/op.
# When no BenchmarkHotpath_* benchmarks exist this gate is a dormant no-op.
#
# Usage: bench-gate.sh [build-tags]
#   No argument gates the untagged BenchmarkHotpath_* — the pure-Go hot
#   paths that build on any host (the bench-gate CI job runs this).
#   Pass a build tag (e.g. "integration") to gate the tag-gated benches
#   instead; those exercise the kernel via BPF_PROG_TEST_RUN and must run
#   under privileged Docker (the integration CI job runs this).
#
# Rationale: hot-path allocations compound at the scrape rate and add
# latency tails that are expensive to diagnose in production. Catching
# them at PR time is much cheaper than at production diagnosis time.

set -euo pipefail

TAGS="${1:-}"

LOG=$(mktemp)
trap 'rm -f "$LOG"' EXIT

# -run='^$' disables non-bench tests so we don't pay test-setup cost.
# -count=1 prevents flake-averaging (allocations are deterministic).
# Scope: ./internal/... only. Two spellings rather than an array so the
# empty-tags case is safe under bash 3.2 + set -u (macOS default shell).
if [ -n "$TAGS" ]; then
    GOWORK=off go test -tags "$TAGS" -bench='^BenchmarkHotpath_' -benchmem -run='^$' -count=1 ./internal/... 2>&1 | tee "$LOG"
else
    GOWORK=off go test -bench='^BenchmarkHotpath_' -benchmem -run='^$' -count=1 ./internal/... 2>&1 | tee "$LOG"
fi

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
    echo "PASS: all BenchmarkHotpath_ benches at zero allocations${TAGS:+ (tags: $TAGS)}"
else
    echo "PASS: no BenchmarkHotpath_ benches exist yet (gate dormant)${TAGS:+ (tags: $TAGS)}"
fi
