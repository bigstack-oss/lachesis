# ADR 0007 — Custom prometheus.Collector over CounterVec

**Status:** accepted

## Context

`CounterVec` is the idiomatic Prometheus type for cumulative counters with labels; the client library handles all the bookkeeping.

## Decision

Implement `prometheus.Collector` directly: on `Collect()`, walk `GlobalState` (restored from the WAL on boot) and emit the cumulative values.

1. **`CounterVec` resets to zero on process restart.** The new process starts every counter at 0; Prometheus sees the value drop and `rate()` emits a *negative* spike.
2. **Negative `rate()` corrupts billing pipelines.** Anything downstream that integrates rate over time produces wrong totals. Some pipelines silently treat negative values as 0, others as the absolute value, others propagate `NaN`.
3. **No way to "preload" a CounterVec from disk.** The library has no public API for setting an initial value above 0.

## Consequences

- Cumulative continuity holds across restarts; the [consumption contract](../architecture/billing.md) (endpoint-sample subtraction) becomes exact.
- We own the emission path: `Collect()` must hold RLock for its whole iteration (Contract 2), allocate nothing per call, and emit live+settled sums under one lock snapshot (Contract 7).
