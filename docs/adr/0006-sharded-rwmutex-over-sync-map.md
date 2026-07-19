# ADR 0006 — 64-shard RWMutex over sync.Map

**Status:** accepted

## Context

The metadata cache (`ShardedMetadataMap`) is read on every scrape aggregation and written on every reconcile pass. `sync.Map` is Go's lock-free concurrent map and avoids RWMutex contention.

## Decision

Shard a plain map 64 ways by `mac_uint64 & 63`, each shard under its own `sync.RWMutex`.

1. **`sync.Map` is read-optimized.** It's specifically tuned for "read-mostly, rare writes" workloads. We write on every reconcile pass — that's the dirty path. Under continuous mixed read/write, `sync.Map` performs *worse* than RWMutex.
2. **64-shard RWMutex is simple and fast.** Sharding distributes contention 64-way; each shard's RWMutex is uncontended for ~99% of operations.
3. **Predictable performance.** We can reason about lock contention. `sync.Map`'s internal `dirty`/`read` maps make latency harder to predict.

## Consequences

- Lock discipline is explicit and auditable (acquire late, release early, never across IO) — the Store archetype's contract ([development/conventions.md](../development/conventions.md#package-anatomy)).
- The value type must stay pointer-immutable (`*TenantMeta` pointer-replace, Contract 3) since readers hold no lock between lookup and use.
