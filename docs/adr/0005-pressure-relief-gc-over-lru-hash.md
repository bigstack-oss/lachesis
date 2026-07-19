# ADR 0005 — Pressure-relief GC over PERCPU_LRU_HASH

**Status:** accepted

## Context

The `telemetry_map` can fill. `BPF_MAP_TYPE_PERCPU_LRU_HASH` evicts the least-recently-used entry automatically when the map fills — no userspace GC needed, no map-full errors.

## Decision

Use plain `PERCPU_HASH` (no auto-eviction) plus a userspace pressure-relief GC that triggers above an 80% fill watermark, flushes each victim's bytes into GlobalState, and only *then* deletes the entry ([data-structures.md](../architecture/data-structures.md#kernel-side-bpf-maps)).

1. **LRU is silent data loss.** The kernel evicts entries between scrapes. If a long-running flow's entry is evicted at second 7 of a 10-second scrape window, the bytes accumulated up to that point are gone. We never see them.
2. **No way to flush before eviction.** LRU eviction is a one-step kernel operation; there is no "about to evict" hook.

## Consequences

- No bytes are ever lost to capacity pressure while the agent is running; map-full inserts that *do* fail are counted (`lachesis_bpf_update_failures_total{reason="update_failure"}`) rather than dropped silently.
- We own an eviction policy in userspace: watermark hysteresis, oldest-first by `last_seen_ns`, a per-pass cap bounding scrape stall to ~50 ms.
- Corollary: **never clear the map from userspace** — read-don't-clear is what makes crash recovery work ([boot-and-recovery.md](../architecture/boot-and-recovery.md)).

**When LRU_HASH is right:** approximate analytics where some loss is fine — flow sampling, hot-key detection, top-N tracking.
