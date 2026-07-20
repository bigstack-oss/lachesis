# Boot Sequence & Crash Resilience

Boot order is load-bearing: several orderings that "mostly work" produce
permanently-misclassified flows or double-counting. This chapter defines the
sequence, the sync mechanism that enforces it, the outage policies, and what
survives each kind of crash.

## Boot sequence

```
1. Zombie Hunter
   → delete orphaned tc_telemetry_in/out filters from a previous crash

2. Load eBPF objects
   → including subnet_zone_trie and mac_tenant_map specs
   → the counter-bearing maps (telemetry_map, telemetry_stats) are
     pinned under bpf.pin_path and reused when a compatible pin
     survives (agent-crash zero-loss recovery below); the metadata
     maps are rebuilt by cold-start, so they are not pinned

3. Cold-start metadata via Neutron API
   → populate ShardedMetadataMap
   → populate mac_tenant_map (full device_owner filter set:
     compute:*, network:router_interface, network:router_gateway;
     see data-structures.md)
   → populate subnet_zone_trie (five-step algorithm,
     trie-construction.md)

4. Wire the Netlink subscriber (attach allowlist → TC programs)
   → TC attach is netlink-driven: the subscriber subscribes with
     kernel replay of existing links (ListExisting), attaching TC
     clsact and filling the Interface Registry; later RTM_NEWLINK
     events attach new taps dynamically. The Registry deduplicates
     attach attempts; genuine FilterReplace idempotence additionally
     requires the explicit filter priority that
     `tcattach.FilterPriority` pins — at priority 0 the kernel
     allocates a new chain per call, so every re-attach would stack
     another filter copy and double-count.

5. Read WAL → restore GlobalState (live rows + settled accumulator)

6. Start the Run workers, one goroutine each, from the drain-ordered
   workers() table:

     netlink subscriber   (performs step 4's attach sweep)
     ghost sweeper        (awaits StateRestored)
     kafka consumer       (awaits StateRestored)
     reconciler           (awaits StateRestored; 5-min timer + kicks)
     scraper              (first BatchLookup merges kernel deltas
                           against the WAL-restored LastEbpfRaw)
     WAL flusher

   The /metrics + /debug HTTP listener is opened during construction
   and served alongside them.
```

**How the order is enforced.** Steps 1–5 run straight-line inside `Bootstrap`
(`internal/agent/bootstrap_linux.go`), advancing `boot.Sequencer` phases
`BPFLoaded → MetadataReady → Attached → StateRestored`; the sequencer validates
step-by-one order and logs each transition. Step 6's workers start in
`Agent.Run` via the `workers()` table, and every worker that mutates kernel or
GlobalState state — the ghost sweeper, the Kafka consumer, the reconciler —
**blocks on `Sequencer.Await(PhaseStateRestored)` before its first action**, so
no eviction, kick, or kernel write can race the restore even though the workers
are separate goroutines. This is [Contract 4](./contracts.md#required-contracts).

### Failure modes if order is violated

| Skip / reorder | Consequence |
|---|---|
| TC attach before trie populated | First flows permanently keyed `dst_zone=MISS`; never reclassify (zone is baked into the kernel flow key) |
| GC before WAL merge | Active flows evicted before `LastEbpfRaw` set → counter spike on next scrape |
| Initial attach sweep before netlink subscribe | A tap created in the gap is never attached → silent undercount. Subscribe-with-replay closes the gap; the Interface Registry + pinned filter priority (step 4) make the replay/event overlap harmless |
| Skip Zombie Hunter | Restart stacks duplicate filters → every packet counted twice |

## Failure policy — Neutron API and Kafka outages

**Neutron API unreachable at cold-start** (step 3 cannot complete):
- Block with exponential backoff (start 1s, cap at 30s, indefinite retries).
- State surfaced via `lachesis_neutron_sync_age_seconds=-1` (never synced) and `lachesis_neutron_api_errors_total{endpoint, code}`.
- **Do NOT proceed to step 4 (TC attach).** Without metadata, every packet classifies as `ZONE_MISS`, and once that miss is written into the kernel `flow_key` it is permanent. Blocking at boot is the only correctness-safe policy.
- An explicit `--unsafe-allow-degraded-boot` flag may be added later for operators who want fail-open behavior during planned Neutron upgrades; default is fail-closed.

**Neutron API unreachable at runtime** (cold-start succeeded, reconcile fails):
- Continue serving from the in-memory snapshot.
- Each failed call increments `lachesis_neutron_api_errors_total{endpoint, code}` and ages `lachesis_neutron_sync_age_seconds`.
- When Kafka is available each committed change kicks a reconcile within one pass; the 5-minute periodic reconcile is the safety net (below). Both run on the one reconciler goroutine, so a kick and a timer tick never apply concurrently.

**Kafka unreachable** (cold-start succeeded, then Kafka becomes unreachable):
- No more kicks arrive, so the agent's metadata becomes increasingly stale: new VMs miss in `mac_tenant_map` → land in the UnresolvedBuffer; deleted VMs over-stay their 60s ghost; route changes don't apply.
- **The periodic 5-minute reconcile mitigates this.** It is the same pass a kick triggers — a full snapshot fetch diffed against current state, applying only the delta ([trie-construction.md](./trie-construction.md#incremental-updates)). **Bounds metadata staleness to 5 minutes regardless of Kafka availability.**
- `lachesis_kafka_lag_messages` and `lachesis_kafka_consume_errors_total` surface the outage; alerting threshold suggested: `lag > 1000` sustained.

**Partial Neutron failures** (e.g., `GET /v2.0/ports` succeeds, `GET /v2.0/routers` returns 500):
- **Cold-start is all-or-nothing.** If any required endpoint fails, the entire cold-start fails and the boot loop retries from the top. Starting with partial metadata reproduces the same permanent-miss problem as a full Neutron outage.
- **Runtime reconcile is best-effort per endpoint.** A 500 on one endpoint doesn't invalidate state derived from successfully-fetched endpoints; the per-endpoint error counter tracks recovery. The next reconcile cycle retries the failed endpoint.

## Crash resilience

### Agent crash (process killed, kernel intact)

**Zero-loss (map pinning, implemented):**
- The counter-bearing maps (`telemetry_map`, `telemetry_stats`) are pinned under `bpf.pin_path` → they survive the process. The two metadata maps are deliberately *not* pinned; cold-start (step 3) rebuilds them before attach, so pinning them would buy no billing continuity.
- Across the crash gap the orphaned TC filters keep the old program counting into the pinned `telemetry_map`; the boot-time Zombie Hunter (step 1) then detaches them, but the bpffs pin holds the map alive independently of any filter/program refcount — so hunt-then-reuse cannot destroy it, and the two steps need no ordering constraint between them.
- The new agent reuses the pinned maps, reads the [WAL](./primer.md#write-ahead-log) → restores GlobalState (cumulative counters and the settled-bytes accumulator), and the first BatchLookup merges the surviving kernel counters against the WAL-restored `LastEbpfRaw` (`current ≥ lastRaw`, so the delta is exact).
- **Net data loss: 0.**

**Stale pin after a map-ABI change:** a pinned map whose sizing/type no longer matches the current build is never adopted (`MapSpec.Compatible` rejects it) — it is removed and recreated fresh, self-healing across the bump. That boot's crash recovery is skipped, but classification stays correct.

**Fallback (unpinned):** if pinning cannot be established — e.g. `bpf.pin_path` is not on a mounted bpf filesystem — the agent **refuses to boot** unless `bpf.unsafe_allow_unpinned_maps=true`, in which case it loads fresh unpinned maps and recovers from the WAL exactly like the hard-reboot path below (the `current < lastRaw` delta guard absorbs the empty map). **Net data loss then: ≤60s (the WAL flush window)** — agent crash and hard reboot share one recovery path. The `lachesis_bpf_maps_pinned` gauge (1 = pinned/zero-loss, 0 = unpinned/degraded) surfaces which path is live.

### Hard reboot (kernel destroyed)

- Kernel RAM gone → map starts empty.
- Delta math handles this: `current < last → treat current as fresh absolute`.
- WAL gives us up-to-60s-old GlobalState.
- **Net data loss: ≤60s of bytes** (the WAL flush window).

### Why not `BPF_MAP_TYPE_PERCPU_LRU_HASH`?

LRU silently evicts entries between scrapes. Bytes accumulated on an evicted entry are lost forever — unrecoverable. Pressure-relief GC (in Go) flushes to GlobalState **before** evicting, so the bytes survive. See [ADR 0005](../adr/0005-pressure-relief-gc-over-lru-hash.md).

### Why not Prometheus `CounterVec`?

`CounterVec` resets to zero on process restart. Restart emits a lower cumulative value, `rate()` goes negative, billing dashboards break. The custom `prometheus.Collector` emits from GlobalState (loaded from WAL), so cumulative continuity holds across restarts. See [ADR 0007](../adr/0007-custom-collector-over-countervec.md).

---

Next: [performance.md](./performance.md) →
