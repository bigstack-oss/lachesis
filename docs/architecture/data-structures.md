# Data Structures

The kernel counts; userspace attributes, accumulates, and persists. This chapter
defines every load-bearing structure on that path: the three BPF maps, the Go
agent's stores, and the two lifecycle mechanisms (Lingering Ghost, settled bytes)
that keep attribution correct while metadata churns.

## Kernel-side BPF maps

### `telemetry_map` — the byte/packet counter

```
Type:        BPF_MAP_TYPE_PERCPU_HASH    ← see primer, PERCPU_HASH
Max entries: 65,536  (compile-time constant, internal/bpf/schema.go)
Pinning:     PinByName under bpf.pin_path — the counter-bearing maps
             (telemetry_map, telemetry_stats) are pinned so they survive
             an agent crash and a restarted agent reuses them for
             zero-loss recovery (contracts.md, deferred item 7 — shipped;
             boot-and-recovery.md#agent-crash-process-killed-kernel-intact)

KEY:   struct flow_key  (16 bytes, packed)
   ┌──────────────────────────────────────────────────────────────────┐
   │ src_mac    [6]u8                                                 │
   │ dst_mac    [6]u8                                                 │
   │ eth_proto  u16   (0x0800 IPv4 / 0x86DD IPv6)                     │
   │ direction  u8    (0=VM sending, 1=VM receiving)                  │
   │ dst_zone   u8    (0=ext 1=same 2=other 3=infra 4=miss 5=shared   │
   │                   6=multicast)                                   │
   └──────────────────────────────────────────────────────────────────┘

VALUE: struct flow_metrics  (24 bytes, one slot per CPU)
   ┌──────────────────────────────────────────────────────────┐
   │ bytes        u64                                         │
   │ packets      u64                                         │
   │ last_seen_ns u64  (CLOCK_MONOTONIC, matches Go side)     │
   └──────────────────────────────────────────────────────────┘
```

**Why [PERCPU](./primer.md#percpu_hash).** At 10 Gbps × 32 cores, a global hash with `__sync_fetch_and_add` becomes the bottleneck — atomic contention dominates. PERCPU eliminates contention; each CPU has its own slot, no atomics needed once the entry exists.

**Pressure-relief GC.** Capacity is recovered by a userspace pass that flushes bytes to GlobalState *before* deleting the map entry (never the other way around — see [boot-and-recovery.md](./boot-and-recovery.md)). Trigger and bounds:

- Fill ratio sampled at the start of each scrape (every 10s by default).
- Above the **high watermark** (default **80%**), run pressure-relief in the same goroutine as the scrape, after the BatchLookup completes. Relief then runs on every scrape until fill falls back below the **low watermark** (default **75%**) — a hysteresis, so the map settles near the low watermark rather than oscillating at the high one.
- Eviction order: oldest by `last_seen_ns` first.
- **Per-pass cap: 1,000 entries** (default). Bounds the worst-case stall to ~50 ms (≈50 µs/entry × 1,000) regardless of how full the map is.
- **Algorithm: single-pass scan with a bounded size-K heap** (K = the per-pass cap) to select the oldest-K by `last_seen_ns`. The heap is ordered *max*-by-`last_seen_ns`, so the newest of the K candidates retained so far sits at the root and is evicted in favour of an older flow as the scan proceeds. Cost is O(N log K) where N is the current entry count. For N=52k (80% fill), this is ~50 ms — included in the per-pass budget. A naïve full sort (O(N log N)) would be ~200 ms; avoid it.
- Floor: the low watermark (default **75%**). One pass evicts ~3,250 entries to reach the floor; the cap kicks in first, so the floor is reached over 3–4 successive scrapes — still well under a minute.
- Each pass increments `lachesis_gc_pressure_relief_runs_total` and `lachesis_gc_evictions_total{reason="pressure_relief"}` ([metrics.md](./metrics.md)).
- The two watermarks and the per-pass cap are operator-tunable via the `gc:` config section and **hot-reloadable on SIGHUP** — see [runtime tuning](../operations/runtime.md) for the mechanism and the full hot set. The high watermark is validated `< 1.0`: at 1.0 the map fills and the kernel drops counters on its own, the exact byte loss this GC prevents.

If the map sustains >80% fill across many scrapes despite the GC, the deployment has outgrown the configured `max_entries` and the operator must rebuild with a larger value — surfaced via the map-entry gauges before it becomes a billing problem.

**Why MAC-pair, not 5-tuple.** MAC-pair scales with topology (~850 entries on a 50-VM node). 5-tuple scales with connection count and explodes both the map and downstream Prometheus labels. Detailed comparison in [ADR 0004](../adr/0004-mac-pair-flow-key-over-5-tuple.md).

**Why `dst_zone` is in the key.** When VM-A in subnet-1 sends to VM-B in subnet-2 via the tenant router, the L2 destination MAC at VM-A's tap is the router's MAC — *identical* to VM-A talking to the internet via the same router. Without an L3 classification baked into the key, the four billing categories collapse into one ambiguous bucket. `dst_zone` is the L3 tiebreaker, populated by an in-kernel [LPM lookup](./primer.md#lpm-trie).

### `subnet_zone_trie` — the L3 zone resolver

```
Type:        BPF_MAP_TYPE_LPM_TRIE       ← see primer, LPM Trie
Max entries: 16,384  (compile-time constant)
Flags:       BPF_F_NO_PREALLOC

KEY:   struct lpm_key
   ┌──────────────────────────────────────────────────────────┐
   │ prefixlen  u32   (bits in tenant_id ++ ip)               │
   │ tenant_id  u32   (always exact-matched, 32 bits)         │
   │ ip         u32   (network byte order in memory, IPv4)    │
   └──────────────────────────────────────────────────────────┘

The `ip` field stores the IPv4 address in **network byte order** in
memory (MSB at the lowest address). The kernel LPM trie walks key
data byte-by-byte, MSB-first within each byte, so for CIDR matching
to work the IPv4's leading octet (the "10" in `10.0.1.x`) must
appear at the lowest byte address of the `ip` field. Both sides
preserve wire order: the C path assigns `lk.ip = remote_ip_be` (no
`ntohl`), the Go path uses `bpf.LpmKeyForPrefix` which encodes via
`binary.NativeEndian.Uint32(addr.As4())`. cilium/ebpf serialises
the struct via host-layout memcpy, so kernel and userspace end up
with the same byte pattern regardless of host endianness.

VALUE: u8  zone code  (one of ZONE_EXTERNAL, ZONE_SAME_TENANT,
                      ZONE_OTHER_TENANT, ZONE_INFRA, ZONE_MISS,
                      ZONE_SHARED — emission rules in
                      trie-construction.md. ZONE_MULTICAST is set by
                      the kernel from the destination MAC, never
                      written to this trie.)

Insertion examples:
  Catchall for tenant 1001:
    {prefixlen=32, tenant_id=1001, ip=0}             → ZONE_EXTERNAL
  /24 subnet for tenant 1001:
    {prefixlen=56, tenant_id=1001, ip=10.0.1.0}      → ZONE_SAME_TENANT
  /24 subnet on a SHARED network (any tenant's view):
    {prefixlen=56, tenant_id=1001, ip=192.168.0.0}   → ZONE_SHARED
  Single-host /32 (e.g., metadata svc):
    {prefixlen=64, tenant_id=1001, ip=169.254.169.254} → ZONE_INFRA
```

**Why `(tenant_id, ip)` and not just `ip`.** Two tenants can have the same CIDR (e.g., both register `10.0.1.0/24`). Zone is **always relative to the source VM's tenant** — `10.0.1.0/24` may be `SAME_TENANT` for tenant 1001 and `OTHER_TENANT` for tenant 1002. Scoping the key by `tenant_id` makes both views coexist in one trie.

**Global-row dedup via the `tenant_id=0` sentinel.** The naïve per-tenant emission of the [five-step cold-start algorithm](./trie-construction.md#the-five-step-algorithm) replicates every *global* row (catchall, metadata /32, shared subnets, infra IPs) once per tenant:

```
  total_entries  =  |T| × (2 + |shared| + |infra|)  +  Σ_t |owned(t)|
```

Empirically on a 27-tenant single-host OVN deployment that was 9,270 entries — **~96% of trie occupancy was per-tenant replication of identical global rows** — and at realistic production tenant counts (≥200) the model overflows the 16,384 cap and hard-fails at boot via `bpf.ValidateMapSizes`. The implemented shape therefore stores catchall / INFRA / SHARED rows **once**, under sentinel `tenant_id=0`, read with a fallback `bpf_map_lookup_elem` on first-lookup miss. Picked over a split-map alternative (`tenant_subnet_trie` + `global_zone_trie`) because pin-path / `ValidateMapSizes` / `LpmKey` surface area stays single-map, and `tenant_id=0` is already reserved by `metadata.TenantIDUnset` — the interner starts at `nextID=1`, so 0 is a natural "applies to all tenants" sentinel rather than a magic value. Cardinality reshapes from `O(T × G + Σ O_t)` to `O(G + Σ O_t)`. The hot-path cost is one extra BPF map lookup on the routed-fallback path; the MAC-first hot path is unchanged. The Kafka-driven incremental diffs ([trie-construction.md](./trie-construction.md#incremental-updates)) are written against this deduplicated shape.

`max_entries` stays at **16,384** even after dedup. Headroom is cheap on an LPM_TRIE with `BPF_F_NO_PREALLOC` (entries are allocated on demand, not pre-reserved) and absorbs future per-tenant SAME_TENANT growth without another `task generate` cycle.

### `mac_tenant_map` — MAC-to-tenant lookup

```
Type:        BPF_MAP_TYPE_HASH
Max entries: 8,192  (compile-time constant)

KEY:   u64  (MAC packed into low 48 bits, big-endian byte order)
VALUE: u32  (tenant_id)
```

Default sized for a 500-VM-per-host node plus ~2k infrastructure MACs across many tenants (router interfaces, gateways, distributed DHCP). On a tested multi-node OVN deployment (~30 VMs) typical fill is <500 entries.

Populated from Neutron ports matching `device_owner` in:
- `compute:nova` — VM (keyed by port's tenant)
- `network:router_interface` — router-to-subnet attachment (keyed by router's tenant)
- `network:router_gateway` — router-to-external attachment (keyed as INFRA / external boundary)
- `network:dhcp`, `network:metadata` — traditional Neutron equivalents (zero entries on OVN deployments; included for forward-compatibility with a hypothetical mixed-mode cluster)

NOT populated:
- `network:floatingip` — handled via the NAT path ([octavia.md](./octavia.md) for the LB case)
- External / internet MACs — resolve via the LPM trie
- `network:distributed` — **verified empirically**: OVN does NOT use the Neutron `network:distributed` port MAC on the wire; it synthesizes its own DHCP `server_mac`, which misses here and classifies via the LPM fallback instead. Full story in [trie-construction.md, step 4](./trie-construction.md#the-five-step-algorithm).

**Lifecycle.** `mac_tenant_map` is a kernel-side mirror of the userspace `ShardedMetadataMap` (below). Insertions go userspace-then-kernel; deletions are delayed by the 60s [Lingering Ghost](#lingering-ghost) and then go kernel-then-userspace. The deletion-grace property is enforced on this kernel map specifically — if the kernel entry is deleted too eagerly, dying FIN/RST packets fall through to ZONE_MISS even though userspace still ghosts the metadata. Exact ordering rules: [map lifecycle invariants](#map-lifecycle-invariants).

## Userspace structures

```
ShardedMetadataMap                  64 shards × sync.RWMutex
  shard_idx = mac_uint64 & 63
  Key:   MAC as uint64
  Value: *TenantMeta { ProjectID, IsAmphora, DeleteAt }
         (a VMName log/dashboard enrichment field is deferred until
          a consumer arrives; see internal/metadata schema.go)

  INVARIANT 1: TenantMeta is immutable.
             Multiple MACs may share the same pointer.
             Updates replace the pointer atomically — never mutate fields.

  INVARIANT 2: ShardedMetadataMap is a strict superset of mac_tenant_map.
             Insertions: userspace first, then kernel.
             Deletions: kernel first (after 60s ghost), then userspace.
             Full lifecycle rules below.

GlobalState                         keyed by tenant flow ID
  Value: { PrometheusTotal u64, LastEbpfRaw u64 }
  Read-locked during Prometheus Collect().
  Write-locked during Scraper merge.
  Carries a second map — the settled accumulator (see "Settled bytes").

UnresolvedBuffer                    late-binding for unknown MACs
  Key:   flow_key (same as telemetry_map; delta math is per-flow)
  Value: { Total, LastEbpfRaw, FirstSeen }
  Capped at 10,000 entries (default) with LRU eviction.
  Retried every scrape interval.

  The scraper classifies each drained reading by its VM-side MAC:
  known (incl. lingering ghosts) → GlobalState; unknown → here. An
  entry accumulates the flow's cumulative since first sight (first
  sight seeds Total=LastEbpfRaw=current; later sightings add the delta
  with the same wraparound guard GlobalState uses).

  Late-binding resolution: when a buffered flow's MAC becomes known
  mid-window — the reconcile learning a new port, or a Kafka event
  kicking that reconcile — GlobalState.Resolve credits the buffered
  Total to the right tenant and writes LastEbpfRaw back, so the next
  scrape does not double-count (the write-back is Contract-critical;
  see contracts.md). Successes count on
  lachesis_unresolved_resolved_total.

  On eviction — TTL (default 60s) OR LRU-over-cap — the accumulated
  Total is folded into a synthetic "unknown" GlobalState key (both MACs
  zeroed, real eth_proto/direction/zone), which resolves to
  tenant_id="unknown" and collapses all unknown traffic into a handful
  of monotonic (unknown, zone, direction) series — so rate() never goes
  negative and cardinality stays bounded. Eviction ALSO deletes the
  flow's kernel telemetry_map entry: resetting the counter means a flow
  that reappears re-baselines from a fresh value, so its already-folded
  bytes are never folded twice. (The graceful-shutdown drain folds
  every entry without the kernel delete — the maps are replaced on the
  next boot.)

  Because eviction deletes a kernel entry, the buffer is wired only
  where that handle exists (the Linux Bootstrap), beside the
  pressure-relief evictor; both run in the scrape goroutine, so their
  telemetry_map deletes never race.

WAL                                 /var/lib/lachesis/network_agent_state.json (+ .bak)
  Atomic JSON snapshot of GlobalState (see primer, Write-Ahead Log).
  Flush every 60s (default; hot-tunable); previous snapshot retained as
  .bak for recovery from a bad write. Read on boot before any other
  operation.

  Snapshot envelope (schema v3):
    {
      "schema_version": 3,               // v1: flow records only.
                                         // v2: + settled section.
                                         // v3: + external_network on
                                         //     settled buckets.
                                         // Each bump is additive — older
                                         // files load without migration.
      "agent_build":    "8c2f4d1a9b3e",  // short VCS revision; ops correlation
      "written_at_ns":  "1746...",       // u64-as-string (see below)
      "global_state":   { ... },         // live flow rows
      "settled":        { ... }          // settled accumulator buckets
    }

  u64 fields (byte counters, last_seen_ns, written_at_ns) are encoded as
  decimal strings, not JSON numbers. JSON numbers are IEEE 754 doubles →
  silent precision loss above 2^53 (~83 days at 10 Gbps cumulative).
  Go's encoding/json handles this via the `,string` struct tag.

  Flush procedure (atomic, in this order):
    1. Write payload to wal.json.tmp; fsync.
    2. Rename wal.json → wal.json.bak (best-effort; ignore ENOENT).
    3. Rename wal.json.tmp → wal.json.
    4. Open the parent directory; fsync; close. Without it the renames
       are not journaled (ext4/XFS) — power loss after a successful
       flush could roll back to the previous snapshot.

  Boot procedure:
    1. Try wal.json. On missing / parse-fail, fall back to wal.json.bak
       with a loud warning and a lachesis_wal_load_fallback_total
       increment. A schema_version newer than this build never falls
       back — boot refuses to start (migration policy below) and leaves
       both files untouched.
    2. If both files are missing, start empty (first boot). If both are
       unreadable, quarantine the primary — rename wal.json →
       wal.json.quarantine (one slot; a later quarantine overwrites it,
       bounding disk use across crash loops) so the flush rotation can't
       destroy the evidence — then start empty and log the loss. A
       corrupt primary that lost to a readable .bak is quarantined the
       same way; an unreadable .bak is not (it is an older generation
       superseded by whatever the primary held).

  Migration policy:
    - schema_version unknown (newer than this build): refuse to start.
      Starting empty instead would let the flush rotation destroy the
      forward snapshot within two flushes — the rollback-after-upgrade
      scenario where fatal beats silent loss.
    - schema_version older: load directly when the change was additive
      (all bumps so far — v1→v2 settled, v2→v3 external_network — decode
      with the absent fields mapped to their sentinels); an explicit
      migration function per step is required the first time a bump is
      not additive.
    - Never silently skip unknown fields; never auto-coerce types.

  Why JSON, not binary or compressed:
    1–2 MB per flush at 16–33 KB/s sustained — IO is negligible. Compression
    saves ~80% but costs more CPU than the IO time it saves, and breaks
    `cat | jq` for ops debugging. Append-only logs and embedded KV stores
    (Bolt, SQLite) are overkill for "one writer, once per minute" with the
    ≤60s recovery target (boot-and-recovery.md).
```

## Lingering Ghost

When the reconcile (or a Kafka event driving it) observes a deleted port or subnet, the metadata entry is **NOT** removed immediately. Instead `DeleteAt = now + 60s`. The ghost sweeper (`internal/gc`, its own worker) sweeps expired entries every 60s. Reason: dying TCP FIN/RST packets can arrive after the VM is gone — without the lingering ghost they would mis-attribute to `unknown`.

The grace period must be enforced on the **kernel `mac_tenant_map`**, not just the userspace `ShardedMetadataMap`. The per-packet hot path looks up `mac_tenant_map[peer_mac]` and falls through to `ZONE_MISS` if the entry is missing there — regardless of what userspace thinks. See below for the exact insert/delete ordering rules across both maps.

**Precedence over UnresolvedBuffer.** A Lingering Ghost entry is still a *hit* in **both** maps — packets matching it attribute to the ghosted tenant, not the UnresolvedBuffer. The UnresolvedBuffer catches only MACs Neutron has *never* told us about (typically late Kafka delivery for a brand-new VM). The two paths are mutually exclusive: ghosts cover the tail of a known MAC's life; UnresolvedBuffer covers the head before the first Kafka event lands.

## Map lifecycle invariants

The kernel `mac_tenant_map` is the load-bearing copy for billing — every packet's classification depends on it. The userspace `ShardedMetadataMap` carries richer metadata (project_id UUID, IsAmphora flag, DeleteAt) but the kernel only reads its own map. Keeping the two consistent requires strict ordering on every operation.

**Invariant.** `mac_tenant_map` (kernel) is a strict subset of `ShardedMetadataMap` (userspace): every kernel entry has a userspace entry.

| Event | Order | Why |
|---|---|---|
| **Insert** (Kafka-kicked reconcile or cold-start) | userspace `ShardedMetadataMap` FIRST → then kernel `mac_tenant_map` | When the kernel classifies the next packet, userspace is already ready to enrich the resulting `tenant_id` into a project_id label at scrape time |
| **Mark for delete** (port/subnet gone from the snapshot) | set `DeleteAt = now + 60s` on the userspace entry. **Kernel entry is NOT touched.** | Dying FIN/RST packets continue to classify correctly during the grace window |
| **GC sweep** (every 60s; entries with `DeleteAt < now`) | kernel `mac_tenant_map` → the swept MACs' residual kernel `telemetry_map` flows → settled-bytes fold of their GlobalState rows (below) → userspace `ShardedMetadataMap` LAST | At no point does the kernel return a `tenant_id` that userspace can't translate; the fold runs while the metadata still resolves the tenant, so the dead VM's historical bytes stay attributed instead of re-bucketing to `unknown` |

**Violations are silent** — they don't crash the agent, they produce small but real billing errors:

| Mistake | Visible symptom |
|---|---|
| Insert kernel-first | First packets of a brand-new VM miss in the kernel → land in UnresolvedBuffer for a brief window before the kernel entry catches up |
| Delete kernel immediately on port deletion (skipping the 60s grace) | Dying FIN/RST packets attribute to `tenant=unknown` instead of the right tenant. The Lingering Ghost is functionally dead — under-billing on every shut-down VM |
| GC deletes userspace first | Brief window where a kernel hit can't be enriched → `tenant=unknown` labels on the next scrape's Collect output — and the settled-bytes fold can no longer learn the tenant, so the dead VM's history re-buckets to `unknown` permanently |

## Settled bytes

The Collector late-binds `tenant_id`: every scrape resolves each GlobalState flow's VM MAC through the metadata map. Series identity is therefore a function of *current* metadata — and two lifecycle events change the answer for bytes that were already counted:

- the **ghost sweep** deletes a dead VM's metadata: its flows stop resolving and would re-aggregate under `tenant_id="unknown"`;
- a **live port is reassigned** to another project: its flows' entire history would re-aggregate under the new tenant.

Either way an exposed per-tenant series would *decrease* — breaking [Contract 7](./contracts.md#required-contracts) and the [subtraction-billing contract](./billing.md) (silent under-billing), while the re-bucketed step spikes the revenue-leak SLO with bytes that are historical, not leaking.

The fix is **fold-forward at the moment attribution dies**. GlobalState carries a second map — the **settled accumulator**, keyed `(tenant_id, zone, external_network, direction)`, exactly the exposed label tuple — and `Settle(mode, resolve)` folds matching rows' totals into it inside one write-lock critical section. Two callers, two modes:

| Caller | Moment | Mode | Why that mode |
|---|---|---|---|
| Ghost sweep | after the kernel MAC + residual-flow deletes, before the userspace metadata delete — the last instant the tenant is knowable | **SettleEvict** — fold, then delete the rows | The flow's kernel counters are already gone, so the rows are dead; evicting them is also what stops GlobalState (and the WAL) growing with every VM that ever lived on the host |
| MAC reconcile, attribution change | just before the `*TenantMeta` pointer-replace (or router-map swap) | **SettleRebase** — fold, zero `Total`, keep `LastEbpfRaw` | The port lives on and its kernel counters keep running; the intact watermark makes the next drain credit only post-fold bytes, which late-bind to the new attribution. Evicting instead would re-count the full kernel cumulative as first sight |

`Collect()` emits **live + settled** per tuple, and snapshots both maps under ONE RLock — a snapshot torn across a concurrent fold would double-count (live then settled) or drop (settled then live) the folded bytes for one scrape, breaking monotonicity at the next. The WAL snapshot is combined for the same reason (a torn WAL pair would make the error permanent on crash-restore). The per-tuple sum is invariant across a fold; that invariance *is* the Contract 7 guarantee.

Consequences and boundaries:

- **MAC reuse is safe.** A swept MAC reborn on another tenant's port starts a fresh GlobalState row from a fresh kernel counter; the old tenant's bytes are already settled. Without the fold, the surviving row's whole history would re-bind to the new tenant at the next scrape (over-billing it) — raw bytes were never at risk (the Contract 5 wraparound guard treats the restarted kernel counter as a reset), but attribution was.
- **Settled buckets only grow**, and their cardinality is bounded by `tenants × zones × external networks × 2 directions` — a few KB even at hub-tenant scale. They round-trip through the WAL (additively since schema v2) and restore before the scraper starts.
- **Hard-crash window.** A fold becomes durable at the next WAL flush (≤60s). A hard crash in between restores the pre-fold rows, whose metadata may already be gone — so up to one flush window of folds can degrade to `unknown` on the next boot. This is the same envelope as the WAL's general ≤60s tail-loss trade-off; a graceful shutdown's final flush loses nothing.
- The UnresolvedBuffer's synthetic `unknown` keys have zero MACs and never settle — `unknown` is not a tenant whose history needs preserving, and those rows are already terminal.

### Per-server carry (the mortal family's fold absorber)

The settled accumulator keeps the **immortal** tenant family monotone but deliberately drops the `server_id` dimension, so it does nothing for the **mortal** per-server family (`lachesis_server_bytes_total`), emitted as `Σ live rows`. A fold that removes rows from a *still-live* server tuple — one port of a multi-port server deleted, or a same-server port recreated — would make that server's exposed series *dip* while it is still live, which the billing ETL's day-window clamp reads as under-usage ([billing.md](./billing.md), lachesis#226 / #227).

The fix is a second accumulator, the **carry**, keyed by the full server tuple `(server_id, tenant_id, zone, external_network, direction)` — exactly the emitted label set. `Settle` credits it with the same folded bytes it credits into settled, in the same write-lock critical section; the Collector emits `Σ live rows + carry` per server tuple, but **only for tuples that still have a live row** — a carry with no live row is a dormant rebirth seed, and the series has ended (mortal). One bucket, three behaviors:

- **tuple still has live rows** → the carry credit keeps the series from dipping (fixes #226);
- **tuple fully dead** → the series ends as today; the carry lies dormant as a same-window rebirth seed;
- **dormant past the TTL** → the carry is dropped; the bytes remain in tenant settled and in the billing days already extracted, so dead servers accumulate no unbounded state.

Dormancy and expiry are owned by the ghost sweep (`GlobalState.ExpireServerCarry` — never a per-tuple timer): each pass classifies a carry tuple live-or-dormant by resolving every live flow row, stamps `now` on one that has just fallen empty, and drops one dormant longer than the live `gc.server_carry_ttl` (hot-reloadable; default a day + margin, above the billing ETL's day window). The carry round-trips the WAL (additive schema v4) and restores before the scraper starts, so a restart never dips a live server's series; dormancy is re-derived after restore. `Collect` and the WAL snapshot read live + settled + carry under ONE lock — a torn snapshot would over- or under-bill a rebirth.

---

Next: [packet-classification.md](./packet-classification.md) →
