# Performance Characterization

Budgets and measured costs for the two hot paths — the per-packet kernel path
and the 10-second scrape loop — plus the memory model and where it ceilings.
The CI gates that hold these numbers are described in
[development/testing.md](../development/testing.md).

## Memory budget (per compute node)

| Structure | Size |
|---|---|
| `telemetry_map` PERCPU_HASH | `max_entries × (16 + 24×N_CPU)` bytes — preallocated. `max_entries` is compiled at 65,536 today (see the sizing note below). Typical fill (~850 flows on a 50-VM node): <1 MB of *used* entries |
| `subnet_zone_trie` LPM | 16,384 entries × ~24 bytes = ~400 KB max (`BPF_F_NO_PREALLOC` — allocated on demand) |
| `mac_tenant_map` HASH | 8,192 entries × 12 bytes = ~100 KB |
| `ShardedMetadataMap` (Go) | ~200 bytes per VM. 1,000 VMs → ~200 KB |
| `GlobalState` (Go) | ~60 bytes per flow entry. ~10,000 flows → ~600 KB |
| `UnresolvedBuffer` cap | 10,000 × ~80 bytes = ~800 KB max |

**`telemetry_map` sizing — current state and design target.** Because each
entry pre-allocates one slot per CPU, the per-entry cost grows linearly with
`N_CPU`. Today `max_entries` is a compile-time constant (65,536 in
`internal/bpf/schema.go`, mirrored by the map spec), which makes the
preallocated footprint a function of the host:

| N_CPU | per-entry bytes | preallocated kernel memory at 65,536 entries |
|---|---|---|
| 32 | 784 | ~50 MB |
| 64 | 1,552 | ~100 MB |
| 128 | 3,088 | ~200 MB |

The **design target** is to derive `max_entries` from a memory budget (default
50 MB) instead, clamped to `[8192, 65536]`:

```
max_entries = clamp(8192, 65536, memory_budget_bytes / (16 + 24 × N_CPU))
```

That keeps the kernel-map footprint roughly flat across host sizes at the cost
of a smaller flow ceiling on very-high-core hosts. It is **not implemented** —
deploying on a 128-core host today costs ~200 MB of kernel RAM, 4× the target
budget. Deferred as [item 10](./contracts.md#deferred-work); the
`lachesis_bpf_map_max_entries` gauge already surfaces the effective size per
host so the gap is observable.

**Total memory footprint — two separate pools, often conflated.** The agent's
**process RSS** is small: ~26 MB measured on a 48-core c36 node (the Go runtime
plus userspace state, *not* the map). The PERCPU `telemetry_map` is **kernel**
memory (memlock), which does not count against process RSS — that is the
~50–200 MB in the table above (by host core count; ~76 MB at 48 cores). So the
daemon costs on the order of ~26 MB of process RAM plus a fixed kernel-locked
map pool; both are well within budget. (Earlier revisions of this doc reported
"~150–200 MB RSS, mostly the map" — that folded the kernel map pool into RSS,
which the `VmRSS` of a live agent disproves.)

## CPU overhead

Per-packet kernel cost is dominated by:
1. Header pull (`bpf_skb_pull_data` for ~34 bytes) — negligible
2. Map lookups (`mac_tenant_map` ×2, maybe `subnet_zone_trie` ×2 with the sentinel fallback) — ~50 ns each when cached
3. One PERCPU update — ~30 ns

Total: **~150 ns / packet**. The amd64 CI runner measures ~135 ns through
`BPF_PROG_TEST_RUN` on the lookup-miss path (the CI ceiling gate fails above
300 ns — see [testing](../development/testing.md)); a live run on a c36 compute
node (Xeon, kernel 6.12) measured ~82 ns egress / ~94 ns ingress, so 150 ns is a
conservative design figure.

The CPU this costs is `packet_rate × per_packet_ns`, so the "% of a core" it
burns is a function of the **packet rate**, not of how many cores the host has.
Worked out at the 150 ns design figure:

| Traffic reaching a VM tap | packet rate at the TC hook | telemetry CPU on the core that processes it |
|---|---|---|
| 10 Gbps bulk TCP (GSO-coalesced) | ~30–50 k frames/s | ~0.5 % of one core |
| 10 Gbps at 1500 B | ~833 k pps | ~12 % of one core |
| **10 Gbps at 64 B — line-rate worst case** | 14.88 Mpps | **~2.2 cores** (≈223 % of one core; ≈1.4 cores at the 94 ns measured on c36) |

The 64 B line-rate case is the true worst case and it is **not free**:
`14.88e6 × 150 ns = 2.23 CPU-seconds per second`, i.e. ~2.2 full cores of work.
A single core saturates around 6–10 Mpps running only this program, so a genuine
64 B flood cannot fit on one core — it must be spread across several by
multiqueue/RSS. The cost **parallelises across the cores that carry the traffic;
it does not shrink**. Expressing it as a percentage of the whole host is only
meaningful when the load is actually spread that way — a flow pinned to one
queue pays the full per-core cost on that one core.

In practice a VM tap never sees 64 B line rate. Guest virtio TX caps a
small-packet flood well below 1 Mpps, and GSO delivers a 10 Gbps bulk stream to
the hook as only tens of thousands of frames/s (the c36 run measured ~32 k
frames/s at 9.3 Gbps). Realistic per-tap cost is therefore a fraction of one
core, and that same run showed the classifier **attached vs. detached
indistinguishable from run-to-run noise** — no measurable throughput penalty.

> `BPF_PROG_TEST_RUN` times a warm-cache tight loop; real traffic with many
> distinct flows adds map-lookup cache misses, so treat the per-packet numbers
> as a floor.

## Throughput characteristics

- Userspace `BatchLookup` polls every 10s (default). Single syscall, full snapshot. (`Iterate` is an alternative with the same data-volume cost; only syscall overhead differs.)
- **Map snapshot data volume = `entries × N_CPU × 24` bytes.** This is the kernel→userspace data transfer per scrape regardless of which API is used:

| Scenario | Volume | Wall time (memcpy + sum at ~50 GB/s) |
|---|---|---|
| 32-core, 10k flows | 7.5 MB | ~5 ms |
| 64-core, 10k flows | 15 MB | ~10 ms |
| 128-core, 10k flows | 30 MB | ~30 ms |
| 128-core, 50k flows | 150 MB | ~100+ ms |

  At high core counts a flat "5 ms" scrape estimate is not realistic; the scrape
  budget must account for the actual N_CPU. The wall times above are **modelled,
  not measured**: the drain is not instrumented — no histogram wraps the
  scraper's `BatchLookup` tick, so a node's real drain cost is not observable
  from `/metrics` today.

  In particular `lachesis_collect_duration_seconds` does **not** surface it (an
  earlier revision of this page said it did). That histogram times the Prometheus
  `Collect` pass over GlobalState — the read/exposition path, one row per flow
  with no `N_CPU` term — which is a different axis from this kernel→userspace
  snapshot. Sizing a scrape budget from it will mislead: it moves with flow count
  and label cardinality, not with host core count.

- Map iteration during pressure-relief GC: same cost; runs in the same scrape goroutine (after BatchLookup), so its `telemetry_map` deletes never race the drain.
- **WAL flush** breaks into three phases, not just fsync:

| Phase | Cost | Lock held? |
|---|---|---|
| Copy GlobalState into a temp buffer | ~5 ms for 10k entries | RLock on GlobalState, briefly |
| Marshal Go struct → JSON | ~50–100 ms for 600 KB output | no lock |
| Write + fsync + rename + rotate `.bak` | ~5–10 ms (varies wildly on slow disks) | no lock |

  Marshaling dominates, not the fsync. The critical section (lock-held) is just the copy phase, so a slow disk does NOT block the scraper. Per-phase metrics: `lachesis_wal_snapshot_copy_seconds`, `lachesis_wal_marshal_seconds`, `lachesis_wal_flush_latency_seconds` (the last covers write+fsync+rename only).

## Scalability ceiling

- The `telemetry_map` upper bound is `max_entries` (65,536 today) — it limits distinct (MAC-pair, direction, zone) combinations per node.
- On a 50-VM node: typical fill is ~850 entries (~1.3% — nowhere near the cap).
- On a 500-VM node (extreme): proportionally ~8,500 entries — ~13% fill, still comfortable.
- If a host reports fill >80% sustained (`lachesis_bpf_map_current_entries / lachesis_bpf_map_max_entries`), pressure-relief GC is already cycling and the deployment has outgrown the map; rebuild with a larger `max_entries` or add compute nodes. The gauge pair makes this visible before it becomes a billing problem ([metrics.md](./metrics.md)).

---

Next: [metrics.md](./metrics.md) →
