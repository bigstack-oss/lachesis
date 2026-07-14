# CubeCOS Network Telemetry — Design Document

> Per-tenant, line-rate network telemetry for OpenStack via eBPF TC.
> This document is the canonical reference for the design.
> Use it to onboard engineers, review changes, or evaluate trade-offs.

---

## Reading Guide

This document is self-contained but assumes general systems engineering background. We use a number of specialized technologies; if any term below is unfamiliar, follow the link into [Appendix B — Concept Primer](#appendix-b--concept-primer) first.

| Topic | First needed in | Primer |
|---|---|---|
| eBPF, TC, BTF | §2, §3 | [B.1](#b1-ebpf-in-60-seconds), [B.2](#b2-tc-clsact-qdisc), [B.3](#b3-btf-bpf-type-format) |
| `BPF_MAP_TYPE_PERCPU_HASH` | §3 | [B.4](#b4-percpu_hash) |
| `BPF_MAP_TYPE_LPM_TRIE` | §3, §5 | [B.5](#b5-lpm-trie) |
| `bpf_skb_ct_lookup`, conntrack | §6 | [B.6](#b6-bpf_skb_ct_lookup-and-conntrack) |
| Netlink, RTM_NEWLINK | §9 | [B.7](#b7-netlink) |
| OpenStack: Neutron / OVN / OVS / VXLAN/Geneve / Floating IP | §1, §5, §7 | [B.8](#b8-openstack-networking-primer) |
| Octavia, Amphora | §6 | [B.9](#b9-octavia-and-amphora-vms) |
| DPDK / SR-IOV / Smart NIC | §8 | [B.10](#b10-dpdk--sr-iov--smart-nic) |
| Write-Ahead Log (WAL) | §10 | [B.11](#b11-write-ahead-log-wal) |

For decisions we considered but rejected, see [Appendix C — Rejected Alternatives](#appendix-c--rejected-alternatives).

---

## Table of Contents

1. [Problem & Goals](#1-problem--goals)
2. [System Architecture](#2-system-architecture)
3. [Data Structures](#3-data-structures)
4. [Per-Packet Classification Algorithm](#4-per-packet-classification-algorithm)
5. [Trie Construction at Cold Start](#5-trie-construction-at-cold-start)
6. [Octavia LB Attribution](#6-octavia-lb-attribution)
7. [Scenario Walkthroughs](#7-scenario-walkthroughs)
8. [Edge Cases & Accuracy Ceiling](#8-edge-cases--accuracy-ceiling)
9. [Boot Sequence (Order Matters)](#9-boot-sequence-order-matters)
10. [Crash Resilience](#10-crash-resilience)
11. [Performance Characterization](#11-performance-characterization)
12. [Demo Workflow](#12-demo-workflow)
13. [Implementation Notes](#13-implementation-notes)
- [Appendix A — Design Decisions Table](#appendix-a--design-decisions-table)
- [Appendix B — Concept Primer](#appendix-b--concept-primer)
- [Appendix C — Rejected Alternatives](#appendix-c--rejected-alternatives)
- [Appendix D — Glossary](#appendix-d--glossary)

---

## 1. Problem & Goals

### What we're solving

CubeCOS is a multi-tenant OpenStack platform. Existing tools fail for billing-grade observability:

- **OVS counters / NetFlow / iptables** can't reliably distinguish North-South from East-West traffic.
- **Octavia load balancers** lose tenant context through NAT — bytes get attributed to the admin project, not the real end-user tenant. (See [B.9 Octavia and Amphora VMs](#b9-octavia-and-amphora-vms).)
- **Userspace packet parsing** burns CPU at 10 Gbps line rate.

### Goals

| # | Requirement |
|---|---|
| 1 | Classify all traffic into four categories: **N-S out** (VM → internet), **N-S in** (internet → VM), **Intra-Tenant E-W**, **Inter-Tenant E-W** |
| 2 | Re-attribute Octavia LB traffic to the real end-user tenant |
| 3 | Run entirely in the kernel via [eBPF TC](#b1-ebpf-in-60-seconds) at line-rate (10 Gbps+) with near-zero CPU overhead |
| 4 | Maintain real-time OpenStack metadata via Neutron API cold-start + Kafka events |
| 5 | Expose Prometheus cumulative counters at `/metrics` — billing semantics defined in [§11.5 Billing model & consumption contract](#billing-model--consumption-contract) |
| 6 | Survive Go agent crashes (zero data loss) and hard reboots (≤60s data loss) |

### Target environment

- Linux 5.10+ with [BTF](#b3-btf-bpf-type-format) and `bpf_skb_ct_lookup` (5.10 is the floor; verified empirically on kernels 6.10 and 6.12), x86_64
- Deployed as a daemon per OpenStack compute node
- Standard [OVS kernel datapath](#b8-openstack-networking-primer) with **Neutron OVN ML2 plugin** (verified empirically on OpenStack Yoga; see §B.8). DPDK/SR-IOV are out of scope — see [§8](#8-edge-cases--accuracy-ceiling). Traditional Neutron (OVS-agent + L3-agent + qrouter namespaces) is deferred — see [§13.2](#132-deferred-work).
- Dev: Apple Silicon Mac via Docker cross-compile

---

## 2. System Architecture

### Four layers

```
┌─────────────────────────────────────────────────────────────────────┐
│ Layer 4 — Prometheus + WAL                                          │
│   Custom Collector, GlobalState, /var/lib/lachesis/...json snapshot  │
└────────────────────────────────▲────────────────────────────────────┘
                                 │  cumulative counters
┌────────────────────────────────┴────────────────────────────────────┐
│ Layer 3 — Go agent                                                  │
│   Scraper · Delta math · Octavia attribution · Netlink Watcher      │
│   Interface Registry · UnresolvedBuffer (late-binding)              │
└────▲────────────────────────────────────────────────────────────────┘
     │  BatchLookup every 10s             ▲
     │                                    │  Neutron API + Kafka
┌────┴───────────────────────┐  ┌─────────┴───────────────────────────┐
│ Layer 1 — eBPF data plane  │  │ Layer 2 — OpenStack metadata        │
│   tc_telemetry_in/out      │  │   ShardedMetadataMap                │
│   PERCPU_HASH telemetry    │  │   builds: subnet_zone_trie          │
│   LPM trie subnet_zone     │  │           mac_tenant_map            │
│   HASH mac_tenant          │  │   Source: Neutron v2.0 API          │
└────────────────────────────┘  └─────────────────────────────────────┘
        ▲
        │  every packet, both directions
┌───────┴──────────────────────────────────────────────────────────────┐
│ VM tap interfaces (tapXXX)                                           │
└──────────────────────────────────────────────────────────────────────┘
```

### Data flow

- **Packet path:** VM → tap → TC ingress/egress hook → PERCPU_HASH map.
- **Read path:** Go agent `BatchLookup` → delta math → GlobalState → Prometheus.
- **Metadata path:** Neutron API cold-start + Kafka live updates → builds the trie + MAC map → kernel uses these to classify each packet.

### Why TC clsact, not XDP

| Concern | TC clsact | XDP |
|---|---|---|
| Coverage on tap interfaces | Both ingress + egress | **Ingress only** (empirically confirmed 2026-04-30: 0% TX coverage on tap) |
| Conntrack helper | [`bpf_skb_ct_lookup`](#b6-bpf_skb_ct_lookup-and-conntrack) available | Not available — required for Octavia attribution |
| Verdict | **Chosen** | Rejected — see [C.1](#c1-xdp-hook-instead-of-tc) |

### Why per-VM tap, not OVS bridge or physical NIC

| Concern | VM tap (chosen) | OVS br-int / Physical NIC |
|---|---|---|
| Per-VM attribution | Exact (each tap = one VM) | Requires inner-header parsing |
| Same-host E-W traffic | Captured (each VM has its own tap) | Misses (stays inside OVS, never hits NIC) |
| [VXLAN](#b8-openstack-networking-primer) visibility | None (pre-encap) | Yes (post-encap) |
| Required for billing? | Yes | VXLAN is not needed — MAC is unique enough |

Detailed reasoning in [C.2 Sampling at OVS / VXLAN envelope extraction](#c2-sampling-at-ovs--vxlan-envelope-extraction).

> **Implementers:** §13.1 lists seven contracts the build must guarantee for correctness. Read those first — they cover invariants that are easy to miss (RLock around `Collect()`, kernel/userspace lifecycle ordering, `*TenantMeta` pointer-replace semantics, boot-order sync points, u64 wraparound, UnresolvedBuffer cap, monotone cumulative counters). Violating any of them produces silent billing errors that don't crash the agent.

---

## 3. Data Structures

### 3.1 Kernel-side BPF maps

#### `telemetry_map` — the byte/packet counter

```
Type:        BPF_MAP_TYPE_PERCPU_HASH    ← see B.4
Max entries: 65,536
Pinning:     none yet — map lifetime is tied to the loaded collection
             and the attached TC filters; pinning under bpf.pin_path
             for zero-loss agent-crash recovery is deferred (§10, §13.2 #7)

KEY:   struct flow_key  (16 bytes, packed)
   ┌──────────────────────────────────────────────────────────────────┐
   │ src_mac    [6]u8                                                 │
   │ dst_mac    [6]u8                                                 │
   │ eth_proto  u16   (0x0800 IPv4 / 0x86DD IPv6)                     │
   │ direction  u8    (0=VM sending, 1=VM receiving)                  │
   │ dst_zone   u8    (0=ext 1=same 2=other 3=infra 4=miss 5=shared)  │
   └──────────────────────────────────────────────────────────────────┘

VALUE: struct flow_metrics  (24 bytes, one slot per CPU)
   ┌──────────────────────────────────────────────────────────┐
   │ bytes        u64                                         │
   │ packets      u64                                         │
   │ last_seen_ns u64  (CLOCK_MONOTONIC, matches Go side)     │
   └──────────────────────────────────────────────────────────┘
```

**Why [PERCPU](#b4-percpu_hash).** At 10 Gbps × 32 cores, a global hash with `__sync_fetch_and_add` becomes the bottleneck — atomic contention dominates. PERCPU eliminates contention; each CPU has its own slot, no atomics needed once the entry exists.

**Pressure-relief GC.** Capacity is recovered by a userspace pass that flushes bytes to GlobalState *before* deleting the map entry (never the other way around — see §10). Trigger and bounds:

- Fill ratio sampled at the start of each scrape (every 10s).
- Above the **high watermark** (default **80%**), run pressure-relief in the same goroutine as the scrape, after the BatchLookup completes. Relief then runs on every scrape until fill falls back below the **low watermark** (default **75%**) — a hysteresis, so the map settles near the low watermark rather than oscillating at the high one.
- Eviction order: oldest by `last_seen_ns` first.
- **Per-pass cap: 1,000 entries** (default). Bounds the worst-case stall to ~50 ms (≈50 µs/entry × 1,000) regardless of how full the map is.
- **Algorithm: single-pass scan with a bounded size-K heap** (K = the per-pass cap) to select the oldest-K by `last_seen_ns`. The heap is ordered *max*-by-`last_seen_ns`, so the newest of the K candidates retained so far sits at the root and is evicted in favour of an older flow as the scan proceeds. Cost is O(N log K) where N is the current entry count. For N=52k (80% fill), this is ~50 ms — included in the per-pass budget. A naïve full sort (O(N log N)) would be ~200 ms; avoid it.
- Floor: the low watermark (default **75%**, not 70%). One pass evicts ~3,250 entries to reach the floor; the cap kicks in first, so the floor is reached over 3–4 successive scrapes — still well under a minute.
- Each pass increments `lachesis_gc_pressure_relief_runs_total` and `lachesis_gc_evictions_total{reason="pressure_relief"}` (§11.4 health metrics).
- The two watermarks and the per-pass cap are operator-tunable via the `gc:` config section and **hot-reloadable on SIGHUP** — the reliever reads them through an atomic snapshot, so retuning needs no restart. The high watermark is validated `< 1.0`: at 1.0 the map fills and the kernel drops counters on its own, the exact byte loss this GC prevents. The defaults are the values quoted above.

If the map sustains >80% fill across many scrapes despite the GC, the deployment has outgrown the configured `max_entries` and the operator must rebuild with a larger value — surfaced via the fill-ratio gauge before it becomes a billing problem.

**Why MAC-pair, not 5-tuple.** MAC-pair scales with topology (~850 entries on a 50-VM node). 5-tuple scales with connection count and explodes both the map and downstream Prometheus labels. Detailed comparison in [C.4](#c4-5-tuple-flow-key-instead-of-mac--zone).

**Why `dst_zone` is in the key.** When VM-A in subnet-1 sends to VM-B in subnet-2 via the tenant router, the L2 destination MAC at VM-A's tap is the router's MAC — *identical* to VM-A talking to the internet via the same router. Without an L3 classification baked into the key, the four billing categories collapse into one ambiguous bucket. `dst_zone` is the L3 tiebreaker, populated by an in-kernel [LPM lookup](#b5-lpm-trie).

#### `subnet_zone_trie` — the L3 zone resolver

```
Type:        BPF_MAP_TYPE_LPM_TRIE       ← see B.5
Max entries: 16,384   (default; configurable)
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
                      ZONE_SHARED — see §5.2 for emission rules)

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

**Scaling cost of the current (tenant_id, ip) shape.** The §5.2 cold-start algorithm emits, *for every tenant T*:

```
  total_entries(T)  =  1 (catchall)
                     + 1 (metadata /32)
                     + |shared_prefixes|          (every shared subnet, all tenants)
                     + |infra_prefixes|           (router/DHCP/gateway IPs, all tenants)
                     + |owned_subnets(T)|         (genuinely per-tenant)

  total_entries     =  |T| × (2 + |shared| + |infra|)  +  Σ_t |owned(t)|
```

Empirically on a 27-tenant single-host OVN deployment: 9270 total entries, of which ~340 per tenant are global (catchall + metadata + shared + infra). That is `27 × 340 + 90 ≈ 9270` — i.e. **~96% of trie occupancy is per-tenant replication of identical global rows.** Adding compute hosts does not multiply this (every node loads the same cluster-wide Neutron snapshot), but adding tenants does. At realistic production tenant counts (≥200) the model overflows the 16384 trie cap and hard-fails at boot via `bpf.ValidateMapSizes`.

**Dedup landed in Sprint 4c** (see `docs/sprint-plan.md` §4c). The implemented shape is **sentinel `tenant_id=0` rows in this same trie** for catchall / INFRA / SHARED, read with a fallback `bpf_map_lookup_elem` on first-lookup miss. Picked over a split-map alternative (`tenant_subnet_trie` + `global_zone_trie`) because pin-path / `ValidateMapSizes` / `LpmKey` surface area stays single-map, and `tenant_id=0` is already reserved by `metadata.TenantIDUnset` — the interner starts at `nextID=1`, so 0 is a natural "applies to all tenants" sentinel rather than a magic value. Cardinality reshapes from `O(T × G + Σ O_t)` to `O(G + Σ O_t)`. The hot-path cost is one extra BPF map lookup on the routed-fallback path; the MAC-first hot path is unchanged. Sprint 4c is also a hard dependency of Sprint 7 — incremental Kafka diffs are cheaper to write against the deduplicated shape than to migrate later.

`max_entries` stays at **16,384** even after dedup. Headroom is cheap on an LPM_TRIE with `BPF_F_NO_PREALLOC` (entries are allocated on demand, not pre-reserved) and absorbs future per-tenant SAME_TENANT growth without another `task generate` cycle.

#### `mac_tenant_map` — MAC-to-tenant lookup

```
Type:        BPF_MAP_TYPE_HASH
Max entries: 8,192   (default; configurable)

KEY:   u64  (MAC packed into low 48 bits, big-endian byte order)
VALUE: u32  (tenant_id)
```

Default sized for a 500-VM-per-host node plus ~2k infrastructure MACs across many tenants (router interfaces, gateways, distributed DHCP). On a tested multi-node OVN deployment (~30 VMs) typical fill is <500 entries. The 1k default originally specified was too tight; production deployments with >500 VMs/host would have hit the cap.

Populated from Neutron ports matching `device_owner` in:
- `compute:nova` — VM (keyed by port's tenant)
- `network:router_interface` — router-to-subnet attachment (keyed by router's tenant)
- `network:router_gateway` — router-to-external attachment (keyed as INFRA / external boundary)
- `network:dhcp`, `network:metadata` — traditional Neutron equivalents (zero entries on OVN deployments; included for forward-compatibility with a hypothetical mixed-mode cluster)

NOT populated:
- `network:floatingip` — handled via the Octavia / NAT path in §6
- External / internet MACs — resolve via the LPM trie
- `network:distributed` — **verified empirically**: OVN does NOT use the Neutron `network:distributed` port MAC on the wire. Instead OVN synthesizes its own DHCP `server_mac` (stored in OVN Northbound DB's `DHCP_Options` table) which does not correspond to any Neutron port. DHCP responses to VMs therefore have a `peer_mac` that misses in `mac_tenant_map`. This is acceptable because DHCP volume is negligible (a few packets per lease renewal, ~once per day per VM), and the response's `remote_ip` (the DHCP `server_id`, identical to the subnet's `gateway_ip`) IS in the LPM trie tagged INFRA (§5.2 Step 4) — so DHCP traffic classifies correctly via the LPM fallback, just not via the hybrid MAC path

**Lifecycle.** `mac_tenant_map` is a kernel-side mirror of the userspace `ShardedMetadataMap` (§3.2). Insertions go userspace-then-kernel; deletions are delayed by the 60s Lingering Ghost (§3.3) and then go kernel-then-userspace. The deletion-grace property is enforced on this kernel map specifically — if the kernel entry is deleted too eagerly, dying FIN/RST packets fall through to ZONE_MISS even though userspace still ghosts the metadata.

### 3.2 Userspace structures (Go agent)

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

  INVARIANT 2: ShardedMetadataMap is a strict superset of mac_tenant_map (§3.1).
             Insertions: userspace first, then kernel.
             Deletions: kernel first (after 60s ghost), then userspace.
             Full lifecycle rules: §3.4.

GlobalState                         keyed by tenant flow ID
  Value: { PrometheusTotal u64, LastEbpfRaw u64 }
  Read-locked during Prometheus Collect().
  Write-locked during Scraper merge.

UnresolvedBuffer                    late-binding for unknown MACs
  Key:   flow_key (same as telemetry_map; delta math is per-flow)
  Value: { Total, LastEbpfRaw, FirstSeen }
  Capped at 10,000 entries with LRU eviction.
  Retried every scrape interval.

  The scraper classifies each drained reading by its VM-side MAC:
  known (incl. lingering ghosts) → GlobalState; unknown → here. An
  entry accumulates the flow's cumulative since first sight (first
  sight seeds Total=LastEbpfRaw=current; later sightings add the delta
  with the same wraparound guard GlobalState uses).

  On eviction — 60s TTL OR LRU-over-cap — the accumulated Total is
  folded into a synthetic "unknown" GlobalState key (both MACs zeroed,
  real eth_proto/direction/zone), which resolves to tenant_id="unknown"
  and collapses all unknown traffic into a handful of monotonic
  (unknown, zone, direction) series — so rate() never goes negative and
  cardinality stays bounded. Eviction ALSO deletes the flow's kernel
  telemetry_map entry: resetting the counter means a flow that reappears
  re-baselines from a fresh value, so its already-folded bytes are never
  folded twice. (The graceful-shutdown drain folds every entry without
  the kernel delete — the maps are replaced on the next boot.)

  Because eviction deletes a kernel entry, the buffer is wired only
  where that handle exists (the Linux Bootstrap), beside the
  pressure-relief evictor; both run in the scrape goroutine, so their
  telemetry_map deletes never race.

  Late-binding resolution — attributing a buffered flow to the right
  tenant once its MAC becomes known mid-window — is the Kafka consumer's
  job (a later sprint); until then every unresolved flow ages out to
  "unknown" at the TTL.

WAL                                 /var/lib/lachesis/network_agent_state.json (+ .bak)
  Atomic JSON snapshot of GlobalState (see B.11).
  Flush every 60s; previous snapshot retained as .bak for recovery from
  a bad write. Read on boot before any other operation.

  Snapshot envelope:
    {
      "schema_version": 1,               // bump on any GlobalState shape change
      "agent_build":    "8c2f4d1a9b3e",  // short VCS revision; ops correlation
      "written_at_ns":  "1746...",       // u64-as-string (see below)
      "global_state":   { ... }          // the actual payload
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
       with a loud warning and an internal-error counter increment. A
       schema_version newer than this build never falls back — boot
       refuses to start (migration policy below) and leaves both files
       untouched.
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
    - schema_version older: run explicit migration function (one per step).
    - Never silently skip unknown fields; never auto-coerce types.

  Why JSON, not binary or compressed:
    1–2 MB per flush at 16–33 KB/s sustained — IO is negligible. Compression
    saves ~80% but costs more CPU than the IO time it saves, and breaks
    `cat | jq` for ops debugging. Append-only logs and embedded KV stores
    (Bolt, SQLite) are overkill for "one writer, once per minute" with the
    ≤60s recovery target (§10).
```

### 3.3 Lingering Ghost (60s TTL on metadata deletion)

When Neutron emits `port.deleted` or `subnet.deleted`, the metadata entry is **NOT** removed immediately. Instead `DeleteAt = now + 60s`. A GC sweeps every 60s and drops expired entries. Reason: dying TCP FIN/RST packets can arrive after the VM is gone — without the lingering ghost they would mis-attribute to `unknown`. (Implementation status: the `MarkDelete` hook and `DeleteAt` field exist today; the 60s sweep goroutine lands with the GC subsystem, sprint 6.)

The grace period must be enforced on the **kernel `mac_tenant_map`**, not just the userspace `ShardedMetadataMap`. The per-packet hot path looks up `mac_tenant_map[peer_mac]` and falls through to `ZONE_MISS` if the entry is missing there — regardless of what userspace thinks. See §3.4 for the exact insert/delete ordering rules across both maps.

**Precedence over UnresolvedBuffer.** A Lingering Ghost entry is still a *hit* in **both** maps — packets matching it attribute to the ghosted tenant, not the UnresolvedBuffer. The UnresolvedBuffer (§3.2) catches only MACs Neutron has *never* told us about (typically late Kafka delivery for a brand-new VM). The two paths are mutually exclusive: ghosts cover the tail of a known MAC's life; UnresolvedBuffer covers the head before the first Kafka event lands.

### 3.4 Map lifecycle invariants

The kernel `mac_tenant_map` is the load-bearing copy for billing — every packet's classification depends on it. The userspace `ShardedMetadataMap` carries richer metadata (project_id UUID, IsAmphora flag, DeleteAt) but the kernel only reads its own map. Keeping the two consistent requires strict ordering on every operation.

**Invariant.** `mac_tenant_map` (kernel) is a strict subset of `ShardedMetadataMap` (userspace): every kernel entry has a userspace entry.

| Event | Order | Why |
|---|---|---|
| **Insert** (Kafka `port.created` or cold-start) | userspace `ShardedMetadataMap` FIRST → then kernel `mac_tenant_map` | When the kernel classifies the next packet, userspace is already ready to enrich the resulting `tenant_id` into a project_id label at scrape time |
| **Mark for delete** (Kafka `port.deleted` / `subnet.deleted`) | set `DeleteAt = now + 60s` on the userspace entry. **Kernel entry is NOT touched.** | Dying FIN/RST packets continue to classify correctly during the grace window (§3.3) |
| **GC sweep** (every 60s; entries with `DeleteAt < now`) | kernel `mac_tenant_map` → the swept MACs' residual kernel `telemetry_map` flows (§3.3) → settled-bytes fold of their GlobalState rows (§3.5) → userspace `ShardedMetadataMap` LAST | At no point does the kernel return a `tenant_id` that userspace can't translate; the fold runs while the metadata still resolves the tenant, so the dead VM's historical bytes stay attributed instead of re-bucketing to `unknown` |

**Violations are silent** — they don't crash the agent, they produce small but real billing errors:

| Mistake | Visible symptom |
|---|---|
| Insert kernel-first | First packets of a brand-new VM miss in the kernel → land in UnresolvedBuffer for a brief window before the kernel entry catches up |
| Delete kernel immediately on `port.deleted` (skipping the 60s grace) | Dying FIN/RST packets attribute to `tenant=unknown` instead of the right tenant. The Lingering Ghost is functionally dead — under-billing on every shut-down VM |
| GC deletes userspace first | Brief window where a kernel hit can't be enriched → `tenant=unknown` labels on the next scrape's Collect output — and the settled-bytes fold (§3.5) can no longer learn the tenant, so the dead VM's history re-buckets to `unknown` permanently |

### 3.5 Settled bytes (fold-forward when attribution dies)

The Collector late-binds `tenant_id`: every scrape resolves each GlobalState flow's VM MAC through the metadata map (§3.2). Series identity is therefore a function of *current* metadata — and two lifecycle events change the answer for bytes that were already counted:

- the **ghost sweep** deletes a dead VM's metadata (§3.3): its flows stop resolving and would re-aggregate under `tenant_id="unknown"`;
- a **live port is reassigned** to another project: its flows' entire history would re-aggregate under the new tenant.

Either way an exposed per-tenant series would *decrease* — breaking Contract 7 (§13.1) and the §11.5 subtraction-billing contract (silent under-billing), while the re-bucketed step spikes the revenue-leak SLO with bytes that are historical, not leaking.

The fix is **fold-forward at the moment attribution dies**. GlobalState carries a second map — the **settled accumulator**, keyed `(tenant_id, zone, direction)`, exactly the exposed label tuple — and `Settle(mode, resolve)` folds matching rows' totals into it inside one write-lock critical section. Two callers, two modes:

| Caller | Moment | Mode | Why that mode |
|---|---|---|---|
| Ghost sweep (§3.3/§3.4) | after the kernel MAC + residual-flow deletes, before the userspace metadata delete — the last instant the tenant is knowable | **SettleEvict** — fold, then delete the rows | The flow's kernel counters are already gone, so the rows are dead; evicting them is also what stops GlobalState (and the WAL) growing with every VM that ever lived on the host |
| MAC reconcile, tenant change | just before the `*TenantMeta` pointer-replace | **SettleRebase** — fold, zero `Total`, keep `LastEbpfRaw` | The port lives on and its kernel counters keep running; the intact watermark makes the next drain credit only post-fold bytes, which late-bind to the new tenant. Evicting instead would re-count the full kernel cumulative as first sight |

`Collect()` emits **live + settled** per tuple, and snapshots both maps under ONE RLock — a snapshot torn across a concurrent fold would double-count (live then settled) or drop (settled then live) the folded bytes for one scrape, breaking monotonicity at the next. The WAL snapshot is combined for the same reason (a torn WAL pair would make the error permanent on crash-restore). The per-tuple sum is invariant across a fold; that invariance *is* the Contract 7 guarantee.

Consequences and boundaries:

- **MAC reuse is safe.** A swept MAC reborn on another tenant's port starts a fresh GlobalState row from a fresh kernel counter; the old tenant's bytes are already settled. Without the fold, the surviving row's whole history would re-bind to the new tenant at the next scrape (over-billing it) — raw bytes were never at risk (the §13.1 #5 wraparound guard treats the restarted kernel counter as a reset), but attribution was.
- **Settled buckets only grow**, and their cardinality is bounded by `tenants × zones × 2 directions` — a few KB even at hub-tenant scale. They round-trip through the WAL (schema v2; purely additive, so a v1 snapshot loads with an empty accumulator) and restore before the scraper starts.
- **Hard-crash window.** A fold becomes durable at the next WAL flush (≤60s, §B.11). A hard crash in between restores the pre-fold rows, whose metadata may already be gone — so up to one flush window of folds can degrade to `unknown` on the next boot. This is the same envelope as the WAL's general ≤60s tail-loss trade-off; a graceful shutdown's final flush loses nothing.
- The UnresolvedBuffer's synthetic `unknown` keys (§3.2) have zero MACs and never settle — `unknown` is not a tenant whose history needs preserving, and those rows are already terminal.

---

## 4. Per-Packet Classification Algorithm

### 4.1 Pseudocode (kernel-side, runs on every packet)

```
1. Parse Ethernet.
   If proto not in {IPv4, IPv6}, return TC_ACT_OK without counting.

2. direction = 0  if attached to ingress hook (VM is sending)
              = 1  if attached to egress  hook (VM is receiving)

3. Directional swap — always reason about "the VM" and "the remote endpoint":

     if direction == 0:                  # VM sending
        vm_mac    = eth->h_source
        remote_ip = iph->daddr
     else:                                # VM receiving
        vm_mac    = eth->h_dest
        remote_ip = iph->saddr

4. tenant_id = mac_tenant_map[vm_mac]
   if not found: dst_zone = ZONE_MISS (alert: unrecognized VM)
   else:        proceed

5. Hybrid zone resolution:

     peer_mac = eth->h_dest    if direction == 0
              = eth->h_source  if direction == 1
     peer_tid = mac_tenant_map[peer_mac]

     if peer_tid is set:
        # Direct L2 between two known endpoints — exact comparison.
        # No routing involved; trie is bypassed.
        dst_zone = SAME_TENANT  if peer_tid == tenant_id
                   OTHER_TENANT otherwise
     else:
        # peer_mac is a router or external MAC — fall back to LPM trie.
        dst_zone = subnet_zone_trie[(tenant_id, remote_ip)]
                   or ZONE_MISS if no trie entry

6. Build flow_key { src_mac, dst_mac, eth_proto, direction, dst_zone }.

7. Look up telemetry_map[flow_key]:
     hit:   val->bytes += skb->len
            val->packets += 1
            val->last_seen_ns = bpf_ktime_get_ns()
     miss:  insert {skb->len, 1, ktime} with BPF_ANY
```

### 4.2 The directional swap, explained

Without the swap, the kernel always reads `h_source` and `daddr`. That's correct for the ingress hook (VM sending: `h_source` is the VM, `daddr` is the remote). But on the egress hook (VM receiving), `h_source` is the *router's* MAC and `daddr` is the *VM's own IP*.

That second case has two failures stacked:

1. **Wrong MAC** — `mac_tenant_map[router_mac]` misses → `ZONE_MISS`. Visible in metrics.
2. **Wrong IP** — even if you used the right MAC, looking up `(tenant, vm_own_ip)` matches the VM's own subnet → classifies a **10 GB Google download as same-tenant intra-traffic**. Silently misclassified, no signal.

The directional swap eliminates both. The mental model: *the kernel always asks "relative to this VM's tenant, which zone is the remote endpoint in?"* — and the values of "VM" and "remote" depend on the direction.

### 4.3 The hybrid lookup, explained

For direct L2 traffic (VM-A → VM-B, same broadcast domain, no router), the destination MAC IS the destination VM's MAC. We can look it up in `mac_tenant_map` and get an *exact* tenant comparison. No trie involved. No CIDR ambiguity. No misconfiguration risk.

For routed traffic (anything via a router or external), `peer_mac` is the router's MAC, which is not in `mac_tenant_map`. We fall back to the LPM trie, which uses the L3 destination IP.

This means the trie only needs to handle routed traffic. Direct L2 traffic is exact-classified without it. We considered the always-LPM approach and rejected it — see [C.8](#c8-always-lpm-no-mac-first-hybrid).

### 4.4 Decision tree

```
                    packet at VM tap
                           │
                 ┌─────────┴─────────┐
              IP packet?         non-IP (ARP/LLDP)
                 │                   │
                yes              pass-through
                 │               (uncounted)
                 ▼
        Apply directional swap
        → vm_mac, remote_ip, peer_mac
                 │
                 ▼
        Is peer_mac an Amphora?
        (mac_tenant_map[peer_mac].IsAmphora == true)
                 │
         ┌───────┴───────┐
        yes              no
         │                │
         ▼                │
   Octavia path (§6):     │
   - attribution =        │
     LBOwnerTenant        │
     (from MAC flag,      │
      not conntrack)      │
   - zone derivation      │
     depends on which     │
     tap we are at        │
         │                │
         └───────┬────────┘
                 ▼
        Is vm_mac in mac_tenant_map?
                 │
        ┌────────┴────────┐
       no                yes
        │                 │
        ▼                 ▼
   ZONE_MISS    Is peer_mac in mac_tenant_map?
                          │
                  ┌───────┴───────┐
                 yes              no
                  │                │
                  ▼                ▼
        Compare tenant_ids   LPM trie lookup
                  │           (tenant_id, remote_ip)
        ┌─────────┼─────────┐    │
       eq       neq          │    ▼
        │        │           │   one of:
        ▼        ▼           │     SAME_TENANT
   SAME       OTHER          │     OTHER_TENANT
                             │     INFRA
                             │     EXTERNAL
                             │     MISS (catchall miss)
```

The Octavia branch (top of tree) attributes LB-mediated traffic to the LB owner via the **Amphora MAC flag**, not via conntrack — see §6 for the full algorithm. Zone derivation differs by tap: at the Amphora's tap, Segment 1 may use an optional `bpf_skb_ct_lookup` to identify the client's zone; at the backend's tap, Segment 2 is unconditionally classified as INFRA. Conntrack-lookup miss falls back to EXTERNAL for Segment 1 zone classification without affecting LB-owner attribution (§8 Tier 4 #17).

---

## 5. Trie Construction at Cold Start

This is the hardest part of the system. The kernel does a single LPM lookup; all the intelligence is in **how Go assembles the trie** before traffic starts flowing.

### 5.1 Data sources (Neutron v2.0 API)

| Endpoint | Fields used |
|---|---|
| `GET /v2.0/networks` | `id, tenant_id, shared, router:external` |
| `GET /v2.0/subnets` | `id, network_id, cidr, tenant_id, gateway_ip` |
| `GET /v2.0/ports` | `id, network_id, mac_address, device_id, device_owner, fixed_ips, tenant_id` |
| `GET /v2.0/routers` | `id, tenant_id, external_gateway_info, routes` |
| `GET /v2.0/address-scopes` + `subnetpools` | optional, for explicit cross-tenant peering |

**OVN deployments.** All needed data comes through the standard Neutron port API; no DB queries, no OVN-specific extensions. OVN-specific `device_owner` values (`network:distributed`, etc.) are handled in §5.2 Step 4. The traditional Neutron `dvr-mac-addresses` extension is NOT used by OVN, and OVN does not require per-host MAC enumeration because logical routers have a single MAC across all chassis (routing is implemented by OVS flow rules, not per-host `qrouter-XXX` namespaces).

**Why API and not direct MySQL.** Neutron's internal schema migrates with each OpenStack release. The v2.0 API is explicitly versioned and backward-compatible. Direct DB access also requires DB credentials — a security concern. All joins are done in Go memory after caching the API responses. See [C.3](#c3-direct-mysql-queries-instead-of-neutron-api) for the full reasoning.

### 5.2 The 5-step algorithm (per tenant T)

```
For each tenant T (run once at cold start, then incrementally on Kafka events):

  Step 1 — Catchall
    add (T, 0.0.0.0/0) → ZONE_EXTERNAL

  Step 2 — Directly-owned subnets
    for each subnet S where S.network.tenant_id == T AND not shared:
      add (T, S.cidr) → ZONE_SAME_TENANT

  Step 3 — Shared / provider networks T can reach
    for each subnet S where S.network.shared == true:
      add (T, S.cidr) → ZONE_SHARED

    ZONE_SHARED is emitted uniformly for every tenant, including the
    network's owner. Rationale: the LPM trie cannot resolve per-VM
    ownership inside a shared /24, so guessing SAME or OTHER
    systematically mis-bills the wrong direction. The MAC-first
    hot path classifies L2 traffic on shared networks correctly
    (intra-tenant L2 hits ZONE_SAME_TENANT via mac_tenant_map
    comparison); ZONE_SHARED labels only the L3-routed-fallback
    case, where the trie alone has insufficient information.
    Billing engines should treat ZONE_SHARED as its own line item.

    Exception: subnets on networks where router:external == true
    are NOT emitted by Step 3 (or Step 2); they fall through to
    Step 1's catchall as ZONE_EXTERNAL.

  Step 4 — Infrastructure IPs into the trie
    for each port P with device_owner in {
        network:dhcp,                   # traditional Neutron DHCP
        network:metadata,               # traditional Neutron metadata
        network:distributed,            # OVN distributed DHCP — IP only (MAC isn't on wire)
        network:router_interface,       # router-to-subnet attachment (both architectures)
        network:router_gateway,         # router-to-external attachment
      }:
      add (T, P.fixed_ip/32) → ZONE_INFRA

    for each subnet S where S.gateway_ip is set:
      add (T, S.gateway_ip/32) → ZONE_INFRA
        # ^ catches OVN's DHCP server_id (= gateway_ip), which is the
        #   src_ip on synthesized DHCP responses. The OVN server_mac is
        #   NOT a Neutron port (see §3.1) so mac_tenant_map will miss
        #   on DHCP responses — the LPM lookup on gateway_ip carries
        #   the classification.

    Add Nova metadata service:
      add (T, 169.254.169.254/32) → ZONE_INFRA

    Note: OVN deployments use `network:distributed` for DHCP (not `network:dhcp`)
    and have no `network:metadata` ports — metadata is handled via the OVN
    metadata agent proxying to 169.254.169.254 directly. The filter set above
    covers both architectures; absent values produce zero results harmlessly.
    The `network:distributed` filter is kept here (for its fixed_ip → trie
    entry) but is NOT used by `mac_tenant_map` population (§3.1).

    DHCP nit: the gateway_ip/32 → INFRA rule only catches the DHCP server's
    side of the exchange. The broadcast DISCOVER/REQUEST half — destined for
    255.255.255.255 — matches no per-tenant trie row and bills EXTERNAL
    (the §8 Tier 3 broadcast/multicast row; covered by that row's optional
    global-INFRA-prefix fix if ever taken), while the unicast response half
    bills INFRA. Trivial volume; document-accepted.

  Step 5 — Static routes (extraroutes) on T's routers   [the hard part]
    for each router R where R.tenant_id == T:
      for each (destination_cidr, nexthop) in R.routes:
        zone = resolve_static_route_zone(R, destination_cidr, nexthop)
        add (T, destination_cidr) → zone

```

**No per-host MAC enumeration step is needed.** Traditional Neutron with DVR required a "Step 6" that queried `dvr-mac-addresses` to discover the per-host MAC each chassis used for the same logical router. OVN eliminates this: a logical router's interface has a single MAC across all chassis, and the per-chassis routing logic lives in OVS flow rules rather than per-host namespaces. The standard port query in Step 4 picks up that single MAC, and it is correct for every chassis.

If CubeCOS ever supports a traditional Neutron deployment with DVR, this step would need to be reinstated; see §13.2.

### 5.3 The static route resolver (the heart of step 5)

> Interactive walkthrough: [`docs/static-route-resolver.html`](./static-route-resolver.html) animates this algorithm step-by-step across five canonical topologies (single-hop, VM-appliance, multi-hop, cycle, ambiguity), highlighting the matching line in [`internal/neutron/resolve.go`](../internal/neutron/resolve.go) as it executes. Open in any browser; no build step.

CIDR alone is ambiguous — multiple tenants can register the same CIDR. The disambiguator is **the nexthop**, not the destination.

A static route may also be **multi-hop**: T1's router points to T2's router, which has its own extraroute pointing to T3, and so on until some router has the destination directly attached. The resolver must walk this chain — a single-hop check would falsely return `EXTERNAL` whenever the destination is more than one router away.

The algorithm is therefore an **iterative graph walk** with cycle detection and a hop limit.

```
function resolve_static_route_zone(R, destination_cidr, initial_nexthop):

  source_tenant = R.tenant_id
  current_router = R
  current_nexthop = initial_nexthop
  visited = { R.id }
  MAX_HOPS = 16

  for hop in 0 .. MAX_HOPS-1:

    Step A — Anchor:
      iface_subnet = pick current_router's interface subnet S where current_nexthop ∈ S.cidr
      if iface_subnet is None:
         return EXTERNAL    ← nexthop not on a directly-attached subnet (misconfig)

    Step B — Identify the device on the other end:
      nexthop_port = port in iface_subnet with fixed_ip == current_nexthop
      switch nexthop_port.device_owner:
        "network:router_interface" → next_router = router with id == device_id; proceed
        starts with "compute:"     →
          vm_owner = nexthop_port.tenant_id
          return zone_for(vm_owner, source_tenant, iface_subnet.network)
          ← VM appliance: classify by the appliance's Neutron-visible tenant.
          ← Nova writes compute:<az-name> — "nova" is only the default AZ —
            so the match is on the prefix, never the literal.
          ← The destination beyond the appliance is opaque; we stop tracing here.
        anything else              → return EXTERNAL    ← unknown device type

      if next_router.id in visited:
         log "routing cycle detected"; return EXTERNAL
      visited.add(next_router.id)

    Step C — Is destination directly attached to next_router?
      candidates = subnets on next_router whose cidr ⊇ destination_cidr,
                   excluding iface_subnet.network (the network we entered through)

      if exactly one candidate, OR multiple all-same-owner:
         owner = that subnet's network.tenant_id
         return zone_for(owner, source_tenant, that network)

      if multiple candidates with different owners:
         log "ambiguous owner"; return EXTERNAL   (or refuse to start in strict mode)

    Step D — If not directly attached, follow next_router's own extraroutes:
      Find next_router.routes entries whose destination ⊇ destination_cidr.
      Pick the longest-prefix match (LPM semantics).

      if a matching route exists:
         current_router  = next_router
         current_nexthop = matching_route.nexthop
         continue                                  ← next iteration: hop further

    Step E — Default route fallback:
      if next_router has external_gateway_info:
         return EXTERNAL                           ← traffic escapes via internet
      else:
         return EXTERNAL                           ← unreachable per Neutron; misconfig

  # Loop fell through without resolving — chain too long.
  log "MAX_HOPS exceeded"; return EXTERNAL


function zone_for(owner_tenant, source_tenant, network):
  if network is router:external == true:  return EXTERNAL
  if network.shared == true:               return SHARED   ← see §5.2 Step 3
  if owner_tenant == source_tenant:        return SAME_TENANT
  return OTHER_TENANT
```

The `shared` check sits **above** the owner check so that a shared
network owned by the source tenant returns SHARED, not SAME — the
trie cannot resolve per-VM ownership inside a shared CIDR, and
returning SAME would systematically under-bill the owner's traffic
to non-owner VMs that have attached to the shared network. The
MAC-first hot path provides exact SAME_TENANT classification for
L2 intra-tenant traffic on shared networks; SHARED is the honest
label for the L3-routed-fallback case only.

**Cycle detection.** A misconfigured deployment can have routing loops (R2 forwards to R3, R3 forwards back to R2). The `visited` set bounds the walk to each router at most once and bails to `EXTERNAL` on detection. Without this, the resolver would infinite-loop at cold-start.

**Hop limit.** `MAX_HOPS = 16` is generous — real OpenStack deployments rarely exceed 3–4 hops. If hit, it's almost certainly a configuration issue worth surfacing.

**Performance.** Each iteration is O(1) hashmap lookups against the cached Neutron snapshot. A typical resolution completes in microseconds. Cold-start runtime is dominated by API fetch latency, not the trace.

**VM-appliance nexthop.** When a nexthop resolves to a `compute:<az>` port (a VM acting as a software router, NAT box, or VPN gateway — Nova writes `compute:<az-name>` as the device_owner, `compute:nova` being just the default availability zone), the trace stops there — Neutron has no visibility into what the appliance does with the traffic. The zone for the destination CIDR is determined by the appliance's own Neutron tenant using `zone_for`, giving correct attribution for the immediate hop. However, when the appliance forwards traffic onward, that egress is independently counted at the appliance's own tap — the same bytes appear in billing twice, once at the originating VM's tap and once at the appliance's tap. See §8 Tier 4 and Scenario L.

Why CIDR alone is insufficient — and why we considered and rejected the simpler approach — is detailed in [C.9](#c9-direct-cidr-lookup-without-nexthop-trace).

### 5.4 Worked example — single hop

```
DEPLOYMENT
  T1=1001 (frontend), T2=1002 (analytics), admin=9999

  Networks:
    net-T1   (T1)      10.0.1.0/24, 10.0.2.0/24
    net-T2   (T2)      10.1.1.0/24, 10.50.0.0/16
    net-shr  (admin)   192.168.100.0/24    [shared=true]
    net-pub  (admin)   203.0.113.0/24      [external]
    net-mgmt (admin)   169.254.169.254/32  [metadata]

  Routers:
    router-T1 (T1):
       interfaces  10.0.1.1, 10.0.2.1, 192.168.100.10
       ext gateway → net-pub
       extraroutes:
         dest 10.50.0.0/16    via 192.168.100.20
         dest 172.16.99.0/24  via 10.0.1.50

    router-T2 (T2):
       interfaces  10.1.1.1, 10.50.0.1, 192.168.100.20
       ext gateway → net-pub
```

#### Trie for T1

| Step | Source | Resolution | Trie entry |
|---|---|---|---|
| 1 | catchall | — | `(T1, 0.0.0.0/0) → EXTERNAL` |
| 2 | net-T1 owned | `T1 == T1` | `(T1, 10.0.1.0/24) → SAME` |
| 2 | net-T1 owned | `T1 == T1` | `(T1, 10.0.2.0/24) → SAME` |
| 3 | net-shr shared | not T1 | `(T1, 192.168.100.0/24) → OTHER` |
| 4 | metadata svc | infra | `(T1, 169.254.169.254/32) → INFRA` |
| 5 | extraroute `10.50.0.0/16` via `192.168.100.20` | hop 0: nexthop → router-T2; Step C finds `10.50.0.0/16` directly attached → owner T2 | `(T1, 10.50.0.0/16) → OTHER` |
| 5 | extraroute `172.16.99.0/24` via `10.0.1.50` | hop 0: nexthop port has `device_owner=compute:nova`, `tenant_id=T1`; `zone_for(T1, T1, net-T1)` → SAME | `(T1, 172.16.99.0/24) → SAME` |

#### Trie for T2 (same data, different perspective)

| Trie entry | Why |
|---|---|
| `(T2, 0.0.0.0/0) → EXTERNAL` | catchall |
| `(T2, 10.1.1.0/24) → SAME` | T2 owned |
| `(T2, 10.50.0.0/16) → SAME` | T2 owned (note: same CIDR as in T1's view, opposite zone) |
| `(T2, 192.168.100.0/24) → OTHER` | shared |
| `(T2, 169.254.169.254/32) → INFRA` | metadata |

### 5.5 Worked example — multi-hop chain

A more demanding case: 5 routers in series, ending in a different tenant. This is what verifies the iterative trace works correctly.

```
DEPLOYMENT
  Tenants: T1=1001, T2=1002, T3=1003, T4=1004, T5=1005

  Routers chained via four shared transit networks:

    transit-A  10.10.1.0/24   shared=true
    transit-B  10.10.2.0/24   shared=true
    transit-C  10.10.3.0/24   shared=true
    transit-D  10.10.4.0/24   shared=true

  Routers (each owned by its tenant):
    R1 (T1):   interfaces in net-T1, transit-A
       extraroute:  dest 10.99.0.0/16  via 10.10.1.20
    R2 (T2):   interfaces in net-T2, transit-A, transit-B
       extraroute:  dest 10.99.0.0/16  via 10.10.2.30
    R3 (T3):   interfaces in net-T3, transit-B, transit-C
       extraroute:  dest 10.99.0.0/16  via 10.10.3.40
    R4 (T4):   interfaces in net-T4, transit-C, transit-D
       extraroute:  dest 10.99.0.0/16  via 10.10.4.50
    R5 (T5):   interfaces in net-T5, transit-D
       net-T5 owns 10.99.0.0/16  ← FINAL DESTINATION (directly attached to R5)

  Nexthop addresses on each transit:
    10.10.1.20  = R2's interface in transit-A
    10.10.2.30  = R3's interface in transit-B
    10.10.3.40  = R4's interface in transit-C
    10.10.4.50  = R5's interface in transit-D
```

#### Trace for T1's extraroute `dest=10.99.0.0/16 via 10.10.1.20`

| Hop | Current router | Nexthop | Step A — anchor | Step B — peer | Step C — directly attached? | Step D — extraroute? | Action |
|---|---|---|---|---|---|---|---|
| 0 | R1 | 10.10.1.20 | transit-A | R2 (router_interface) | no `10.99.0.0/16` on R2 | LPM hit on R2: `10.99.0.0/16 via 10.10.2.30` | continue → R2 |
| 1 | R2 | 10.10.2.30 | transit-B | R3 | no | LPM hit on R3: via 10.10.3.40 | continue → R3 |
| 2 | R3 | 10.10.3.40 | transit-C | R4 | no | LPM hit on R4: via 10.10.4.50 | continue → R4 |
| 3 | R4 | 10.10.4.50 | transit-D | R5 | **yes**: `10.99.0.0/16` directly on net-T5 | — | **resolve** |

`zone_for(owner=T5, source=T1, network=net-T5)`:
- net-T5.tenant_id = T5 ≠ T1 → `OTHER_TENANT`

**Trie entry for T1:** `(T1, 10.99.0.0/16) → OTHER_TENANT` ✓

The chain crosses four transit networks and four router hops, ending in a different tenant five tenants away from the source. The trace correctly identifies T5 as the owner and produces `OTHER_TENANT`.

#### What if T5 didn't exist? (cycle / unreachable)

If R4's extraroute pointed back to R2 instead of forward to R5, the `visited` set catches the cycle at hop 4: `R2.id ∈ visited` → return `EXTERNAL`, log a warning. No infinite loop.

If R4 had no route for `10.99.0.0/16` and no external gateway, Step F returns `EXTERNAL`. Operator misconfig — the route is unreachable per Neutron's view.

If the chain genuinely is longer than `MAX_HOPS = 16` (unrealistic in practice), the loop bails and returns `EXTERNAL` with a warning. Worth logging but extremely rare.

### 5.6 What ambiguity-after-scoping means

If, after step 5d, the peer router has connections to two networks both carrying `10.50.0.0/16` with different owners, we have a genuine ambiguity. Three policies:

| Policy | Behavior |
|---|---|
| **Safe-billing** | Fallback `ZONE_EXTERNAL` and log loudly |
| **Pessimistic** | Fallback `ZONE_OTHER_TENANT` (definitely cross-tenant) |
| **Strict** | Refuse to start; surface the config error |

For production billing engines, **Strict is recommended** — better to refuse than to bill wrong.

### 5.7 Update semantics — Kafka-driven incremental changes

Live metadata updates are driven by the Kafka consumer (`internal/kafka`) and the periodic reconcile (`internal/reconcile`). The consumer never applies changes itself: it decodes oslo notifications from `notifications.info` and, on each committed (`*.end`) Neutron change, kicks the reconciler. The reconciler is the single applier — a 5-minute timer and the Kafka kicks feed the same goroutine — so it runs one full Neutron snapshot fetch, diffs it against the last committed state, and pushes only the delta. The kick path and the periodic safety net therefore execute identical apply logic and never overlap. (The kick carries no payload; routing every change through one re-sync keeps a single apply path and guarantees the post-event trie matches a cold-start at the same instant, at the cost of one Neutron `Sync` per debounced burst — the same operation the periodic reconcile already runs.)

The trie delta is applied by `kernelwriter.ApplyTrieDelta`. The BPF LPM trie supports per-entry insert and delete, but **not** transactional multi-entry batches. For changes that touch multiple entries (e.g., a `router.routes` update that affects N CIDR mappings), strict ordering is required:

```
For a change set that REPLACES entries:
  1. Compute the diff:   new_entries[], obsolete_entries[]
  2. Insert / overwrite all new_entries[]   (LPM allows upsert at same key)
  3. Delete obsolete_entries[]              (only after all inserts complete)
```

`ApplyTrieDelta` implements exactly this: it skips unchanged rows, upserts added/changed rows, and — only if every upsert succeeded — deletes the obsolete ones (an upsert failure keeps the stale rows, harmless under LPM longest-match, and the next pass retries). The mac_tenant_map side is reconciled in the same pass: new ports are learned (userspace→kernel), and deleted ports are MarkDeleted into the 60s lingering ghost (§3.3) rather than removed outright.

**Why this order matters.** If we deleted first, there would be a window (microseconds, but real on a busy system) where the entry doesn't exist; packets matching that CIDR would fall through to the next-longest match — typically the catchall `(T, 0.0.0.0/0) → EXTERNAL`. Those packets would then be **permanently miskeyed in the kernel `flow_key`** because `dst_zone` is baked into the key — the entry never reclassifies even after the trie is fixed. Insert-first guarantees at least one valid entry exists at every moment.

**Atomicity guarantee.** LPM matches are deterministic per-packet — the kernel walks the trie and returns whichever stored entry has the longest matching prefix. During the insert phase, both old and new entries may briefly coexist; LPM's longest-match semantics resolve them deterministically. After the delete phase, only the new state remains. No racy "neither valid" state.

**For tenant-cross-cutting changes** (e.g., a network's `shared` flag flips, affecting how every tenant sees that subnet): batch all the per-tenant inserts before any delete. The transient state is "both old and new visible" which under LPM longest-match is safe — every flow is classified by whichever prefix is more specific.

**Failure mode if violated.** If an implementation does delete-then-insert (the naive order), every Kafka-driven route change creates a small burst of `ZONE_MISS` or wrongly-zoned entries that persist until those flows expire from `telemetry_map` (via TTL GC, typically 60s for low-traffic flows). Visible as a brief blip in zone distribution after each router config change.

---

## 6. Octavia LB Attribution

### The two-connection reality

An [Octavia](#b9-octavia-and-amphora-vms) load balancer is implemented by an **Amphora** VM in the admin project, running HAProxy. The traffic appears to flow as one client-to-backend stream, but at the network level it is **two distinct TCP connections** (verified empirically):

```
   Segment 1                              Segment 2
   ──────────                             ──────────
   client ↔ Amphora                       Amphora ↔ backend
   (HAProxy terminates this conn          (HAProxy originates this as a
    inside the Amphora VM)                 brand-new TCP session)
```

HAProxy is an application-layer terminator. From the kernel's perspective these are two completely separate TCP sessions joined only by HAProxy's userspace logic. Conntrack physically cannot bridge them — there is no "single record" with both `client_ip` and `backend_vm_ip`.

This is the same model AWS (ELB) and GCP (Cloud Load Balancing) use: each segment is independently captured at its interface (ENI/VNIC/tap) and independently billed. The billing pipeline sums and dedupes downstream — charging postures and consumption rules in [§11.5 Billing model & consumption contract](#billing-model--consumption-contract).

**Provider scope: amphora only.** The two-connection model below assumes the **amphora** provider — the only Octavia provider enabled on target deployments (verified empirically: the provider list shows amphora alone, and every live LB uses it). The **OVN provider** (no Amphora VM, source IP preserved end-to-end, a single network segment) is a fundamentally different shape and is explicitly out of scope. When Octavia support lands, the agent should log the configured provider at cold-start so a non-amphora deployment is caught loudly rather than silently mis-modeled.

### Billing model — both segments attribute to the LB owner

Naïvely, traffic at the backend's tap appears to come from the Amphora's MAC and would attribute to admin (Amphora's owner). But the customer is the LB's owning tenant. The fix: tag Amphora MACs at cold-start.

| Segment | Captured at | dst_zone | Tenant attribution |
|---|---|---|---|
| 1: client ↔ Amphora | Amphora's tap | depends on client location (EXTERNAL / OTHER / SAME) | LB owner |
| 2: Amphora ↔ backend | Amphora's tap **and** backend's tap | INFRA (LB internal plumbing) | LB owner |

Total LB-mediated billing = Segment 1 + Segment 2 bytes. Segment 2 appears at two taps as the standard one-`tx`-plus-one-`rx` emission pair (§8 Tier 4 #15); under §11.5's per-side charging postures no dedup is needed — and Segment 2 is `infra`, $0 today.

### Mechanism — Amphora MAC flag, not conntrack

At cold-start, the Go agent queries the Octavia API and populates each Amphora's MAC in `mac_tenant_map` with two pieces of metadata:

- `IsAmphora = true`
- `LBOwnerTenant = <tenant_id of the LB>`

When a packet arrives:

- If `peer_mac` is flagged Amphora → attribute bytes to `LBOwnerTenant` (instead of Amphora's own admin tenant).
- If `peer_mac` is not an Amphora → normal hybrid lookup (§4.3).

**No conntrack lookup is required for attribution.** The MAC flag alone is sufficient, and works identically at the Amphora's tap and the backend's tap.

### Optional refinement — conntrack-based zone for Segment 1

At the Amphora's tap, the on-wire packet's `remote_ip` is the post-DNAT Amphora address. To determine the actual client's zone (was the request from the internet, another tenant, or the same tenant?), the kernel can optionally use [`bpf_skb_ct_lookup`](#b6-bpf_skb_ct_lookup-and-conntrack) to recover the pre-NAT tuple:

```
ct = bpf_skb_ct_lookup(skb, ...)
if ct: real_client_ip = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip
       re-classify dst_zone using real_client_ip via the LPM trie
else:  dst_zone = EXTERNAL    ← safe-billing default
```

**Critical constraint (verified empirically).** This lookup only works at the **Amphora's tap on the Amphora's compute host**. Reasoning:

1. The conntrack entry that contains the original client_ip is for Segment 1 (`client_ip ↔ floating_ip ↔ Amphora_ip`). It lives on the host that performed the FIP DNAT. In OVN deployments verified empirically, that's the Amphora's compute host (OVN does the DNAT distributed via OVS flow rules with `ct()` actions, and the entry is written to the host's kernel conntrack table).
2. At the backend's tap, the visible conntrack entry is Segment 2's (`Amphora_ip ↔ backend_vm_ip`) — a separate flow with no record of the original client.

**Do not call `bpf_skb_ct_lookup` at the backend's tap.** It would either miss or return Segment 2's entry, which doesn't help. Use the unconditional `INFRA` zone for Segment 2 instead.

### Failure modes

| What fails | Impact | Severity |
|---|---|---|
| Conntrack lookup misses (first SYN, TTL expiry, UDP idle >30s, lookup at wrong tap) | Segment 1 falls back to `dst_zone=EXTERNAL`. **Attribution to LB owner is unaffected** because it comes from the MAC flag, not conntrack | Low (see §8 Tier 4 #17) |
| Amphora MAC missing from `mac_tenant_map` (Octavia API stale) | Traffic attributes to admin (Amphora's tenant). Self-corrects on next Kafka event for Amphora creation, or on the next full Neutron/Octavia reconcile | Medium |
| UDP listener with sparse traffic | Conntrack default UDP timeout is 30s. Long-idle UDP LB flows lose the Segment 1 conntrack entry between packets → Segment 1 zone falls back to EXTERNAL. Attribution unaffected. Tested deployments use TCP LBs only, so this is not exercised today | Low |

### What this design deliberately does NOT do

Some LB telemetry stories try to "stitch" a single billable record across Conn1 and Conn2 by recovering the client tuple at the backend's tap. We don't:

- AWS and GCP don't (they emit per-ENI / per-VNIC flow records).
- The underlying conntrack physically can't bridge HAProxy-terminated connections.
- Attribution-to-LB-owner doesn't require it.

Our model is segment-by-segment, summed at the billing pipeline.

### Why `bpf_skb_ct_lookup` is TC-only

This helper is only available in TC programs, not XDP — one of the reasons TC was chosen. See [C.1](#c1-xdp-hook-instead-of-tc).

---

## 7. Scenario Walkthroughs

For each scenario: where the packet appears, what the classification produces, whether it's counted correctly on each side.

### Scenario A — Same tenant, same subnet (direct L2)

```
VM-A (T1, 10.0.1.5, mac=AA) ──→ VM-B (T1, 10.0.1.6, mac=BB)
```

| Hook | direction | vm_mac | peer_mac | Lookup | dst_zone |
|---|---|---|---|---|---|
| VM-A tap, ingress | 0 | AA → T1 | BB → T1 | tenants match (hybrid) | SAME ✓ |
| VM-B tap, egress | 1 | BB → T1 | AA → T1 | tenants match (hybrid) | SAME ✓ |

Trie not touched. Pure MAC-based classification.

### Scenario B — Same tenant, different subnets via tenant router

```
VM-A (T1, subnet1) ──→ router-T1 ──→ VM-B (T1, subnet2)
```

| Hook | vm_mac | peer_mac | peer in map? | Path | dst_zone |
|---|---|---|---|---|---|
| VM-A tap, ingress | AA→T1 | router_iface_mac (subnet1) | likely yes (router iface) | hybrid: tenants match | SAME ✓ |
| VM-B tap, egress | BB→T1 | router_iface_mac (subnet2) | yes | hybrid: tenants match | SAME ✓ |

If router interface MACs are in `mac_tenant_map` (recommended), it stays exact. Otherwise fallback LPM with subnet1/subnet2 entries.

### Scenario C — Cross-tenant via shared network or address scope

```
VM-A (T1) ──→ shared bus ──→ router-T2 ──→ VM-X (T2)
```

| Hook | vm_mac | peer_mac | Path | dst_zone |
|---|---|---|---|---|
| VM-A tap, ingress | AA→T1 | router_mac (peer router) | LPM (T1, X_ip) → trie has (T1, X's subnet) → OTHER | OTHER ✓ |
| VM-X tap, egress | XX→T2 | router_mac | LPM (T2, A_ip) → (T2, A's subnet) → OTHER | OTHER ✓ |

Requires Go cold-start to have populated cross-tenant entries via address-scope discovery or extraroute resolution.

### Scenario D — External egress (VM → internet)

```
VM-A (T1, 10.0.1.5) ──→ tenant router ──→ NAT GW ──→ 8.8.8.8
```

| Hook | direction | vm_mac | remote_ip | LPM | dst_zone |
|---|---|---|---|---|---|
| VM-A tap, ingress | 0 | AA→T1 | 8.8.8.8 | catchall `0.0.0.0/0` | EXTERNAL ✓ |

### Scenario E — External ingress (internet → VM via floating IP)

```
client 1.2.3.4 ──→ floating IP 203.0.113.5 ──[DNAT on net node]──→ VM-A
```

DNAT happens upstream at the network node. At VM-A's tap: `src_ip=1.2.3.4, dst_ip=10.0.1.5` (the internal IP).

| Hook | direction | vm_mac | remote_ip | LPM | dst_zone |
|---|---|---|---|---|---|
| VM-A tap, egress | 1 | AA (h_dest) | 1.2.3.4 (saddr) | catchall | EXTERNAL ✓ |

### Scenario F — Octavia LB (external → Amphora → backend VM)

```
client 1.2.3.4 ──→ floating IP ──[DNAT]──→ Amphora (admin) ──[HAProxy NEW conn]──→ VM-B (T1 backend)
                                            ↑                                       ↑
                                            two TCP connections (Seg1, Seg2);       both at the wire level
                                            HAProxy terminates Seg1 and             — NOT one transparent flow
                                            originates Seg2
```

Two distinct TCP connections per LB request (§6). We capture each at its tap and bill both to the LB owner.

**Segment 1: client ↔ Amphora.** At the Amphora's tap (egress, Amphora receiving):

| direction | vm_mac | peer_mac | Lookup | dst_zone | Attribution |
|---|---|---|---|---|---|
| 1 | Amphora_mac (h_dest) | client_mac/FIP-gateway (h_source) | `mac_tenant_map[Amphora_mac].IsAmphora == true` → LB-owner branch | EXTERNAL (optional refinement: `bpf_skb_ct_lookup` recovers pre-NAT `client_ip` → trie lookup) | **LB owner (T1)** via the Amphora's `LBOwnerTenant` field — NOT admin |

**Segment 2: Amphora ↔ backend.** At VM-B's tap (egress, VM-B receiving):

| direction | vm_mac | peer_mac | Lookup | dst_zone | Attribution |
|---|---|---|---|---|---|
| 1 | VM-B_mac (h_dest) | Amphora_mac (h_source) | `mac_tenant_map[Amphora_mac].IsAmphora == true` → LB-owner branch | **INFRA** (unconditional — Segment 2 is internal LB plumbing; do NOT call `bpf_skb_ct_lookup` here) | **LB owner (T1)** |

**Critical:** the conntrack lookup is **optional and Amphora-tap-only** — at the backend's tap, the conntrack entry is Segment 2's (`Amphora_ip ↔ backend_ip`) and contains no client_ip. See §6 for full rationale; verified empirically.

Total bytes billed to T1 = Segment 1 + Segment 2. Segment 2 is also visible at the Amphora's tap (other direction) — the standard both-sides emission of §8 Tier 4 #15, harmless under §11.5's charging postures (`infra` bills $0 today).

### Scenario G — Static route, Neutron-managed

```
T1's router has extraroute: dest=192.168.50.0/24 via 10.0.1.100
```

Resolution at cold-start: nexthop 10.0.1.100 → port → device → reachable subnets → owner of 192.168.50.0/24. Trie entry pre-baked. Per-packet: just an LPM lookup, looks identical to a directly-attached subnet.

### Scenario H — Static route, OS-level (inside the VM)

```
Operator runs inside the VM:
  ip route add 172.16.0.0/12 via 10.0.1.100
```

Neutron has no record. Trie has no entry. Packet falls to catchall → `ZONE_EXTERNAL`.

**Verdict:** Unsolvable without an in-VM agent (which defeats the eBPF design — see [C.11](#c11-in-vm-agent-for-os-level-routes)). The fallback is the safest billing failure mode — tenant gets charged at the external rate. Documented exception.

### Scenario I — Same-host, same-tenant (VM-A and VM-B on same hypervisor)

OVS forwards packet within br-int, no VXLAN. Each tap sees the packet.

| Hook | Result | dst_zone |
|---|---|---|
| VM-A tap, ingress | counted | SAME ✓ |
| VM-B tap, egress | counted | SAME ✓ |

Both-sides counting is intentional: the transfer emits exactly one `tx` series (VM-A's tap) and one `rx` series (VM-B's tap). The per-side charging postures (§11.5) make the pair safe by construction — `same_tenant` bills $0, so nothing is double-charged.

### Scenario J — Cross-host, same-tenant (Geneve tunneled)

```
VM-A on host1 ──→ OVS encap ──→ Geneve ──→ host2 OVS decap ──→ VM-B
```

| Hook | What it sees | dst_zone |
|---|---|---|
| VM-A tap on host1, ingress | plain Ethernet (pre-encap) | SAME ✓ |
| VM-B tap on host2, egress | plain Ethernet (post-decap) | SAME ✓ |

The overlay tunnel is invisible to TC at the tap layer, which is correct. (OVN ML2 tunnels with Geneve, not VXLAN; the distinction has zero behavioral impact here — we observe pre-encap/post-decap frames either way.)

### Scenario K — Multi-hop static route across multiple tenants

```
VM-A (T1) ──→ R1 ──→ R2 ──→ R3 ──→ R4 ──→ R5 ──→ VM-Z (T5)
              T1's   T2's   T3's   T4's   T5's
              router router router router router

Each Rn → R(n+1) link is a shared transit network with its own /24.
Only R5 has VM-Z's CIDR (10.99.0.0/16) directly attached.
```

At runtime (kernel side), the per-packet view is unchanged from any other routed flow:

| Hook | direction | vm_mac | peer_mac | LPM lookup | dst_zone |
|---|---|---|---|---|---|
| VM-A tap, ingress | 0 | AA→T1 | R1's router interface MAC | `(T1, 10.99.0.0/16)` | OTHER ✓ |

The hard work happens at **cold-start**, not per-packet. The trie entry `(T1, 10.99.0.0/16) → OTHER_TENANT` was pre-baked by the iterative resolver walking R1 → R2 → R3 → R4 → R5 and finding T5 at the end. See [§5.5](#55-worked-example--multi-hop-chain) for the step-by-step trace.

The kernel does **one** LPM lookup per packet regardless of how many routers the trace traversed during boot. Multi-hop and single-hop routes are indistinguishable at runtime.

### Scenario L — Static route via VM appliance (compute:nova nexthop)

```
T1's router has extraroute: dest=172.16.99.0/24 via 10.0.1.50
Port at 10.0.1.50: device_owner=compute:nova, tenant_id=T1  (T1's own VM appliance)
```

At cold-start the resolver reaches 10.0.1.50, identifies `compute:nova`, and calls `zone_for(T1, T1, net-T1)` → SAME_TENANT. Trie entry baked: `(T1, 172.16.99.0/24) → SAME`.

At packet time (VM-A → 172.16.99.x):

| Hook | direction | vm_mac | remote_ip | LPM | dst_zone |
|---|---|---|---|---|---|
| VM-A tap, ingress | 0 | AA→T1 | 172.16.99.x | `(T1, 172.16.99.0/24)` → SAME | SAME |

**Double-billing.** When the VM appliance at 10.0.1.50 forwards the packet onward, that forwarded egress is independently counted at the appliance's own tap — attributed to T1 again. The same bytes are billed at both hops as separate flows (different MAC pairs). Billing aggregation must account for this when tenants deploy forwarding appliances. See §8 Tier 4 #21.

---

## 8. Edge Cases & Accuracy Ceiling

### Tier 1 — Hard limits (eBPF cannot count these at all)

| # | Edge case | Impact | Mitigation |
|---|---|---|---|
| 1 | [DPDK / userspace OVS datapath](#b10-dpdk--sr-iov--smart-nic) | TC hooks don't fire | Detect at boot; fall back to OVS sFlow for those VMs, or block at admission |
| 2 | [SR-IOV passthrough](#b10-dpdk--sr-iov--smart-nic) | No tap interface exists | Same as DPDK — needs NIC-level telemetry |
| 3 | Smart NIC offload (BlueField, ASAP²) | Datapath in HW, software taps bypassed | Same as SR-IOV |
| 3a | Neutron trunk ports / VLAN-aware VMs | 802.1Q-tagged frames (`0x8100`/`0x88A8`) on the trunk parent tap fail `telemetry.c`'s ethertype gate and pass uncounted — subport traffic is invisible (not even ZONE_MISS). The loss is asymmetric: host→VM may still count where OVS leaves the tag in skb metadata (VLAN tag offload) and the linear data starts at the inner IP header, while VM→host carries the tag in-band and never counts — corrupting in/out ratio sanity checks. Meanwhile the metadata layer admits `trunk:*` subport MACs into `mac_tenant_map` — entries the data plane can never hit | Cold-start warn-log + `lachesis_neutron_trunk_subports` gauge whenever the snapshot contains trunk subports; the kernel-side skipped-ethertype counter (issue #39) makes the in-band loss visible under live traffic. Real support — a single 802.1Q parse — is deferred pending a billing decision on the flow-key shape (§13.2 #8) |

### Tier 2 — Require explicit handling

| # | Edge case | Failure | Fix |
|---|---|---|---|
| 4 | Map full (>65k flows) | `bpf_map_update_elem` returns `-E2BIG`; bytes lost | Pressure-relief GC at >80% fill; evict oldest by `last_seen_ns`, **flush to GlobalState first**. The loss is observable: the kernel counts every rejected insert into `lachesis_bpf_update_failures_total{reason="update_failure"}` (§11.4) |
| 5 | PERCPU first-packet TOCTOU | Two CPUs race on creation; one's BPF_ANY overwrites the other | At most 1 packet lost per new flow per race. Documented & accepted |
| 6 | GSO/TSO/GRO offload | `skb->len` is the aggregated-skb byte count — correct payload, but per-segment L2/L3/L4 headers are counted once per superpacket rather than per wire segment, so bulk MTU-1500 TCP measures ≈4.35% under wire-equivalent (verified empirically on a single-node OVN deployment; provider-favorable to the customer). Both hooks count the same aggregated-skb basis — confirmed symmetric, no direction skew. Packet counts are superpacket counts, far under the wire segment count | Bill on bytes, not packets; the byte-basis contract is stated in §11.5 |
| 7 | Boot ordering: TC attached before trie populated | First flows permanently keyed `dst_zone=MISS` | Enforce sequence with sync gates ([§9](#9-boot-sequence-order-matters)) |
| 8 | WAL window (60s) | Up to 60s data loss on hard reboot | Documented; tunable |

### Tier 3 — Misclassification (bytes still counted, but wrong zone)

| # | Edge case | Failure | Fix |
|---|---|---|---|
| 9 | OS-level static route inside VM | Falls to EXTERNAL | Unsolvable; safe-billing fallback |
| 10 | Port security disabled + MAC spoof | Classification trusts the L2 headers, so a port with `port_security_enabled=false` (common for NFV) breaks the trust model two ways: a VM can emit frames carrying *another* tenant's MAC — `mac_tenant_map[spoofed]` hits the wrong tenant and inflates that tenant's bill — and any VM can spray random peer MACs to mint flow keys in the shared per-node `telemetry_map` (max 65,536 entries), a noisy-neighbor pressure vector | Billing integrity assumes port security on (the Neutron default); ports with it disabled are **attributed-but-untrusted**. The minting attack is observable: the spray pressures the map toward full and the resulting rejected inserts land in `lachesis_bpf_update_failures_total{reason="update_failure"}` (§11.4) |
| 11 | DVR with per-host router MACs (traditional Neutron only — n/a on OVN) | Each compute node's [DVR](#b8-openstack-networking-primer) router has a different MAC | Not encountered on OVN deployments (single MAC per logical router across chassis); if a traditional Neutron deployment is ever supported, reinstate the cold-start enumeration step — see §13.2 |
| 12 | VM uses its own GRE/VXLAN/IPsec | We see outer headers; classification on tunnel endpoint | Document; treat as external |
| 13 | IPv6 not in trie | All v6 → ZONE_MISS | Extend trie schema to 32-byte v6 keys (future work) |
| 14 | Late Kafka delivery (new VM not yet in MAC map) | First packets → ZONE_MISS | UnresolvedBuffer late-binding + write-back to LastEbpfRaw |
| 14a | OVN-synthesized DHCP `server_mac` not visible in Neutron port API (verified empirically) | DHCP responses to VMs have a `peer_mac` that misses `mac_tenant_map` | LPM trie carries the classification via `gateway_ip/32 → INFRA` (§5.2 Step 4). Visible as a small fraction of packets classified via the LPM-only path instead of the hybrid path; functionally correct |
| 14b | Allowed-address-pairs / VRRP virtual MAC | A keepalived pair in vMAC mode (`00:00:5e:00:01:xx`) or an allowed-address-pair configured with an explicit MAC sources frames from a MAC that is not a Neutron port MAC → `mac_tenant_map` miss → bytes land in `tenant_id="unknown"`, `zone="miss"` (unbillable). Default keepalived (GARP over the real port MACs) classifies correctly | Already counted as a structural revenue-leak contributor (§11.5 revenue-leak SLO). Deferred fix: fetch `allowed_address_pairs` in `ListPorts` and admit those MACs into `mac_tenant_map` (§13.2 #9) |
| 14c | VM→FIP hairpin | Same-cloud (even same-hypervisor, same-subnet) traffic addressed via a peer's floating IP bills `external` on *both* taps — OVN hairpin-SNATs the source to the client's own FIP, so each side sees an external-net address | Deliberate, not a misclassification to fix: documented as the chosen posture in §11.5 (public-cloud norm; tenants avoid it by addressing fixed IPs). Verified empirically on a single-node OVN deployment |
| 14d | Broadcast / multicast destinations | `255.255.255.255` (the DHCP DISCOVER/REQUEST half) and `224.0.0.0/4` (IGMP / mDNS / VRRP advertisement chatter) match no per-tenant trie row → sentinel catchall → `external` | Document-accepted (trivial volume). Optional one-line fix if it ever matters: add global INFRA trie rows for both prefixes |

### Tier 4 — Subtle correctness

| # | Edge case | Risk | Fix |
|---|---|---|---|
| 15 | Both-side counting (sender tap + receiver tap) | Naive cross-tap sum doubles the total | Deliberate, not a bug: each transfer emits exactly one `tx` series (sender's tap) and one `rx` series (receiver's tap). No host label exists on the metric — host identity is the Prometheus `instance` scrape label, so the pair lands on different `instance` series; billing consumes per-instance series and sums downstream. The per-side charging postures (§11.5) make the pair harmless: each side pays its own direction (`same_tenant` bills $0), never summed as one flow |
| 16 | VM live migration | Tap vanishes on the source host, appears on the destination host | Handled by the Netlink Watcher: DELLINK detaches on the source, NEWLINK attaches on the destination (the Neutron port is *not* deleted, so the Lingering Ghost path plays no role). Each host's agent emits its own cumulative series under its own `instance` label — one VM accrues up to N instances' series over its lifetime; the billing pipeline sums them (§11.5). Few-packet loss during the cutover is bounded |
| 17 | Conntrack miss on Segment 1 zone classification | The optional `bpf_skb_ct_lookup` at the Amphora's tap may miss (first SYN, TTL expiry, UDP >30s idle, lookup at the wrong tap). Segment 1 zone falls back to EXTERNAL | Attribution to LB owner is unaffected — it comes from the Amphora MAC flag, not conntrack. See §6 |
| 18 | u64 wraparound | At 10 Gbps continuous, ~467 years to overflow (2⁶⁴ / 1.25 GB/s ≈ 1.5×10¹⁰ seconds). The guard is one comparison, so add it anyway | — |
| 19 | Crashed agent leaves orphan TC filters | Stale filters double-count if agent restarts | Either zombie hunter at startup, or accept until reboot |
| 20 | Multicast / broadcast | One sent packet, many receivers → ingress sum doubles (this row is the *counting* angle; the *zone* angle — these destinations missing the trie → EXTERNAL — is Tier 3 row 14d) | Filter or accept as <0.1% noise |
| 21 | VM-appliance forwarding double-billing | Traffic via a compute:nova nexthop is billed at the originating VM's tap (at the appliance's tenant zone) AND again at the appliance's tap for the forwarded egress — same bytes, different MAC pairs, different flows | Documented; billing aggregation must dedup forwarding chains. Scenario L. |

### Honest accuracy ceiling

| Deployment | Realistic ceiling |
|---|---|
| Standard kernel-datapath OVS, port security on, no DPDK/SR-IOV, full Neutron-managed routing | ~99.9% byte accuracy. Residual error from PERCPU TOCTOU + conntrack misses on first SYN, both bounded |
| With DPDK or SR-IOV | Hard floor at "fraction of VMs using standard path". Non-standard VMs are blind spots |
| With OS-level static routes / port security disabled | Misclassification possible, but bytes still counted. Safe-billing fallback applies |

**True 100% requires:**
1. Admission control (block DPDK/SR-IOV for billed tenants), OR
2. A second telemetry plane for non-standard VMs (NIC counters, sFlow on infra), OR
3. Documented exceptions billed at uniform external rate

eBPF gives exact counting on every packet it sees. It cannot count packets it doesn't see — and that's a deployment-design issue, not an algorithm issue.

### Platform floor

The 5.10+ kernel requirement (§1) has two distinct origins worth recording. `BPF_MAP_LOOKUP_BATCH`, the syscall the scraper drains the map with, needs ≥5.6. The per-CPU zero-fill of recycled `PERCPU_HASH` elements — so a map slot reused after pressure-relief GC deletes an entry never returns a previous flow's stale counter on a CPU that didn't touch it — needs ≥5.10; this only starts to matter once GC actually deletes entries. Both staging clusters run 6.12.x, comfortably above the floor.

One related GC design rule: `last_seen_ns` is `CLOCK_MONOTONIC` (§3.1), which resets at every boot. The GC must never compare a WAL-restored timestamp from a prior boot against a current-boot kernel value — they live on different monotonic timelines, and a cross-boot subtraction yields garbage. WAL-restored state carries cumulative byte counters across boots; the eviction-age clock does not.

---

## 9. Boot Sequence (Order Matters)

```
1. Zombie Hunter
   → delete orphaned tc_telemetry_in/out filters from previous crash

2. Load eBPF objects
   → including subnet_zone_trie and mac_tenant_map specs

3. Cold-start metadata via Neutron API
   → populate ShardedMetadataMap
   → populate mac_tenant_map (full device_owner filter set per §3.1: compute:nova, network:router_interface, network:router_gateway, network:distributed)
   → populate subnet_zone_trie (5-step algorithm, §5)

4. Wire the Netlink subscriber (attach allowlist → TC programs)
   → TC attach is netlink-driven: when Run starts the subscriber it
     subscribes with kernel replay of existing links (ListExisting),
     attaching TC clsact and filling the Interface Registry; later
     RTM_NEWLINK events attach new taps dynamically. The Registry
     deduplicates attach attempts; genuine FilterReplace idempotence
     additionally requires the explicit filter priority that
     `tcattach.FilterPriority` pins — at priority 0 the kernel
     allocates a new chain per call, so every re-attach would stack
     another filter copy and double-count.

5. Read WAL → restore GlobalState

6. Start the Run workers (drain-ordered): netlink subscriber
   (performs step 4's attach sweep), scraper, WAL flusher,
   /metrics + /debug HTTP server
   → the scraper's first BatchLookup merges kernel deltas into
     GlobalState against the WAL-restored LastEbpfRaw values

7. Start GC goroutine (lingering ghost + map pressure relief)

8. Start periodic reconcile + Kafka consumer (live metadata updates):
   the reconciler is the single applier; the Kafka consumer decodes
   notifications and kicks it on each committed Neutron change, while
   a 5-minute timer kicks it as the outage safety net (§5.7)
```

Implementation mapping (`internal/agent/bootstrap_linux.go`): steps 1–5
run straight-line inside `Bootstrap` — `boot.Sequencer` phases
`BPFLoaded → MetadataReady → Attached → StateRestored` — and steps 6–8's
workers start in `Agent.Run` via the drain-ordered `workers()` table
(ghost sweeper, kafka consumer, reconciler, scraper, WAL). Each
post-`StateRestored` worker awaits that phase before its first action.

### Failure modes if order is violated

| Skip / reorder | Consequence |
|---|---|
| TC attach before trie populated | First flows permanently keyed `dst_zone=MISS`; never reclassify |
| GC before WAL merge | Active flows evicted before `LastEbpfRaw` set → counter spike on next scrape |
| Initial attach sweep before netlink subscribe | A tap created in the gap is never attached → silent undercount. Subscribe-with-replay closes the gap; the Interface Registry makes the replay/event overlap harmless (FilterReplace is idempotent because `tcattach.FilterPriority` pins the filter priority — at priority 0 the kernel would allocate a new chain per call and stack duplicate filters) |
| Skip Zombie Hunter | Restart stacks duplicate filters → every packet counted twice |

### Failure policy — Neutron API and Kafka outages

**Neutron API unreachable at cold-start** (step 3 cannot complete):
- Block with exponential backoff (start 1s, cap at 30s, indefinite retries).
- State surfaced via `lachesis_neutron_sync_age_seconds=-1` (never synced) and `lachesis_neutron_api_errors_total{endpoint, code}`.
- **Do NOT proceed to step 4 (TC attach).** Without metadata, every packet classifies as `ZONE_MISS`, and once that miss is written into the kernel `flow_key` it is permanent (zone is in the key — see §3.1). Blocking at boot is the only correctness-safe policy.
- An explicit `--unsafe-allow-degraded-boot` flag may be added later for operators who want fail-open behavior during planned Neutron upgrades; default is fail-closed.

**Neutron API unreachable at runtime** (cold-start succeeded, periodic refresh fails):
- Continue serving from the in-memory snapshot.
- Each failed call increments `lachesis_neutron_api_errors_total{endpoint, code}` and ages `lachesis_neutron_sync_age_seconds`.
- When Kafka is available each committed change kicks a reconcile within one pass; the 5-minute periodic reconcile is the safety net (see Kafka outage below). Both run on the one reconciler goroutine, so a kick and a timer tick never apply concurrently.

**Kafka unreachable** (cold-start succeeded, then Kafka becomes unreachable):
- No more kicks arrive, so the agent's metadata becomes increasingly stale: new VMs miss in `mac_tenant_map` → land in UnresolvedBuffer; deleted VMs over-stay their 60s ghost; route changes don't apply.
- **The periodic 5-minute reconcile mitigates this.** It is the same pass a kick triggers — a full snapshot fetch (as in cold-start step 3) diffed against current state, applying only the delta (trie via insert-then-delete, mac_tenant_map via insert / MarkDelete). **Bounds metadata staleness to 5 minutes regardless of Kafka availability.**
- `lachesis_kafka_lag_messages` and `lachesis_kafka_consume_errors_total` surface the outage; alerting threshold suggested: `lag > 1000` sustained.

**Partial Neutron failures** (e.g., `GET /v2.0/ports` succeeds, `GET /v2.0/routers` returns 500):
- **Cold-start is all-or-nothing.** If any required endpoint fails, the entire cold-start fails and the boot loop retries from the top. Starting with partial metadata reproduces the same permanent-miss problem as a full Neutron outage.
- **Runtime reconcile is best-effort per endpoint.** A 500 on one endpoint doesn't invalidate state derived from successfully-fetched endpoints; the per-endpoint error counter tracks recovery. The 5-minute reconcile will retry the failed endpoint on its next cycle.

---

## 10. Crash Resilience

### Agent crash (process killed, kernel intact)

**Designed (requires map pinning — deferred, §13.2 #7):**
- Kernel map pinned under `bpf.pin_path` → survives the process.
- New agent reads [WAL](#b11-write-ahead-log-wal) → restores GlobalState (cumulative counters and the settled-bytes accumulator, §3.5).
- BatchLookup reads the surviving kernel map → merges since last WAL checkpoint.
- **Net data loss: 0.**

**Implemented today (no pinning):** the orphaned TC filters do keep the old program + maps alive across the crash, but a restarted agent cannot reach an unpinned map — and the boot-time Zombie Hunter (§9 step 1) deletes those filters, dropping the last references. The old counters are gone; the agent loads a fresh collection and recovers from the WAL exactly like the hard-reboot path below (the `current < lastRaw` delta guard absorbs the empty map). **Net data loss today: ≤60s (the WAL flush window).** Pinning upgrades this to zero; until it lands, agent crash and hard reboot share one recovery path.

### Hard reboot (kernel destroyed)

- Kernel RAM gone → map starts empty.
- Delta math handles this: `current < last → treat current as fresh absolute`.
- WAL gives us up-to-60s-old GlobalState.
- **Net data loss: ≤60s of bytes** (the WAL flush window).

### Why not `BPF_MAP_TYPE_PERCPU_LRU_HASH`?

LRU silently evicts entries between scrapes. Bytes accumulated on an evicted entry are lost forever — unrecoverable. Pressure-relief GC (in Go) flushes to GlobalState **before** evicting, so the bytes survive. See [C.5](#c5-lru_hash-for-map-eviction) for full reasoning.

### Why not Prometheus `CounterVec`?

`CounterVec` resets to zero on process restart. Restart emits a lower cumulative value, `rate()` goes negative, billing dashboards break. The custom `prometheus.Collector` emits from GlobalState (loaded from WAL), so cumulative continuity holds across restarts. See [C.7](#c7-prometheus-countervec).

---

## 11. Performance Characterization

### Memory budget (per compute node)

| Structure | Size |
|---|---|
| `telemetry_map` PERCPU_HASH | `max_entries × (16 + 24×N_CPU)` bytes — preallocated. Defaults scale by CPU count (see formula below). Typical fill (~850 flows on 50-VM node): <1 MB |
| `subnet_zone_trie` LPM | 16,384 entries × ~24 bytes = ~400 KB max |
| `mac_tenant_map` HASH | 8,192 entries × 12 bytes = ~100 KB |
| `ShardedMetadataMap` (Go) | ~200 bytes per VM. 1,000 VMs → ~200 KB |
| `GlobalState` (Go) | ~60 bytes per flow entry. ~10,000 flows → ~600 KB |
| `UnresolvedBuffer` cap | 10,000 × ~80 bytes = ~800 KB max |

**`telemetry_map` sizing formula.** Because each entry pre-allocates one slot per CPU, the per-entry cost grows linearly with `N_CPU`. To keep the kernel-map footprint bounded across host sizes, derive `max_entries` from a memory budget (default **50 MB**):

```
max_entries = clamp(
    lower = 8192,                                             # working-set minimum
    upper = 65536,                                            # kernel/practical cap
    value = memory_budget_bytes / (16 + 24 × N_CPU)
)
```

Worked examples at the default 50 MB budget:

| N_CPU | per-entry bytes | max_entries (formula) | preallocated RSS |
|---|---|---|---|
| 32 | 784 | 65,536 (clamped) | ~50 MB |
| 64 | 1,552 | 33,775 → 32,768 | ~51 MB |
| 128 | 3,088 | 16,978 → 16,384 | ~51 MB |
| 192 | 4,624 | 11,338 → 8,192 (lower clamp) | ~38 MB |

**Sprint 1+ implementation note.** `max_entries` and the memory budget must be exposed as config flags (default budget 50 MB). Without this, deploying the agent on a 128-core host with `max_entries=65536` consumes ~200 MB of kernel RAM — 4× the documented budget. The `lachesis_bpf_map_max_entries` gauge (§11.4) surfaces the actual sized value per host.

**Total agent footprint (RSS)**: ~150–200 MB on a 32-core, 50-VM node. Most of it is the PERCPU map preallocation; well within budget for a daemon. On higher core counts, the budget keeps the kernel-map portion roughly flat at ~50 MB while `max_entries` shrinks proportionally.

### CPU overhead

Per-packet kernel cost is dominated by:
1. Header pull (`bpf_skb_pull_data` for ~34 bytes) — negligible
2. Two map lookups (`mac_tenant_map` + maybe `subnet_zone_trie`) — ~50 ns each on cached
3. One PERCPU update — ~30 ns

Total: ~150 ns / packet. At 10 Gbps × 64-byte packets = ~14.88 Mpps × 150 ns = **~2.2 ms of CPU per second per core in worst case**, or ~0.22% per core. Empirically: <1% delta in iperf3 throughput vs. baseline.

### Throughput characteristics

- Userspace `BatchLookup` polls every 10s. Single syscall, full snapshot. (`Iterate` is an alternative with the same data-volume cost; only syscall overhead differs.)
- **Map snapshot data volume = `entries × N_CPU × 24` bytes.** This is the userspace→kernel data transfer per scrape regardless of which API is used:

| Scenario | Volume | Wall time (memcpy + sum at ~50 GB/s) |
|---|---|---|
| 32-core, 10k flows | 7.5 MB | ~5 ms (matches the original estimate) |
| 64-core, 10k flows | 15 MB | ~10 ms |
| 128-core, 10k flows | 30 MB | ~30 ms |
| 128-core, 50k flows | 150 MB | ~100+ ms |

  At high core counts the documented "5 ms" is no longer realistic; the scrape budget must account for the actual N_CPU. The `lachesis_collect_duration_seconds` histogram (§11.4) surfaces this per node.

- Map iteration during GC: same cost; runs in the same scrape goroutine (after BatchLookup).
- **WAL flush** breaks into three phases, not just fsync:

| Phase | Cost | Lock held? |
|---|---|---|
| Copy GlobalState into a temp buffer | ~5 ms for 10k entries | RLock on GlobalState, briefly |
| Marshal Go struct → JSON | ~50–100 ms for 600 KB output | no lock |
| Write + fsync + rename + rotate `.bak` | ~5–10 ms (varies wildly on slow disks) | no lock |

  The original "5–10 ms" estimate referenced only the fsync — marshaling dominates. The critical section (lock-held) is just the copy phase, so a slow disk does NOT block the scraper. Per-phase metrics: `lachesis_wal_snapshot_copy_seconds`, `lachesis_wal_marshal_seconds`, `lachesis_wal_flush_latency_seconds` (the last covers write+fsync+rename only).

### Health metrics catalog

Two tiers of metrics. **Billing metrics** (the thing we exist to produce) are
emitted by the custom `prometheus.Collector` from `GlobalState` — labels match
the design's existing fan-out (tenant, zone, direction). **Health metrics**
(operator-facing instrumentation) are bounded-cardinality; an operator running
`promql` against one node should see <100 series total.

#### Billing (cumulative counters; emitted from GlobalState)

| Metric | Type | Labels |
|---|---|---|
| `lachesis_bytes_total` | counter | `tenant_id, zone, direction` |
| `lachesis_packets_total` | counter | `tenant_id, zone, direction` |

(Earlier drafts named these `lachesis_tenant_{bytes,packets}_total`; the
implemented, test-pinned names above are canonical — the `tenant_id` label
already carries the tenant dimension.)

**Billing label vocabulary.** These value sets are an API contract —
dashboards and billing pipelines pin them, so changing any value is a
breaking change once consumers exist.

| Label | Value set | Meaning |
|---|---|---|
| `tenant_id` | Neutron project UUID, or `unknown` | The tenant the flow's VM belongs to (resolved via `mac_tenant_map`); `unknown` when the VM MAC is not (yet) in the metadata map |
| `zone` | `external`, `same_tenant`, `other_tenant`, `infra`, `miss`, `shared` | The remote endpoint's zone relative to the VM's tenant (§4); the canonical strings from `bpf.ZoneCode.String()` |
| `direction` | `tx`, `rx` | `tx` = the VM is sending; `rx` = the VM is receiving |

**Why `tx`/`rx`, not the TC hook names.** The TC hooks attach to the
**tap interface (host side)** of each vNIC, so the raw hook names are
inverted relative to the VM: a VM *upload* fires the tap's TC **ingress**
hook (`TC_DIR_INGRESS = 0`, "VM is sending") and a VM *download* fires the
**egress** hook (`TC_DIR_EGRESS = 1`, "VM is receiving"). Exporting the
hook-frame words as label values would make `direction="egress"` mean
*download* — the opposite of the cloud-billing convention where egress is
data leaving the VM. The label vocabulary is therefore frame-free and
NIC-conventional: `tx` (VM transmits — hook ingress) / `rx` (VM receives —
hook egress), rendered by `bpf.Direction.String()`. The kernel enum keeps
its hook-frame names — the §4.2 directional swap depends on them. Do not
reintroduce hook-frame strings into the metric labels.

#### Health — implemented (per-subsystem; bounded cardinality)

| Metric | Type | Labels | Source |
|---|---|---|---|
| `lachesis_bpf_map_max_entries` | gauge | `map="telemetry_map\|subnet_zone_trie\|mac_tenant_map"` | seeded at startup from the compiled-in sizes; surfaces actual sizing per host (telemetry map scales by N_CPU per §11) |
| `lachesis_bpf_map_current_entries` | gauge | same `map` label | userspace-tracked count: kernelwriter push for mac_tenant_map / subnet_zone_trie, scraper drain for telemetry_map. Fill ratio = `current / max` in PromQL (replaces the drafted `lachesis_bpf_map_fill_ratio`; exporting numerator and denominator keeps both visible) |
| `lachesis_bpf_update_failures_total` | counter | `reason="update_failure\|skipped_ethertype"` | kernel `telemetry_stats` PERCPU_ARRAY, CPU-summed and drained by the scraper each tick; both reason series are zero-seeded at startup. `update_failure` = telemetry_map inserts the kernel rejected (map full — those flows' bytes are lost until GC frees space), `skipped_ethertype` = non-IP frames passed through uncounted (ARP/LLDP noise normally; a sustained rise flags a trunk/VLAN blind spot) |
| `lachesis_state_flows` | gauge | — | distinct flow keys in GlobalState (Collector) |
| `lachesis_state_settled_tuples` | gauge | — | distinct (tenant, zone, direction) buckets in the settled-bytes accumulator (§3.5) |
| `lachesis_scraper_errors_total` | counter | — | failed BPF-map drain attempts (Collector, from scraper) |
| `lachesis_scraper_last_success_unix_seconds` | gauge | — | most recent successful drain; 0 if never (Collector, from scraper) |
| `lachesis_collect_duration_seconds` | histogram | — | one Collect pass: snapshot + aggregate + emit. Buckets 1ms..1s |
| `lachesis_wal_snapshot_copy_seconds` | histogram | — | WAL writer, copy-under-lock phase (critical section) |
| `lachesis_wal_marshal_seconds` | histogram | — | WAL writer, JSON marshal phase (no lock held) |
| `lachesis_wal_flush_latency_seconds` | histogram | — | WAL writer, write+fsync+rename phase (no lock held). Buckets: 1ms..1s |
| `lachesis_wal_flush_failures_total` | counter | `stage="write\|fsync\|rename_bak\|rename_current\|dir_sync"` | WAL writer |
| `lachesis_wal_load_fallback_total` | counter | `from="bak\|empty"` | boot loader |
| `lachesis_neutron_sync_age_seconds` | gauge | — | last successful cold-start or full reconcile; -1 = never synced |
| `lachesis_neutron_api_errors_total` | counter | `endpoint, code` (HTTP status, or `network` for connection-level failures) | Neutron client |
| `lachesis_neutron_unknown_device_owner_total` | counter | `owner` | port admissions outside the IsKnownVMOwner allowlist |
| `lachesis_neutron_builder_step_duration_seconds` | histogram | `step` | BuildTrie per-step duration (§5.2 steps 1–5) |
| `lachesis_neutron_anomalies` | gauge | `class="cycle\|ambiguity\|dangling_route\|zero_trie_tenant\|duplicate_router_mac"` | topology anomalies detected at the last cold-start or resync (`DetectAnomalies`; drives `/debug/anomalies`) |
| `lachesis_neutron_trunk_subports` | gauge | — | trunk subport MACs admitted to `mac_tenant_map` at the last cold-start or resync; nonzero flags the §8 Tier 1 trunk blind spot (802.1Q-tagged subport traffic passes uncounted) |
| `lachesis_zombie_filters_cleaned_total` | counter | — | startup Zombie Hunter |
| `lachesis_tc_attach_failures_total` | counter | `iface_kind="tap\|other"` | Netlink Watcher |
| `lachesis_attached_interfaces` | gauge | — | current Interface Registry size |
| `lachesis_gc_evictions_total` | counter | `reason="ttl\|pressure_relief\|ghost_residual_flow"` | GC: lingering-ghost sweep (`ttl`, mac_tenant_map), scraper pressure-relief (`pressure_relief`, telemetry_map), and a swept MAC's residual telemetry_map flows removed so they are not re-billed as "unknown" (`ghost_residual_flow`, §3.3) |
| `lachesis_gc_pressure_relief_runs_total` | counter | — | scraper pressure-relief pass (fill above the high watermark) |
| `lachesis_gc_settled_flows_total` | counter | — | GlobalState flow rows the ghost sweep folded into the settled-bytes accumulator, keeping deleted VMs' bytes attributed to their tenant (§3.5) |
| `lachesis_lingering_ghosts_active` | gauge | — | metadata entries inside the 60s ghost grace window; the Neutron reconcile's MarkDelete on a deleted port/subnet now exercises it (§5.7) |
| `lachesis_unresolved_buffer_depth` | gauge | — | UnresolvedBuffer occupancy (panic threshold near the cap) |
| `lachesis_unresolved_buffer_evictions_total` | counter | `reason="lru\|expired"` | UnresolvedBuffer entries folded to "unknown", by cause |
| `lachesis_unresolved_resolved_total` | counter | — | late-binding successes: a buffered flow whose MAC became known (reconcile or Kafka) attributed to the right tenant with the §3.2 delta write-back |
| `lachesis_reconcile_runs_total` | counter | `result="ok\|sync_error\|apply_error"` | periodic + Kafka-kicked Neutron reconcile passes by outcome; `apply_error` is the runtime kernelwriter-failure sink the revisit note below anticipated |
| `lachesis_kafka_lag_messages` | gauge | `topic` | Kafka consumer lag behind the topic head; sustained growth = falling behind live updates |
| `lachesis_kafka_consume_errors_total` | counter | `topic` | Kafka consumer read failures (broker unreachable, fetch errors) |

#### Health — planned (subsystem not yet built; add with the subsystem)

The Octavia LB attribution metrics (Sprint 8) land with that subsystem.

A drafted generic `lachesis_internal_errors_total{subsystem}` sink was
dropped: every billing-path error site today lands in a dedicated counter
(scraper errors, WAL flush-failure stages, WAL load fallback, Neutron API
errors, TC attach failures), and kernelwriter failures are boot-fatal by
contract (§9 — the next boot rebuilds the maps). Revisit if a runtime
error path lands without a dedicated counter — the Kafka-driven
incremental kernelwriter updates are the expected first case.

Cardinality discipline: **never** label a health metric with `tenant_id`,
`mac`, `flow_key`, or any per-flow identifier. Anything per-flow goes only
into the billing tier, whose cardinality is already bounded by the trie /
MAC-pair model (§3.1).

SLO targets (informational, refined post-MVP):
- `lachesis_neutron_sync_age_seconds` < 120 (Kafka-driven freshness)
- `lachesis_wal_flush_latency_seconds` p99 < 50 ms
- `lachesis_unresolved_buffer_depth` < 1000 sustained (10k cap is a panic threshold)
- `lachesis_bpf_map_current_entries{map="telemetry_map"} / lachesis_bpf_map_max_entries{map="telemetry_map"}` < 0.8 (above triggers pressure-relief GC)
- `lachesis_bpf_update_failures_total{reason="update_failure"}` == 0 (any increase is billed bytes lost in the kernel; alert on `> 0` — a page once pressure-relief GC exists, since then it should never fire)
- `lachesis:unbilled_bytes:ratio_rate5m` < 0.001 — the revenue-leak SLO; recording rule and structural contributors defined in §11.5 below

### Billing model & consumption contract

The measurement layers (§2–§6) produce billing-grade counters; this section defines the product semantics on top of them — which series a billing engine reads, what each zone should cost, and how to consume the counters without corruption. A billing implementer should be able to work from this section alone.

#### The emission invariant

Every byte transfer the data plane can see appears in **exactly one `tx` series and one `rx` series**: counted once at the sender's tap as `direction="tx"` and once at the receiver's tap as `direction="rx"`, each keyed by `(tenant_id, zone, direction)` on `lachesis_bytes_total` / `lachesis_packets_total` (§11.4). The agent **never deduplicates** — both-sides emission is the contract, not an artifact (Scenario I; §8 Tier 4 #15). When only one endpoint sits behind a monitored tap (internet peers, DPDK/SR-IOV VMs), only that side's series exists.

Byte basis: aggregated-skb L2 bytes. Per-segment headers are counted once per GSO/GRO superpacket, so bulk TCP measures ≈4–5% under wire-equivalent (verified empirically; ~0 on small-packet traffic — §8 Tier 2 #6), and `lachesis_packets_total` counts superpackets, not wire segments. Bill on bytes, never on packets.

#### Per-zone charging postures

The zone vocabulary is the §11.4 label table. The guiding principle: **each side pays for its own direction** — under these postures, no cross-tap dedup is ever needed.

| `zone` | Posture | Rationale |
|---|---|---|
| `same_tenant` | **$0** (recommended) | Makes the both-sides emission harmless by construction: an intra-tenant transfer produces one `tx` and one `rx` series for the same tenant, and 2 × $0 = $0 |
| `other_tenant` | **Per-side at the internal rate** — sender pays its `tx`, receiver pays its `rx` | The AWS cross-AZ model: each party is billed for its own direction of a cross-tenant transfer. The two series belong to different tenants, so no dedup question arises |
| `external` | **Per-direction rates** — `tx` at the egress rate (data leaving toward the internet), `rx` at the ingress rate | The universal cloud convention of asymmetric internet pricing |
| `infra` | **$0 today** | Covers DHCP/metadata chatter and Octavia Segment 2 plumbing (§6) alike. Future fork: if LB-processed-byte billing is ever wanted, either split the zone (the kernel's Amphora branch already distinguishes Segment 2, so an `infra_lb` zone is cheap) or source LB usage from the Octavia API. Until that product decision, `infra` stays uniformly free |
| `shared` | **Own line item at an intermediate internal rate** | Owner-vs-other inside a shared CIDR is intentionally indistinguishable on the L3 path — §5.2 Step 3 explains why guessing either mis-bills. Price between `same_tenant` and `other_tenant` instead of guessing |
| `miss` — and any `tenant_id="unknown"` | **Never billed; alert-only** | Unattributable bytes must not become invoices. Tracked by the revenue-leak SLO below |

**FIP hairpin is EXTERNAL on both sides — deliberately.** When a VM reaches a same-tenant peer via the peer's floating IP, both taps classify EXTERNAL: the client's tap sees the remote FIP, and OVN hairpin-SNATs the source to the client's *own* FIP, so the server's tap also sees an external-net address (verified empirically — same tenant, same subnet, same hypervisor). The traffic never leaves the host, yet bills at external rates in both directions. This matches public-cloud norms (AWS bills public-IP hairpins as public traffic); tenants avoid the charge by addressing fixed IPs.

#### The consumption contract

- **Counters are lifetime-cumulative and never decrease.** A flow row lives in GlobalState while its attribution lives, and when the attribution dies — the VM deleted and ghost-swept, or the port reassigned to another project — the row's bytes fold forward into the settled accumulator under the same `(tenant_id, zone, direction)` tuple (§3.5). The exposed series is the live+settled sum, so its value is invariant across the fold: VM churn never decreases a tenant's series. WAL restore (§10) carries both halves across agent restarts and reboots — series never reset to zero. (A hard crash can drop up to the ≤60s WAL window of tail bytes and un-persist that window's folds — provider-unfavorable, §10/§3.5.) §13.1 #7 pins this as an implementation contract.
- **Consume by endpoint-sample subtraction, not `increase()`.** For a billing period `[T₀, T₁]`, charge `value(T₁) − value(T₀)` per series. `increase()` extrapolates to compensate for counter resets and scrape-boundary gaps; these counters never reset, so the extrapolation only adds error. Plain subtraction is exact — the no-eviction property is precisely what makes it safe.
- **Prometheus durability, retention, and HA are the platform's responsibility** (stated non-goal). The agent's promise ends at `/metrics`: cumulative, monotone, restart-surviving series. Whatever scrapes them must retain the two endpoint samples per billing period (or remote-write to something that does).
- **Host identity is the Prometheus `instance` scrape label** — there is no host label on the metric itself. A live-migrated VM accrues series under several `instance` values over its lifetime; sum them (§8 Tier 4 #16).

#### Revenue-leak SLO

The unbilled fraction — bytes in `zone="miss"` or `tenant_id="unknown"` — is the runtime verification of §8's static accuracy-ceiling claim (~99.9%):

```yaml
- record: lachesis:unbilled_bytes:ratio_rate5m
  expr: |
    sum(
        rate(lachesis_bytes_total{zone="miss"}[5m])
      or rate(lachesis_bytes_total{tenant_id="unknown"}[5m])
    )
    /
    sum(rate(lachesis_bytes_total[5m]))
```

The `or` deduplicates series that are both `zone="miss"` and `tenant_id="unknown"`: both operands draw from the same series set, so label sets match exactly and each leaking series counts once.

**Target: < 0.001 (0.1%)**; alert above it. Structural contributors to expect:

- **IPv6** — all of it classifies `zone="miss"` until §13.2 #1 lands; deployments with real v6 traffic will sit above the target until then.
- **Allowed-address-pairs / VRRP virtual MACs** — a vMAC sourced by a keepalived pair is not a Neutron port MAC, misses `mac_tenant_map`, and emits `tenant_id="unknown"`.
- **Transient cold-start / late-Kafka windows** (§8 Tier 3 #14) — self-healing via the UnresolvedBuffer; visible as short spikes, not steady-state leak.

### Scalability ceiling

- The `telemetry_map` upper bound is `max_entries` (computed by the formula above; ranges from 8,192 on high-core hosts to 65,536 on 32-core).
- That bound limits distinct (MAC-pair, direction, zone) combinations per node.
- On a 50-VM node: typical fill is ~850 entries (well under any tier of the cap).
- On a 500-VM node (extreme): proportional ~8,500 entries — still safe at 32-core (~13% fill), but on a 128-core host where `max_entries=16,384` this is ~52% fill, and pressure-relief GC will activate sooner.
- If the agent reports fill ratio >80% sustained on a given host, the deployment has outgrown that host's `max_entries`; raise the memory budget config or add more compute nodes.

### Per-server usage export (planned)

The `/metrics` contract above is deliberately **aggregate** — `tenant_id × zone × external_network × direction`, all low-cardinality. Per-server (and per-user) billing detail is **not** exposed as Prometheus labels: per-VM series multiplied by the monotone-never-reset rule (the consumption contract above) would leak a dead series on every VM teardown, and a TSDB's retention is shorter than a billing period. Per-server billing is therefore a **separate pull-based export** — not a metric label, and not a message bus:

- The agent serves a dedicated endpoint (off `/metrics`) returning **cumulative** byte counters per `(tenant, server, zone, external_network, direction)`, tagged with the host `node` and a `meter_epoch` — the agent's start identity, bumped on restart so a consumer detects a counter reset without value-comparison heuristics. `server` is the Neutron port `device_id` (Nova instance UUID); `user` is not emitted (Neutron ports don't carry it) — the billing consumer derives it from `server`.
- A billing collector pulls the endpoint on a schedule and persists period-bucketed deltas to a durable store (MongoDB on the platform). **Cumulative + pull is lossless across collector/store downtime** — the same property that makes Prometheus scraping robust — so an outage never loses billing data, unlike a push into a bus that can be wiped by a restart.
- **The agent meters; the billing system rates.** The rate table (`zone × external_network × direction → price`) lives in the billing/CMP layer, never in the agent.
- **Live migration:** a VM moving hosts accrues records under successive `(node, meter_epoch)` pairs; the consumer sums deltas across them per `server` (§8 Tier 4 #16).

`external_network` is the one new billing dimension that is *also* low-cardinality enough to carry as a Prometheus label (a handful of external networks, no churn), so operator dashboards can split egress by external network even though per-server detail stays in the export. This keeps Prometheus as the operator/aggregate plane and the export as the per-server billing record-of-truth.

---

## 12. Demo Workflow [HISTORICAL — pre-Sprint 1 baseline]

> This section describes the *demo* agent that existed prior to Sprint 1 (now replaced). Kept as a reference pattern for manual `iperf3` overhead measurement against the production classifier. The production performance number is captured by `cmd/perfbench` (see Sprint 0.5 / `docs/test-strategy.md`).

The demo measures eBPF overhead by attaching/detaching the TC program around iperf3 runs.

```
─── Terminal 1 (server, on the VM) ───
iperf3 -s

─── Terminal 2 (baseline — NO eBPF) ───
iperf3 -c <vm_ip> -t 30 -P 4
# record throughput

─── Terminal 3 (load the agent) ───
TELEMETRY_IFACE=tap<uuid> sudo ./agent
# prints per-flow stats every 5s, GC every 60s

─── Terminal 2 (with eBPF active) ───
iperf3 -c <vm_ip> -t 30 -P 4
# compare throughput to baseline; should be near-identical (<1% delta)

─── Terminal 3 ───
Ctrl-C
# detachTC() runs; filters removed for clean back-to-back runs
```

The demo agent is intentionally minimal: no Zombie Hunter, no metadata stubs, no Prometheus exporter. Just attach + per-flow stats + GC. Easy to load/unload while iperf3 measures externally.

---

## 13. Implementation Notes

The design above leaves a few load-bearing properties to the implementation. This section lists them explicitly so they don't get lost between spec and code.

### 13.1 Required Implementation Contracts

These must be present in any implementation for correctness. They are not deferrable.

| # | Contract | Severity | Notes |
|---|---|---|---|
| 1 | `UnresolvedBuffer` capped at 10k entries with LRU eviction | High | Without a cap, a Kafka outage grows the buffer unboundedly until OOM |
| 2 | `Collect()` holds RLock around the entire `GlobalState` iteration | High | Prometheus scrape races the scraper writer; without RLock the Go runtime fatals on concurrent map iteration |
| 3 | `*TenantMeta` updates always replace the pointer; never mutate fields in-place | High | Multiple MACs share one pointer (§3.2). In-place mutation creates torn reads on the hot path |
| 4 | Boot sequence (§9) ordering enforced — currently by straight-line single-goroutine `Bootstrap`: every phase advances inline and `Bootstrap` returns before `Run` spawns the scraper/WAL/netlink goroutines, so no consumer can observe an out-of-order phase | High | Out-of-order startup silently produces permanently-misclassified flows. `boot.Sequencer` validates the step-by-one order and logs each transition; promoting it to a cross-goroutine `Await`/`Fail` barrier is deferred until concurrent phase-advancers exist (§13.2 #3) |
| 5 | u64 wraparound guard in delta math | Low | At 10 Gbps continuous, ~467 years to overflow — but the guard is one comparison, so add it |
| 6 | Lingering Ghost lifecycle ordering between kernel `mac_tenant_map` and userspace `ShardedMetadataMap` | High | Insertions go userspace→kernel; deletions are delayed 60s then go kernel→userspace (§3.4). Skipping the kernel-side delay silently breaks the ghost's purpose — dying FIN/RST packets mis-attribute to `unknown` |
| 7 | Exposed `(tenant_id, zone, direction)` series are monotone: any mutation that deletes or re-attributes a `GlobalState` flow row folds its total into the settled accumulator in the same critical section (§3.5), and snapshots (Collect, WAL) read both maps under one lock; series are restored cumulatively across restarts (WAL, §10) | High | Billing consumers bill by endpoint-sample subtraction (§11.5) and depend on monotone cumulative counters. Late-bound labels mean row-level append-only is NOT sufficient — deleting metadata re-buckets history, which is a series decrease. Any future eviction/retention feature must preserve the fold-forward property or version the consumption contract first |

### 13.2 Deferred Work

Explicitly out of MVP scope. Documented so future contributors know it's open by design, not oversight.

| # | Item | Notes |
|---|---|---|
| 1 | IPv6 zone resolution | All v6 traffic currently classifies as ZONE_MISS. Retrofit path: add a second LPM trie keyed `(tenant_id, u8[16])` alongside the existing v4 trie; branch in `lookup_zone()` on `eth_proto`. The 5-step cold-start algorithm (§5.2) is IP-version-agnostic — only insertion code changes. Estimated ~1 sprint, low risk |
| 2 | Traditional Neutron (OVS-agent + L3-agent + qrouter namespaces, with or without DVR) | Tested OVN deployments (single-node and 3-node HA) run OpenStack Yoga with OVN ML2 — verified empirically. Traditional Neutron is therefore out of scope. If a future deployment requires it, the cold-start algorithm needs a "Step 6 — DVR per-host MAC enumeration" reinstated (using the `dvr-mac-addresses` Neutron extension); see git history of this file for the removed text. Estimated ~1 sprint to re-add |
| 3 | Cross-goroutine boot sync barrier (`boot.Sequencer.Await` / `Fail`) | `Bootstrap` advances every phase straight-line in one goroutine and returns before `Run` spawns the consumer goroutines, so the boot ordering (Contract #4) holds structurally and `boot.Sequencer` is an in-`Bootstrap` order validator + phase logger. When the Kafka updater or GC advance / block on phases from their own goroutines, add channel-backed `Await(Phase)` / `Fail(err)` so consumers wait on a named phase instead of relying on straight-line execution. Deferred by design, not oversight. Estimated <1 sprint, low risk |
| 4 | Static-route EXTERNAL-fallback counter (`lachesis_neutron_static_route_fallback_total{reason}`) | `resolveStaticRouteZone` (resolve.go) has six EXTERNAL fallback exits; three warn-log (cycle, MAX_HOPS, ambiguity), the others (anchor-subnet miss, port-at miss, unknown next-router device, unknown device-owner) return EXTERNAL silently. A per-`reason` counter would make the fallback rate visible on `/metrics`. Deferred until it can be validated against a real cluster's `/metrics` deltas — it touches billing-relevant route classification, so per the project's validate-before-billing-changes rule it should not ship on theory. Observability-only (counts existing EXTERNAL returns; changes no classification). Estimated <1 sprint, low risk |
| 5 | Netlink attach-presence reconciler (level-triggered periodic resync) | A periodic sweep that lists interfaces matching the attach allowlist and re-attaches our TC filters where missing — the informer "periodic resync catches missed events" pattern. Safe by construction: `FilterReplace` is idempotent (the fixed `tcattach.FilterPriority` makes it so — at priority 0 the kernel would allocate a new chain per call and stack a duplicate filter), so the worst a bug does is re-attach something already attached. Covers NEWLINK events missed around the subscribe window (the netlink integration tests note this race), and the larger missed-event surface under churn: a NEWLINK dropped by netlink socket overflow during an event storm never reaches the subscriber at all. **Scheduled (no longer purely evidence-gated):** the original gate — watch `lachesis_tc_attach_failures_total` — is moot, because that counter is blind to the dominant risk. A dropped NEWLINK never calls `AttachLink`, so nothing increments; the failure counter only sees explicit attach errors, not the missed-event path. The real detector is therefore a *presence gauge* (allowlist-matching links present-but-unattached), landed first as its own slice, with the reconciler acting on it. Event storms (mass VM operations, HA failover rescheduling many ports) make the missed-event path realistic rather than hypothetical. Explicitly **not** a runtime zombie hunter — zombie *deletion* stays boot-only by design, because its safety depends on running before any attach (at that point every matching filter is an orphan by definition); a runtime deleter must distinguish live filters from orphans, and a bug there silently deletes live filters → billing undercount. The risk asymmetry rules it out. Estimated <1 sprint, low risk |
| 6 | Workqueue-backed event handling for the netlink subscriber and Kafka updater | Reference: `k8s.io/client-go/util/workqueue` (dedup/coalescing + rate-limited retry with exponential backoff) — the standard informer → workqueue → reconciler triple. Earmarked for: (a) the netlink subscriber, if flapping interfaces produce event storms or transient attach failures need retry-with-backoff instead of a log line; (b) the Kafka metadata updater, to coalesce rapid per-port update bursts and retry failed kernel-map writes. Not applicable to boot — the boot sequence stays straight-line code plus ordering barriers (`boot.Sequencer`), matching how Kubernetes boots components (`WaitForCacheSync`, post-start hooks), with queues reserved for steady-state events. **Current direction:** the lighter, targeted measures land first — netlink transient-failure and missed-event recovery folds into the idempotent re-attach of #5 (the reconciler *is* the retry), and the Kafka side is handled by a debounce window that coalesces bursts (backlog item, gated on observed event volume) rather than a full queue. The workqueue stays the escalation if those prove insufficient — adopt then, not before |
| 7 | Map pinning for zero-loss agent-crash recovery | §10's agent-crash path currently equals the hard-reboot path: nothing pins the maps (`config.BPFConfig.PinPath` exists but no caller pins), a restarted agent cannot reach the old unpinned maps, and the boot-time Zombie Hunter drops the orphan TC filters that were keeping them alive — so recovery is WAL-bounded at ≤60s. Pinning under `bpf.pin_path` and reusing the pinned maps on boot restores the designed zero-loss path. Touches boot ordering (zombie hunt vs. pinned-map reuse) and `ValidateMapSizes` against a pinned spec. Estimated <1 sprint, medium care: a stale pinned map with wrong sizing must refuse-to-reuse, not silently adopt |
| 8 | Trunk port (VLAN-aware VM) support — single 802.1Q parse | When `h_proto` is `0x8100`/`0x88A8`, parse one VLAN level: `bpf_skb_pull_data` for the 4 extra tag bytes, re-read the data pointers, dispatch on the inner ethertype, and offset the IP header by 4; also handle the offloaded-tag direction (`skb->vlan_present`, where the tag lives in skb metadata and the linear data already starts at the inner header). Blocked on a billing decision: whether `flow_key.eth_proto` records the inner or outer proto (and whether counted bytes include the 4 tag bytes) must be settled **before** WAL entries bake the key shape. Until then trunk deployments are detection-only — cold-start warn-log, `lachesis_neutron_trunk_subports` gauge, and the kernel skipped-ethertype counter (issue #39); see §8 Tier 1 row 3a and issue #37. Estimated ~1 sprint |
| 9 | Allowed-address-pairs MAC ingestion | `ListPorts` does not fetch a port's `allowed_address_pairs`, so a MAC a VM is *permitted* to source (a keepalived/VRRP virtual MAC, or an AAP entry with an explicit MAC) never enters `mac_tenant_map` and its bytes leak to `tenant_id="unknown"` (§8 Tier 3 row 14b; §11.5 revenue-leak SLO). Fix: add `allowed_address_pairs` to the port query and admit each pair's MAC against the owning port's tenant — userspace-then-kernel like any other insert (§3.4). The default keepalived case (real port MACs via GARP) already classifies, so this targets vMAC-mode and explicit-MAC AAP deployments. Estimated <1 sprint, low risk |

### 13.3 Construction Conventions

Several constructor idioms coexist *by design*. New code matches the closest existing one rather than inventing a sixth, and the outliers below are deliberately **not** normalised — converting them only churns tests for no behavioural gain.

| Idiom | Used by | When |
|---|---|---|
| Options struct | `agent.New(Options)`, `netlink.New(Options)`, `config.Load(Options, …)` | More than ~2 inputs, or any optional / defaulted field. The reference pattern — reach for it first |
| Positional params | `scraper.New(reader, st, interval)`, `metadata.NewResolver(m)` | ≤2 unambiguous required args, no options |
| Bare `New()` | `state.New`, `boot.New`, `metadata.New`, `netlink.NewRegistry`, every per-package `NewMetrics` | Zero-config value types. Metric bundles are uniformly `type Metrics` + `NewMetrics()` |
| Functional options | *(none — retired)* | `BuildTrie`'s `WithMetrics` (the sole user) was retired when its only metrics-passing caller moved in-package (`Neutron.Sync` → unexported `buildTrie(snap, m)`); the external call-sites stay argument-free via `BuildTrie(snap)`. Don't reintroduce without a cross-package optional-dependency need |
| `Run(Config)` | `perfbench.Run`, `loadtest.Run` | Single-shot CLI harnesses, not long-lived services |

### 13.4 Package Anatomy

Every `internal/` package is one of four shapes. A new package starts by picking the archetype that matches its job — don't invent a fifth shape, and don't mix surfaces from two archetypes into one package. Uniformity holds *within* an archetype, never across archetypes (the Kubernetes analog: `component-base` daemons share an options-plus-`Run(ctx)` shape while client-go stores/listers stay plain structs). A one-size-fits-all package surface and producer-side interface-per-package were both considered and rejected — the repo already rejected a `Runnable` interface once in favour of the concrete `workers()` table.

**Decision rule:** does it own a loop? → Service. Is it shared mutable state? → Store. Does one owner call verbs on it while others only read? → Driven subsystem. None of the above → Library.

| Archetype | Surface | Examples |
|---|---|---|
| **Service** — owns a long-running loop | Constructor per §13.3 → struct; a blocking `Run(ctx) error` (or equivalent step methods the agent's worker table wraps); cheap health accessors for observability. Services never spawn their own goroutines: long-lived goroutines start in exactly one place, the agent's `workers()` table (drain-ordered, goleak-enforced) | `scraper.Scraper` (`Run`/`Tick`/`ErrorCount`/`LastSuccessUnix`), `netlink.Subscriber` |
| **Store** — passive shared state | Bare `New()`; concrete methods; explicit lock discipline (`RWMutex` or sharding, acquire-late/release-early, never hold a lock across IO). No `ctx`, no goroutines, no IO | `state.GlobalState`, `metadata.ShardedMetadataMap`, `metadata.TenantInterner`, `netlink.Registry` |
| **Driven subsystem** — a caller sequences its verbs | Constructor per §13.3; imperative verb methods the owner calls in a documented order; lock-free read accessors for everyone else (atomic pointer-swap retention, whole-value replace). Single-writer discipline documented on the type | `neutron.Neutron` (`Sync` → kernel push → `Commit`; accessors feed /debug), `runtime.Manager` (`Reload`/`Current`/`DebugHandler`), `boot.Sequencer` (`Advance`), `metrics.Collector` (Prometheus drives `Collect`), `debug.Server` (HTTP mux drives handlers) |
| **Library** — stateless functions | No main type, no constructor, no lifecycle; pure functions with explicit dependencies as arguments | `kernelwriter`, `wal` (`Save`/`Load`), `zombie.Hunt`, `config.Load`, `logging.Init`, `tcattach` |

Two sanctioned one-offs (not archetypes — don't replicate): the composition root (`agent`: one struct, method files by functionality, the `workers()` table, the `subsystemMetrics` registration list) and the CLI harness shape (`perfbench.Run(Config)` / `loadtest.Run(Config)`, already in §13.3).

**Cross-cutting rules (all archetypes):**

- `schema.go` holds the package's consts and pure-data types; behavioural types stay in their method files.
- Observability: `type Metrics` + `NewMetrics()` + `Collectors()` + nil-safe observation helpers; registered centrally via the agent's `subsystemMetrics.registrations()`. Uninstrumented subsystems are undebuggable in production (§11).
- Logging: per-package `component*` const, one vocabulary with the metric registration labels.
- Interfaces are **consumer-defined only**: the consuming package declares the minimal method set it calls, and only when a second implementation exists today (a test seam counts). Never producer-side, never speculative. Current census (all six conform): `scraper.MapReader`, `metrics.TenantResolver`, `metrics.ScraperStats`, `netlink.Subscriber`, `netlink.Attacher`, `kernelwriter.MapUpdater`.

**Package census:**

| Package | Archetype | Notes |
|---|---|---|
| `agent` | composition root | one-off; owns all goroutines via `workers()` |
| `boot` | Driven | `Sequencer.Advance` |
| `bpf` | Library | consts/keys/`ValidateMapSizes` + generated bindings + Metrics |
| `config` | Library | `Load` + `Validate` |
| `debug` | Driven | `New(Options)` + `Handler()`; HTTP mux drives it |
| `kernelwriter` | Library | + consumer interface `MapUpdater` |
| `logging` | Library | `Init` → `Handle` |
| `metadata` | Store | two stores + `NewResolver` adapter |
| `metrics` | Driven | custom `prometheus.Collector` (billing path, §13.1 #2) |
| `netlink` | Service + Store | `Subscriber` + `Registry` + Metrics |
| `neutron` | Driven | + Library surface (`BuildTrie`, `DetectAnomalies`, lookups are pure funcs) |
| `osclient` | Library | shared Keystone bootstrap (`Credentials`, `ParseOpenRC`, `Authenticate`/`AuthenticateProject`); consumed by `neutron` and `scenariotest` |
| `runtime` | Driven | `Manager` |
| `scraper` | Service | reference Service example |
| `state` | Store | reference Store example |
| `tcattach` | Library | `NewLinkAttacher` returns the `Attacher` impl |
| `testenv` | exempt | test-only builders/fixtures |
| `wal`, `zombie` | Library | + Metrics bundles |
| `perfbench`, `loadtest`, `scenariotest` | CLI harness | `Run(Config)`-style single-shot entrypoints (scenariotest: one per subcommand, live-cluster IO behind the `Cloud`/`MetricsSource` seams) |

---

## Appendix A — Design Decisions Table

| Decision | Chosen | Rejected | Why |
|---|---|---|---|
| eBPF hook | TC clsact (ingress + egress) | XDP | XDP is ingress-only on tap; no `bpf_skb_ct_lookup` for Octavia. [C.1](#c1-xdp-hook-instead-of-tc) |
| Octavia LB attribution (LB-owner) | Amphora MAC flag in `mac_tenant_map` | Conntrack tuple recovery as the primary mechanism | HAProxy creates two distinct TCP connections (verified empirically); client_ip isn't recoverable at the backend's tap. MAC-flag attribution works at every tap and matches AWS/GCP segment-by-segment billing |
| Segment 1 zone (LB) | Optional `bpf_skb_ct_lookup` at Amphora's tap | Always EXTERNAL for LB Segment 1 traffic | Conntrack recovery refines the zone to OTHER/SAME when the client is internal; EXTERNAL is the safe-billing fallback on miss |
| Crash resilience | Read, don't clear + WAL (map pinning deferred — §13.2 #7) | Clear after each scrape | ≤60s loss on restart today; zero once pinning lands. See §10 |
| Concurrency | PERCPU_HASH | Global hash + atomics | Atomic contention at 10 Gbps × 32 cores becomes the bottleneck. [B.4](#b4-percpu_hash) |
| Prometheus storage | Custom collector + WAL | `CounterVec` | `CounterVec` resets on crash → negative `rate()` → billing breaks. [C.7](#c7-prometheus-countervec) |
| MAC→tenant map | 64-shard RWMutex | `sync.Map` | sync.Map is read-optimized; we write every 10s from Kafka. [C.6](#c6-syncmap-for-metadata-cache) |
| VM/subnet deletion | Lingering Ghost (60s TTL) | Immediate eviction | Dying FIN/RST packets must still attribute correctly |
| Interface lifecycle | Netlink Watcher + Registry | Static tap list | OpenStack creates/destroys taps dynamically |
| Crash-leftover filters | Zombie Hunter on startup | Ignore / let attach fail | Stacking duplicates on restart silently double-counts |
| Flow-key cardinality | MAC-pair + dst_zone | 5-tuple `(src_ip, dst_ip, ports)` | MAC-pair scales with topology; 5-tuple explodes labels. [C.4](#c4-5-tuple-flow-key-instead-of-mac--zone) |
| Cross-subnet classification | dst_zone u8 + LPM trie | dst_ip in key | dst_ip explodes cardinality and breaks IPv6; LPM scales with topology |
| Shared-network attribution | ZONE_SHARED (distinct 5th zone) | Guess SAME for owner / OTHER for others | The LPM trie cannot resolve per-VM ownership inside a shared /24; either guess systematically mis-bills one side. SHARED is the honest label for the L3-routed-fallback case on shared networks. MAC-first hot path still resolves intra-tenant L2 traffic as SAME_TENANT exactly. See §5.2 Step 3 |
| Map capacity relief | Pressure-relief GC + fill metric | LRU_HASH | LRU evicts silently → unrecoverable byte loss. [C.5](#c5-lru_hash-for-map-eviction) |
| OpenStack metadata source | Neutron v2.0 API | Direct MySQL | API is versioned/stable; DB schema migrates per release. [C.3](#c3-direct-mysql-queries-instead-of-neutron-api) |
| Static route resolution | Nexthop trace through Neutron port topology | CIDR-only lookup | CIDR alone is ambiguous when tenants reuse the same prefix. [C.9](#c9-direct-cidr-lookup-without-nexthop-trace) |
| VM-appliance nexthop | `zone_for(appliance_tenant, source_tenant)` | EXTERNAL fallback | Appliance tenant is Neutron-visible; better attribution than blanket EXTERNAL. Double-billing caveat documented in §8 Tier 4 #21 and Scenario L. |
| Per-packet zone resolution | Hybrid: MAC-first, LPM fallback | Always-LPM | Direct L2 traffic gets exact tenant comparison. [C.8](#c8-always-lpm-no-mac-first-hybrid) |
| Telemetry approach | eBPF TC at tap (exact) | sFlow at OVS / NIC (sampled) | Sampling is unfit for billing. [C.2](#c2-sampling-at-ovs--vxlan-envelope-extraction) |
| Control-plane target | OVN-first (single architecture) | Dual-track OVN + traditional Neutron | Tested OVN deployments (single-node and 3-node HA) verified to run OVN exclusively; supporting traditional Neutron is infra-for-absent-code. See §13.2 deferred work for the retrofit path |
| Chassis MAC enumeration | Standard Neutron port API with broadened `device_owner` filter | OVN Southbound DB / OVS local DB query | DB-direct queries reintroduce the schema-migration and security blast radius problems §C.3 already rejected for Neutron MySQL. OVN exposes everything needed via the standard port API once the OVN-specific `device_owner` values (`network:distributed`, etc.) are accepted |

---

## Appendix B — Concept Primer

A senior engineer can skim this once and proceed; the main text links here when terms first appear.

### B.1 eBPF in 60 seconds

eBPF (extended Berkeley Packet Filter) lets you attach small programs to specific kernel hook points. The programs run in a sandboxed virtual machine inside the kernel — no kernel modules, no recompilation, no reboots. The kernel verifier statically rejects programs that could crash, loop, or read invalid memory.

For our use case, eBPF gives us three things:

1. **Per-packet hooks** at the network stack — we can run code on every packet in/out of an interface, in the kernel, at line rate.
2. **Maps** — kernel data structures (hash, array, LPM trie, etc.) that BPF programs and userspace can share.
3. **Helper functions** — kernel-provided functions BPF programs can call, including `bpf_map_lookup_elem`, `bpf_skb_pull_data`, `bpf_ktime_get_ns`, and (critically for us) `bpf_skb_ct_lookup`.

We use the `cilium/ebpf` Go library for loading and managing programs. The C source is compiled with `clang -target bpf` and embedded into the Go binary via `bpf2go`.

External: [eBPF.io overview](https://ebpf.io/what-is-ebpf/), [Cilium eBPF docs](https://docs.cilium.io/en/stable/bpf/).

### B.2 TC clsact qdisc

Linux's traffic control (TC) layer hooks into the kernel network stack at queueing-discipline (qdisc) boundaries. Most qdiscs only see one direction, but `clsact` is special: it provides **both** an ingress and an egress hook on the same interface.

```
                  ┌─────────────┐
   from VM ──────▶│ clsact      │──────▶ to OVS
                  │ ingress hook│
                  ├─────────────┤
   to VM   ◀──────│ egress hook │◀────── from OVS
                  └─────────────┘
                       (tap)
```

We attach our BPF programs to both hooks:

- `tc_telemetry_in` on ingress (VM is sending — direction=0)
- `tc_telemetry_out` on egress (VM is receiving — direction=1)

`clsact` is added to an interface as a `replace` operation (idempotent). Filters under it reference our BPF programs by FD; deleting the filter removes the program reference.

Note: in TC's terminology, "ingress" and "egress" are from the *interface's* perspective. For a tap interface, ingress means "data flowing INTO the host stack from the VM" — i.e., the VM is the sender. We rename in our code to "VM sending" / "VM receiving" because that's clearer.

### B.3 BTF (BPF Type Format)

BTF is a compact metadata format that describes kernel data structures (struct layouts, types). The kernel ships with `/sys/kernel/btf/vmlinux`, which describes every type in the running kernel.

We use BTF for **CO-RE (Compile Once, Run Everywhere)** — our BPF programs reference kernel structs (like `struct __sk_buff`, `struct iphdr`) and are compiled once. The BPF loader patches the program's struct field accesses at load time using BTF, so the same binary runs on different kernels with different struct layouts.

We generate a flattened `vmlinux.h` from BTF and include it in our BPF C code. One gotcha: macros like `TC_ACT_OK` are not in BTF (they're preprocessor `#define`s), so we redefine them in our C code.

External: [Andrii Nakryiko's BTF intro](https://nakryiko.com/posts/btf-dedup/).

### B.4 PERCPU_HASH

`BPF_MAP_TYPE_PERCPU_HASH` is a hash map where each entry has *N* values internally — one per CPU. When CPU 7 does `bpf_map_lookup_elem` and gets a non-NULL pointer, it's pointing at CPU 7's slot specifically. CPU 8 can update its own slot in parallel without contention.

```
            CPU 0    CPU 1    CPU 2    ...   CPU 31
         ┌────────┬────────┬────────┬─────┬────────┐
key A    │ 100 B  │  50 B  │ 200 B  │ ... │  10 B  │  ← logical sum: 360 B
         ├────────┼────────┼────────┼─────┼────────┤
key B    │  20 B  │   0 B  │   0 B  │ ... │  80 B  │  ← logical sum: 100 B
         └────────┴────────┴────────┴─────┴────────┘
```

**Why this matters for us.** A regular hash with `__sync_fetch_and_add` works, but at 10 Gbps × 32 cores, the cache line bouncing on the atomic counter caps throughput well below line rate. PERCPU_HASH eliminates the contention; userspace just sums across CPUs at scrape time.

**Subtlety: first-packet TOCTOU.** When a flow doesn't exist yet, the BPF program does `lookup → null → update_elem(BPF_ANY, init)`. Two CPUs racing on the *first packet* of a new flow can both see null and both call update_elem — one's `BPF_ANY` overwrites the other's value. We lose at most 1 packet per new flow per race. Subsequent packets (the >99.999% case) are race-free because each CPU updates its own slot.

External: [BPF maps documentation](https://docs.kernel.org/bpf/maps.html).

### B.5 LPM Trie

`BPF_MAP_TYPE_LPM_TRIE` is a longest-prefix-match data structure. You insert entries with `(prefixlen, data)` keys. Lookups specify the full data and the trie returns the value of the longest stored prefix that matches.

```
Stored entries:                      Lookup with key 10.50.0.5/32:
  10.0.0.0/8       → A                 walks trie
  10.50.0.0/16     → B                 longest match: 10.50.0.0/16
  10.50.42.0/24    → C                 returns: B
  0.0.0.0/0        → default
```

We use it because zone classification fundamentally is a "longest-prefix-match" question: a destination IP might match a host-specific entry (`/32`), a subnet (`/24`), a tenant range (`/16`), or fall to the catchall (`/0`). Whichever is most specific wins.

**Our key has `(tenant_id ++ ip)`.** The `prefixlen` field in the BPF LPM key counts bits in the data after the prefixlen field itself. Since we always want exact `tenant_id` match, every stored entry has `prefixlen ≥ 32`. The remaining `prefixlen - 32` bits are the IP prefix.

```
{prefixlen=32, tenant_id=1001, ip=0}              ← "tenant 1001, anything"   /0
{prefixlen=56, tenant_id=1001, ip=10.0.1.0}       ← "tenant 1001, 10.0.1.0/24"
{prefixlen=64, tenant_id=1001, ip=10.0.1.5}       ← "tenant 1001, 10.0.1.5/32"
```

Lookup keys always have `prefixlen=64` (full match requested); the trie walks itself.

### B.6 `bpf_skb_ct_lookup` and conntrack

The Linux kernel maintains a connection tracking table (conntrack) for stateful firewalling and NAT. Each entry is keyed by 5-tuple and stores the original tuple (pre-NAT) plus the reply tuple (post-NAT).

```
Original tuple:    src=1.2.3.4:50000   dst=203.0.113.5:443      (client → floating IP)
Reply tuple:       src=10.0.1.5:443    dst=1.2.3.4:50000        (after DNAT to backend)
```

`bpf_skb_ct_lookup` is a TC-only BPF helper that takes the current packet and queries conntrack, returning a pointer to the matching entry. From there we can read both tuples.

**Why we need it for Octavia (optional refinement).** Used at the Amphora's tap for Segment 1 zone classification — recovering the original client_ip lets us classify the zone as EXTERNAL/OTHER/SAME based on the real client. Attribution to the LB owner does NOT depend on this lookup (it comes from the Amphora MAC flag in `mac_tenant_map`). See §6 for the full algorithm and why `bpf_skb_ct_lookup` is NOT called at the backend's tap.

**Why it's TC-only.** XDP runs before conntrack (at the very earliest stage of packet ingress), so the conntrack entry might not even be matched yet. TC runs *after* `nf_conntrack` has done its lookup, which is why the helper is only available there.

External: [conntrack architecture](https://people.netfilter.org/pablo/docs/login.pdf), [bpf-helpers(7)](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html).

### B.7 Netlink

Netlink is the Linux kernel's primary IPC interface for managing the network stack. The `vishvananda/netlink` Go library wraps it for our use.

We use netlink for three things:

1. **Creating qdiscs** — `netlink.QdiscReplace` adds/replaces the `clsact` qdisc on a tap interface.
2. **Attaching/detaching BPF filters** — `netlink.FilterReplace` and `netlink.FilterDel`.
3. **Subscribing to interface lifecycle events** — `netlink.Subscribe(unix.NETLINK_ROUTE)` gives us `RTM_NEWLINK` and `RTM_DELLINK` notifications. We watch these to attach our BPF program to newly-created taps and clean up registry entries when taps disappear.

External: [netlink(7)](https://man7.org/linux/man-pages/man7/netlink.7.html).

### B.8 OpenStack networking primer

For engineers without OpenStack background, here's the minimum needed.

**Neutron** is OpenStack's networking service. It manages virtual networks, subnets, ports, routers, floating IPs, and security groups — all as API objects.

**OVS (Open vSwitch)** is the kernel-level virtual switch that implements Neutron's networks. OVS has multiple bridges:

- `br-int` — the integration bridge; all VM tap interfaces attach here.
- `br-tun` — the tunnel bridge; encapsulates traffic for cross-host transport.
- `br-ex` — the external bridge; connects to physical infrastructure.

**tap interface (tapXXX)** — a virtual network interface created per VM port. The VM's vNIC is connected to the tap on one end; the other end is plugged into OVS br-int. Our TC hooks attach here.

**VXLAN / Geneve** — overlay tunneling protocols that wrap an Ethernet frame in UDP/IP for transport between hypervisors, each tenant network getting a unique tunnel ID (VXLAN's 24-bit **VNI**, or Geneve's VNI plus extensible options). OVN ML2 — what CubeCOS runs — tunnels with **Geneve**; VXLAN is the traditional-Neutron default. The distinction is immaterial to this design: at our tap layer packets are pre-encapsulation, so we never see either tunnel header.

**Floating IP** — a public IP address allocated to a tenant. When attached to a VM port, the network node performs DNAT (destination NAT) for inbound traffic. The VM still uses its private IP internally; the floating IP is invisible to the VM.

**DVR (Distributed Virtual Routing)** — a *traditional Neutron* mode where each compute node runs its own router namespace. With DVR, intra-tenant E-W routing happens locally; without it, all routing goes through a central network node. Each compute node's DVR router has its own MAC, even for the same logical Neutron router — hence the need for `dvr-mac-addresses` enumeration. **OVN deployments do not use DVR** (see below); they distribute routing via OVS flow rules instead, with a single MAC per logical router across all chassis. CubeCOS targets OVN; DVR is mentioned for context only.

**Address scope** — Neutron's mechanism for allowing cross-tenant routing while preventing CIDR overlap. Subnets in the same address scope must have non-overlapping CIDRs.

**OVN (Open Virtual Network).** CubeCOS deployments use Neutron's **OVN ML2 plugin** instead of the traditional OVS-agent + L3-agent stack. OVN replaces several traditional components:

- The `neutron-openvswitch-agent` on each compute node is replaced by `ovn-controller`, which reads logical flow specifications from the OVN Southbound DB and programs OVS flow tables directly.
- The `neutron-l3-agent` is gone; **logical routers are implemented entirely as OVS flow rules** distributed across all chassis. There are no `qrouter-XXX` namespaces.
- The `neutron-dhcp-agent` is replaced by OVS flow rules that synthesize DHCP responses. Neutron records the DHCP "ports" with `device_owner=network:distributed` and a port status of `DOWN` (because there's no real interface — the MAC and IP exist only as flow-rule parameters).
- Each compute node ("chassis") runs `ovn-controller` plus a `neutron-ovn-metadata-agent` for VM metadata service.

For our cold-start (§5.2), this means **no `dvr-mac-addresses` extension and no per-host MAC enumeration step are needed**: logical routers have a single MAC across all chassis, and that MAC is visible via the standard Neutron port API.

The traditional Neutron architecture is *not* supported by this design; see §13.2 deferred work for the retrofit path if a future deployment requires it.

External: [Neutron API reference](https://docs.openstack.org/api-ref/network/v2/), [OVN architecture](https://www.ovn.org/support/dist-docs/ovn-architecture.7.html).

### B.9 Octavia and Amphora VMs

**Octavia** is OpenStack's load-balancer-as-a-service. When a tenant creates an LB, Octavia provisions an **Amphora** — a dedicated VM running HAProxy — in a special "service" project (typically the admin project). The Amphora sits between external clients and the tenant's backend VMs.

```
external client
    │
    ▼ (port 443 on floating IP)
floating IP   ←── DNAT ──→ Amphora VM (in admin project)
    │
    ▼ HAProxy forwards
Amphora ── NAT'd ──→ backend VM (in tenant project)
```

The naive view: bytes are charged to whoever owns the Amphora (admin). The correct view: bytes are charged to the LB's owning tenant (because they configured the LB and benefit from the traffic). Our design tags Amphora MACs at cold-start with `IsAmphora=true` + `LBOwnerTenant` so traffic touching an Amphora attributes to the LB owner regardless of which tap captures it. HAProxy on the Amphora creates two distinct TCP connections (client↔Amphora, Amphora↔backend); both segments are captured and billed to the same LB owner. See [§6](#6-octavia-lb-attribution).

External: [Octavia architecture](https://docs.openstack.org/octavia/latest/reference/introduction.html).

### B.10 DPDK / SR-IOV / Smart NIC

These are alternative datapaths that bypass the standard kernel network stack — and therefore bypass our eBPF TC hooks.

**DPDK (Data Plane Development Kit)** — userspace networking. The NIC is unbound from the kernel driver and bound to a userspace driver (`vfio-pci`/`uio`). Packets are polled from the NIC into userspace ring buffers; OVS-DPDK handles them entirely in userspace. The kernel network stack is never invoked. TC hooks don't fire.

**SR-IOV (Single Root I/O Virtualization)** — hardware-level NIC virtualization. The physical NIC exposes Virtual Functions (VFs); each VF is assigned to a VM with PCI passthrough. The VM talks directly to the NIC hardware; no virtual switch is involved. No tap interface exists at all.

**Smart NIC offload (NVIDIA BlueField, Intel IPU, AWS Nitro, Mellanox ASAP²)** — the datapath is offloaded to NIC hardware. The hypervisor provisions flows; the NIC enforces them. Some smart NICs run their own embedded OS; some let you load eBPF directly to NIC hardware.

For our design: all three are out-of-scope. They're deployment choices that require alternative telemetry (NIC-level counters, sFlow on physical infrastructure, smart-NIC eBPF). We assume the standard kernel-OVS datapath.

### B.11 Write-Ahead Log (WAL)

A WAL is a durable record of state-changing operations, written before the operation is acknowledged. Databases use WALs for crash recovery; we use a simplified version.

Our WAL is a **single JSON snapshot** of `GlobalState` at a point in time — not an append-only log of operations. The trade-off: simpler implementation, but up to 60 seconds of state can be lost if we crash between flushes.

**Atomic write pattern**: write to `path.tmp`, fsync, `os.Rename` to `path`, then fsync the parent directory. The rename is atomic on POSIX filesystems, so readers either see the old file or the new file — never a partial write. The directory fsync makes the rename itself durable: on ext4/XFS a rename lives in the directory's metadata, and without journaling it a power loss can resurrect the pre-rename view even after the flush reported success.

For a billing system, "≤60s data loss on hard reboot" is acceptable. For tighter guarantees we'd need an append-only log with shorter checkpoints, at higher I/O cost. The simpler scheme also makes the file human-readable for debugging.

---

## Appendix C — Rejected Alternatives

Each section explains an option we considered, why it was attractive, and the deal-breaker that pushed us elsewhere. Some alternatives are still right for *different* deployments — we note when that's the case.

### C.1 XDP hook (instead of TC)

**The pitch.** XDP runs even earlier than TC — at the driver level, before `skb` allocation. It's the fastest possible eBPF hook point, and Cilium and Katran use it for high-throughput packet processing.

**Why we rejected it.**

1. **XDP is ingress-only on tap interfaces.** Empirically confirmed on 2026-04-30: XDP attached to a tap captures 0% of the packets the VM *receives*. We need both directions for billing.
2. **No `bpf_skb_ct_lookup` for XDP.** XDP runs before `nf_conntrack` has matched the packet. Octavia attribution becomes impossible without conntrack.
3. **Throughput advantage is moot for us.** TC processes ~14 Mpps on a single core with our program. The bottleneck on a real OpenStack node is the OVS forwarding pipeline, not our 150ns of telemetry overhead.

**When XDP is the right answer.** L4 load balancers, DDoS mitigation, raw-packet analytics — anywhere you don't need both directions or conntrack.

### C.2 Sampling at OVS / VXLAN envelope extraction

**The pitch.** sFlow on OVS samples 1-in-N packets, captures the full Ethernet frame including VXLAN headers, and ships samples to a collector. The collector parses VNI to identify the tenant network — solving the "same CIDR across tenants" problem cleanly.

**Why we rejected it as the primary mechanism.**

1. **Sampling is wrong for billing.** Default 1:1000 sampling means short-lived flows can be missed entirely; even on long flows, the byte count has statistical error proportional to `1/sqrt(packets_in_flow)`. For long-tail traffic patterns, this is unacceptable. Billing demands every-packet accuracy.
2. **Loses per-VM precision when sampled at the uplink.** sFlow on the physical NIC misses same-host VM-to-VM traffic entirely (it never leaves OVS). sFlow on br-int fixes this but loses the VNI advantage (no VXLAN encap on local traffic).
3. **MAC uniqueness already solves CIDR overlap.** Neutron assigns globally unique MACs across all tenants. Our `mac_tenant_map` resolves the same ambiguity that VNI would resolve in sFlow — we just don't need the outer header.

**When sFlow is the right answer.** Network-wide visibility, anomaly detection, traffic-matrix estimation, capacity planning. We'd happily run sFlow alongside as a secondary observability layer; we just won't bill from it.

### C.3 Direct MySQL queries (instead of Neutron API)

**The pitch.** Direct DB queries are fast (no HTTP overhead), can do JOINs that would otherwise require many API calls, and let us see internal Neutron tables.

**Why we rejected it.**

1. **Schema migrates with every OpenStack release.** Table names, column names, and relationships change. A query that works on Wallaby silently breaks on Yoga — no warning, no error at startup, just wrong data in the trie.
2. **Security.** The agent would need MySQL credentials with read access to Neutron's full database. That's a much bigger blast radius than read-only API access scoped by Keystone token.
3. **Bypasses Neutron's business logic.** Some fields are computed on read by Neutron; querying the DB directly gives raw state without that computation. Risk of subtle correctness bugs.
4. **API performance is fine for our use case.** Cold-start makes 5–10 paginated API calls (with `fields=...` to trim payloads). All joins happen in Go memory after caching. <1 second total startup overhead.

**When direct DB is the right answer.** When you need data the API genuinely doesn't expose (internal IPAM allocation pool state, raw subnet pool tracking). For our use case — MACs, CIDRs, network ownership, router routes — the API has everything.

### C.4 5-tuple flow key (instead of MAC + zone)

**The pitch.** `(src_ip, dst_ip, src_port, dst_port, proto)` is the conventional flow key. It's what NetFlow uses, what conntrack uses, what every flow-analytics tool expects.

**Why we rejected it.**

1. **Cardinality explosion.** Each unique connection (browser tab, RPC call, BGP session, ARP probe) creates a new map entry. A 50-VM node easily reaches >100k entries. Our 65,536 cap is exhausted; pressure-relief GC churns constantly.
2. **Prometheus label explosion.** If we exported by 5-tuple, we'd ship millions of label combinations to Prometheus — the cardinality bomb that kills observability platforms.
3. **MAC-pair scales with topology.** 50-VM node ≈ 850 entries. 500-VM node ≈ 8,500 entries. Topology grows much slower than connection count.
4. **L4 ports add no billing signal.** We charge by tenant and zone. We don't bill TCP ports.

**When 5-tuple is the right answer.** Flow-based intrusion detection, per-connection latency analytics, session reconstruction. Different problem.

### C.5 LRU_HASH for map eviction

**The pitch.** `BPF_MAP_TYPE_PERCPU_LRU_HASH` evicts the least-recently-used entry automatically when the map fills. No userspace GC needed, no map-full errors.

**Why we rejected it.**

1. **Silent data loss.** The kernel evicts entries between scrapes. If a long-running flow's entry is evicted at second 7 of a 10-second scrape window, the bytes accumulated up to that point are gone. We never see them.
2. **No way to flush before eviction.** The LRU eviction is a one-step kernel operation. There's no "tell me when you're about to evict" hook.

**Our alternative.** Standard `PERCPU_HASH` (no auto-eviction) plus userspace pressure-relief GC at >80% fill. The Go agent reads the entry, adds its bytes to GlobalState, *then* deletes it. No bytes lost.

**When LRU_HASH is right.** Approximate analytics where some loss is fine — flow sampling, hot-key detection, top-N tracking.

### C.6 sync.Map for metadata cache

**The pitch.** `sync.Map` is Go's lock-free concurrent map. Avoids RWMutex contention.

**Why we rejected it.**

1. **`sync.Map` is read-optimized.** It's specifically tuned for "read-mostly, rare writes" workloads. We *write* every 10 seconds from Kafka events — that's the dirty path. Under continuous mixed read/write, `sync.Map` performs *worse* than RWMutex.
2. **64-shard RWMutex is simple and fast.** Sharding by `mac_uint64 & 63` distributes contention 64-way. Each shard's RWMutex is uncontended for ~99% of operations.
3. **Predictable performance.** We can reason about lock contention. `sync.Map`'s internal `dirty` / `read` maps make latency harder to predict.

### C.7 Prometheus CounterVec

**The pitch.** `CounterVec` is the idiomatic Prometheus type for cumulative counters with labels. The Prometheus Go client library handles all the bookkeeping.

**Why we rejected it.**

1. **Resets to zero on process restart.** When the agent restarts (planned or crash), the new process starts every `CounterVec` at 0. Prometheus sees the value drop. Its `rate()` function emits a *negative* spike.
2. **Negative `rate()` corrupts billing pipelines.** Anything downstream that integrates rate over time produces wrong totals. Some pipelines silently treat negative values as 0, others as the absolute value, others propagate `NaN`.
3. **No way to "preload" CounterVec from disk.** The library has no public API for setting an initial value above 0.

**Our alternative.** Implement `prometheus.Collector` directly. On `Collect()`, walk our `GlobalState` (which we restore from WAL on boot) and emit the cumulative values. Restart preserves the cumulative — `rate()` stays positive.

### C.8 Always-LPM (no MAC-first hybrid)

**The pitch.** Use only the LPM trie for zone classification — drop the MAC-first comparison from the per-packet path. Simpler kernel code.

**Why we rejected it.**

1. **CIDR ambiguity for direct L2 traffic.** When VM-A talks directly to VM-B in the same subnet, the trie answer depends on subnet entries being correctly populated. If Go's cold-start has a bug or stale data, classification is wrong. MAC comparison is *exact* and trie-independent.
2. **Reduces operational risk surface.** With MAC-first, a misconfigured trie only affects routed traffic. Direct VM-to-VM comms continue working correctly. Failure modes are more localized.
3. **Tiny additional cost.** One extra hash lookup per packet (~50 ns) — well within our overhead budget.

**When always-LPM is right.** A simpler test/demo build where you don't care about routed-vs-direct distinction.

### C.9 Direct CIDR lookup (without nexthop trace)

**The pitch.** When resolving a static route's destination CIDR, just query Neutron for "any subnet with this CIDR" and use the first result.

**Why we rejected it.**

1. **Multiple tenants can have the same CIDR.** Tenant A's `10.0.1.0/24`, Tenant B's `10.0.1.0/24`, and Tenant C's `10.0.1.0/24` are all separate subnets in different network namespaces. Picking "the first match" is arbitrary and wrong.
2. **The static route's nexthop is the disambiguator.** The nexthop is a specific port on a specific subnet attached to a specific router. That router has a known set of attached networks. Scoping the destination CIDR search to those networks gives a deterministic, unambiguous answer.

The nexthop-trace algorithm is detailed in [§5.3](#53-the-static-route-resolver-the-heart-of-step-5).

### C.10 Userspace packet parsing

**The pitch.** Use AF_PACKET / `libpcap` / `tcpdump`-style raw socket capture. Parse packets in Go. Avoid eBPF entirely.

**Why we rejected it.**

1. **CPU at line rate.** Userspace packet capture at 10 Gbps × multiple VMs per host saturates CPU for parsing. eBPF runs the same parsing in the kernel at near-zero cost.
2. **Per-packet syscall.** Even with PACKET_MMAP, you're context-switching once per N packets. eBPF stays in-kernel.
3. **Parsing tax for already-classified traffic.** Most packets are TCP/UDP we're not interested in beyond byte counts. eBPF can short-circuit before doing expensive parsing.

**Empirical benchmarks.** Standard kernel BPF program: ~150 ns/packet. AF_PACKET + Go parser: ~3,000–5,000 ns/packet. 20–30× difference.

### C.11 In-VM agent for OS-level routes

**The pitch.** Install a small agent inside each VM. Have it report routing-table changes to a central service. Use that to populate the trie with OS-level static routes Neutron doesn't know about.

**Why we rejected it.**

1. **Defeats the eBPF design's whole premise.** The point of TC at the tap is that it works regardless of what the VM is running. An in-VM agent makes us depend on guest cooperation.
2. **Tenants run arbitrary OSes.** Windows, BSD, custom Linux distros, containers-as-VMs. Maintaining agents for all is operational pain.
3. **Tenants have admin on their VMs.** A privileged user can disable the agent and reroute traffic invisibly.
4. **Billing-safe fallback exists.** OS-level routes that Neutron doesn't know about fall to `ZONE_EXTERNAL` (charged at the higher external rate). The tenant has incentive to use Neutron-managed routing to get internal rates. This aligns incentives.

### C.12 Store IP in the flow key

**The pitch.** Keep `dst_ip` (and maybe `src_ip`) in the BPF map key so we don't need a separate trie lookup; classification happens at scrape time in Go.

**Why we rejected it.**

1. **Cardinality explosion (same as C.4).** Every distinct IP creates a new entry. `1.2.3.4`, `1.2.3.5`, `1.2.3.6` are separate map entries even if they're all the same external destination.
2. **Breaks IPv6 cleanly.** v6 keys are 16 bytes vs v4's 4 bytes — different key sizes need different maps or padding tricks. Keeping zone codes (1 byte) keeps the key uniform.
3. **Loses kernel-side classification.** If we did the work in Go, the kernel just becomes a counter; we lose the elegance of having pre-classified zones in the key.

---

## Appendix D — Glossary

| Term | One-line definition |
|---|---|
| **Amphora** | The VM that implements an Octavia load balancer (runs HAProxy). |
| **ARP** | Address Resolution Protocol — how a host learns the MAC for a given IP. |
| **BPF / eBPF** | extended Berkeley Packet Filter — kernel-side sandboxed VMs. |
| **BTF** | BPF Type Format — kernel struct metadata, enables CO-RE. |
| **CIDR** | Classless Inter-Domain Routing notation, e.g. `10.0.1.0/24`. |
| **clsact** | A Linux TC qdisc that exposes both ingress and egress hooks. |
| **CO-RE** | Compile Once, Run Everywhere — BTF-driven BPF binary portability. |
| **conntrack** | Kernel connection-tracking table for stateful firewalling and NAT. |
| **DNAT** | Destination NAT — rewriting destination IP/port. |
| **DPDK** | Data Plane Development Kit — userspace networking, bypasses kernel. |
| **DVR** | Distributed Virtual Routing — *traditional Neutron mode only* (per-host router namespaces). Not used by OVN; CubeCOS targets OVN. |
| **floating IP** | A public IP that can be attached to a VM port via DNAT. |
| **GSO/TSO** | Generic/TCP Segmentation Offload — kernel hands NIC a single large packet. |
| **HAProxy** | The load balancer software running inside an Amphora. |
| **LPM** | Longest Prefix Match. |
| **MAC** | Media Access Control address — 48-bit hardware-level identifier. |
| **Netlink** | Linux's IPC for managing the network stack. |
| **Neutron** | OpenStack's networking service. |
| **Nova** | OpenStack's compute service (manages VMs). |
| **Octavia** | OpenStack's load balancer service. |
| **OVS** | Open vSwitch — virtual switch implementing Neutron's networks. |
| **PERCPU** | A BPF map type with one slot per CPU, eliminates atomic contention. |
| **port (Neutron)** | A logical network endpoint with a MAC, IP, and tenant — backs each tap. |
| **qdisc** | Queueing discipline — Linux TC's primary abstraction. |
| **sFlow** | Sampling-based network telemetry protocol. |
| **SR-IOV** | Single Root I/O Virtualization — direct NIC passthrough. |
| **tap interface** | Virtual NIC that carries a VM's traffic to OVS. |
| **TC** | Traffic Control — Linux's kernel layer for shaping/classifying packets. |
| **tenant / project** | An isolation boundary in OpenStack (Keystone term: project). |
| **tuple (5-tuple)** | (src_ip, dst_ip, src_port, dst_port, proto). |
| **VM** | Virtual Machine. |
| **vNIC** | The virtual NIC inside a guest VM. |
| **VNI** | VXLAN Network Identifier — 24-bit tenant network ID. |
| **VXLAN** | UDP-encapsulating overlay protocol for Layer 2 tunneling. |
| **WAL** | Write-Ahead Log — durable record of state for crash recovery. |
| **XDP** | eXpress Data Path — eBPF hook at the NIC driver, fastest but limited. |
| **ZONE** | Our classification: four valid values (SAME / OTHER / EXTERNAL / INFRA) plus MISS as an error / unclassified state. |

---

*Last updated: 2026-05.*
