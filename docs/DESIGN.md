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
| 1 | Classify all traffic into four categories: **Egress** (N-S out), **Ingress** (N-S in), **Intra-Tenant E-W**, **Inter-Tenant E-W** |
| 2 | Re-attribute Octavia LB traffic to the real end-user tenant |
| 3 | Run entirely in the kernel via [eBPF TC](#b1-ebpf-in-60-seconds) at line-rate (10 Gbps+) with near-zero CPU overhead |
| 4 | Maintain real-time OpenStack metadata via Neutron API cold-start + Kafka events |
| 5 | Expose Prometheus cumulative counters at `/metrics` |
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
│   Custom Collector, GlobalState, /var/lib/cubecos/...json snapshot  │
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

> **Implementers:** §13.1 lists six contracts the build must guarantee for correctness. Read those first — they cover invariants that are easy to miss (RLock around `Collect()`, kernel/userspace lifecycle ordering, `*TenantMeta` pointer-replace semantics, boot-order sync points, u64 wraparound, UnresolvedBuffer cap). Violating any of them produces silent billing errors that don't crash the agent.

---

## 3. Data Structures

### 3.1 Kernel-side BPF maps

#### `telemetry_map` — the byte/packet counter

```
Type:        BPF_MAP_TYPE_PERCPU_HASH    ← see B.4
Max entries: 65,536
Pinning:     /sys/fs/bpf/telemetry  (production; demo skips pinning)

KEY:   struct flow_key  (16 bytes, packed)
   ┌──────────────────────────────────────────────────────────┐
   │ src_mac    [6]u8                                         │
   │ dst_mac    [6]u8                                         │
   │ eth_proto  u16   (0x0800 IPv4 / 0x86DD IPv6)             │
   │ direction  u8    (0=VM sending, 1=VM receiving)          │
   │ dst_zone   u8    (0=ext 1=same 2=other 3=infra 4=miss)   │
   └──────────────────────────────────────────────────────────┘

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
- Above **80%**, run pressure-relief in the same goroutine as the scrape, after the BatchLookup completes.
- Eviction order: oldest by `last_seen_ns` first.
- **Per-pass cap: 1,000 entries.** Bounds the worst-case stall to ~50 ms (≈50 µs/entry × 1,000) regardless of how full the map is.
- **Algorithm: single-pass scan with a min-heap of size K=1000** to track the oldest-K by `last_seen_ns`. Cost is O(N log K) where N is current entry count, K=1000. For N=52k (80% fill), this is ~50 ms — included in the per-pass budget. Naïve full sort (O(N log N)) would be ~200 ms; avoid it.
- Floor: **75%** (not 70%). One pass evicts ~3,250 entries at the floor; the cap kicks in first, so the floor is reached over 3–4 successive scrapes — still well under a minute.
- Each pass increments `cubecos_gc_pressure_relief_runs_total` and `cubecos_gc_evictions_total{reason="pressure_relief"}` (§11.4 health metrics).

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

**Dedup is the focus of Sprint 4c**, *not* a deferred item: see `docs/sprint-plan.md` §4c. The chosen shape is **sentinel `tenant_id=0` rows in this same trie** for catchall / INFRA / SHARED, read with a fallback `bpf_map_lookup_elem` on first-lookup miss. Picked over a split-map alternative (`tenant_subnet_trie` + `global_zone_trie`) because pin-path / `ValidateMapSizes` / `LpmKey` surface area stays single-map, and `tenant_id=0` is already reserved by `metadata.TenantIDUnset` — the interner starts at `nextID=1`, so 0 is a natural "applies to all tenants" sentinel rather than a magic value. Cardinality reshapes from `O(T × G + Σ O_t)` to `O(G + Σ O_t)`. The hot-path cost is one extra BPF map lookup on the routed-fallback path; the MAC-first hot path is unchanged. Sprint 4c is also a hard dependency of Sprint 7 — incremental Kafka diffs are cheaper to write against the deduplicated shape than to migrate later.

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
  Value: *TenantMeta { ProjectID, VMName, IsAmphora, DeleteAt }

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
  Key: MAC uint64
  Value: { Bytes, CurrentEbpfValueAtCapture, FirstSeen }
  Capped at ~10,000 entries with LRU eviction.
  Retried every scrape interval.
  On 60s expiry: export under tenant_id="unknown", clear from buffer.

WAL                                 /var/lib/cubecos/network_agent_state.json (+ .bak)
  Atomic JSON snapshot of GlobalState (see B.11).
  Flush every 60s; previous snapshot retained as .bak for recovery from
  a bad write. Read on boot before any other operation.

  Snapshot envelope:
    {
      "schema_version": 1,             // bump on any GlobalState shape change
      "agent_build":    "v0.3.0+abc",  // for ops correlation; informational
      "written_at_ns":  "1746...",     // u64-as-string (see below)
      "global_state":   { ... }        // the actual payload
    }

  u64 fields (byte counters, last_seen_ns, written_at_ns) are encoded as
  decimal strings, not JSON numbers. JSON numbers are IEEE 754 doubles →
  silent precision loss above 2^53 (~83 days at 10 Gbps cumulative).
  Go's encoding/json handles this via the `,string` struct tag.

  Flush procedure (atomic, in this order):
    1. Write payload to wal.json.tmp; fsync.
    2. Rename wal.json → wal.json.bak (best-effort; ignore ENOENT).
    3. Rename wal.json.tmp → wal.json.

  Boot procedure:
    1. Try wal.json. On missing / parse-fail / schema-version-mismatch,
       fall back to wal.json.bak with a loud warning and an internal-error
       counter increment.
    2. If both fail, start empty and log the loss.

  Migration policy:
    - schema_version unknown (newer than this build): refuse to start.
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

When Neutron emits `port.deleted` or `subnet.deleted`, the metadata entry is **NOT** removed immediately. Instead `DeleteAt = now + 60s`. A GC sweeps every 60s and drops expired entries. Reason: dying TCP FIN/RST packets can arrive after the VM is gone — without the lingering ghost they would mis-attribute to `unknown`.

The grace period must be enforced on the **kernel `mac_tenant_map`**, not just the userspace `ShardedMetadataMap`. The per-packet hot path looks up `mac_tenant_map[peer_mac]` and falls through to `ZONE_MISS` if the entry is missing there — regardless of what userspace thinks. See §3.4 for the exact insert/delete ordering rules across both maps.

**Precedence over UnresolvedBuffer.** A Lingering Ghost entry is still a *hit* in **both** maps — packets matching it attribute to the ghosted tenant, not the UnresolvedBuffer. The UnresolvedBuffer (§3.2) catches only MACs Neutron has *never* told us about (typically late Kafka delivery for a brand-new VM). The two paths are mutually exclusive: ghosts cover the tail of a known MAC's life; UnresolvedBuffer covers the head before the first Kafka event lands.

### 3.4 Map lifecycle invariants

The kernel `mac_tenant_map` is the load-bearing copy for billing — every packet's classification depends on it. The userspace `ShardedMetadataMap` carries richer metadata (project_id UUID, VM name, IsAmphora flag, DeleteAt) but the kernel only reads its own map. Keeping the two consistent requires strict ordering on every operation.

**Invariant.** `mac_tenant_map` (kernel) is a strict subset of `ShardedMetadataMap` (userspace): every kernel entry has a userspace entry.

| Event | Order | Why |
|---|---|---|
| **Insert** (Kafka `port.created` or cold-start) | userspace `ShardedMetadataMap` FIRST → then kernel `mac_tenant_map` | When the kernel classifies the next packet, userspace is already ready to enrich the resulting `tenant_id` into a project_id label at scrape time |
| **Mark for delete** (Kafka `port.deleted` / `subnet.deleted`) | set `DeleteAt = now + 60s` on the userspace entry. **Kernel entry is NOT touched.** | Dying FIN/RST packets continue to classify correctly during the grace window (§3.3) |
| **GC sweep** (every 60s; entries with `DeleteAt < now`) | kernel `mac_tenant_map` FIRST → then userspace `ShardedMetadataMap` | At no point does the kernel return a `tenant_id` that userspace can't translate; avoids `tenant=unknown` labels on scrapes that happen to race the deletion |

**Violations are silent** — they don't crash the agent, they produce small but real billing errors:

| Mistake | Visible symptom |
|---|---|
| Insert kernel-first | First packets of a brand-new VM miss in the kernel → land in UnresolvedBuffer for a brief window before the kernel entry catches up |
| Delete kernel immediately on `port.deleted` (skipping the 60s grace) | Dying FIN/RST packets attribute to `tenant=unknown` instead of the right tenant. The Lingering Ghost is functionally dead — under-billing on every shut-down VM |
| GC deletes userspace first | Brief window where a kernel hit can't be enriched → `tenant=unknown` labels on the next scrape's Collect output |

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
        "compute:nova"             →
          vm_owner = nexthop_port.tenant_id
          return zone_for(vm_owner, source_tenant, iface_subnet.network)
          ← VM appliance: classify by the appliance's Neutron-visible tenant.
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

**VM-appliance nexthop.** When a nexthop resolves to a `compute:nova` port (a VM acting as a software router, NAT box, or VPN gateway), the trace stops there — Neutron has no visibility into what the appliance does with the traffic. The zone for the destination CIDR is determined by the appliance's own Neutron tenant using `zone_for`, giving correct attribution for the immediate hop. However, when the appliance forwards traffic onward, that egress is independently counted at the appliance's own tap — the same bytes appear in billing twice, once at the originating VM's tap and once at the appliance's tap. See §8 Tier 4 and Scenario L.

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

Sprint 7 will wire Kafka events into incremental trie updates. The BPF LPM trie supports per-entry insert and delete, but **not** transactional multi-entry batches. For changes that touch multiple entries (e.g., a `router.routes` update that affects N CIDR mappings), strict ordering is required:

```
For a change set that REPLACES entries:
  1. Compute the diff:   new_entries[], obsolete_entries[]
  2. Insert / overwrite all new_entries[]   (LPM allows upsert at same key)
  3. Delete obsolete_entries[]              (only after all inserts complete)
```

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

This is the same model AWS (ELB) and GCP (Cloud Load Balancing) use: each segment is independently captured at its interface (ENI/VNIC/tap) and independently billed. The billing pipeline sums and dedupes downstream.

### Billing model — both segments attribute to the LB owner

Naïvely, traffic at the backend's tap appears to come from the Amphora's MAC and would attribute to admin (Amphora's owner). But the customer is the LB's owning tenant. The fix: tag Amphora MACs at cold-start.

| Segment | Captured at | dst_zone | Tenant attribution |
|---|---|---|---|
| 1: client ↔ Amphora | Amphora's tap | depends on client location (EXTERNAL / OTHER / SAME) | LB owner |
| 2: Amphora ↔ backend | Amphora's tap **and** backend's tap | INFRA (LB internal plumbing) | LB owner |

Total LB-mediated billing = Segment 1 + Segment 2 bytes. Segment 2 appears at two taps; billing-pipeline dedup follows the same pattern as the both-side counting note in §8 Tier 4 #15.

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

Total bytes billed to T1 = Segment 1 + Segment 2. Segment 2 is also visible at the Amphora's tap (other direction); the billing pipeline dedupes — same pattern as §8 Tier 4 #15.

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

Both-sides counting is intentional. Aggregation logic must pick one side per direction to avoid double-counting at the tenant level.

### Scenario J — Cross-host, same-tenant (VXLAN tunneled)

```
VM-A on host1 ──→ OVS encap ──→ VXLAN ──→ host2 OVS decap ──→ VM-B
```

| Hook | What it sees | dst_zone |
|---|---|---|
| VM-A tap on host1, ingress | plain Ethernet (pre-encap) | SAME ✓ |
| VM-B tap on host2, egress | plain Ethernet (post-decap) | SAME ✓ |

VXLAN tunnel is invisible to TC at the tap layer, which is correct.

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

### Tier 2 — Require explicit handling

| # | Edge case | Failure | Fix |
|---|---|---|---|
| 4 | Map full (>65k flows) | `bpf_map_update_elem` returns `-E2BIG`; bytes lost | Pressure-relief GC at >80% fill; evict oldest by `last_seen_ns`, **flush to GlobalState first** |
| 5 | PERCPU first-packet TOCTOU | Two CPUs race on creation; one's BPF_ANY overwrites the other | At most 1 packet lost per new flow per race. Documented & accepted |
| 6 | GSO/TSO offload | `skb->len` is aggregate (correct bytes); packets undercounted | Bill on bytes, not packets |
| 7 | Boot ordering: TC attached before trie populated | First flows permanently keyed `dst_zone=MISS` | Enforce sequence with sync gates ([§9](#9-boot-sequence-order-matters)) |
| 8 | WAL window (60s) | Up to 60s data loss on hard reboot | Documented; tunable |

### Tier 3 — Misclassification (bytes still counted, but wrong zone)

| # | Edge case | Failure | Fix |
|---|---|---|---|
| 9 | OS-level static route inside VM | Falls to EXTERNAL | Unsolvable; safe-billing fallback |
| 10 | Port security disabled + MAC spoof | `mac_tenant_map[spoofed]` misses or hits wrong tenant | Require Neutron port_security_enabled=true (default) |
| 11 | DVR with per-host router MACs (traditional Neutron only — n/a on OVN) | Each compute node's [DVR](#b8-openstack-networking-primer) router has a different MAC | Not encountered on OVN deployments (single MAC per logical router across chassis); if a traditional Neutron deployment is ever supported, reinstate the cold-start enumeration step — see §13.2 |
| 12 | VM uses its own GRE/VXLAN/IPsec | We see outer headers; classification on tunnel endpoint | Document; treat as external |
| 13 | IPv6 not in trie | All v6 → ZONE_MISS | Extend trie schema to 32-byte v6 keys (future work) |
| 14 | Late Kafka delivery (new VM not yet in MAC map) | First packets → ZONE_MISS | UnresolvedBuffer late-binding + write-back to LastEbpfRaw |
| 14a | OVN-synthesized DHCP `server_mac` not visible in Neutron port API (verified empirically) | DHCP responses to VMs have a `peer_mac` that misses `mac_tenant_map` | LPM trie carries the classification via `gateway_ip/32 → INFRA` (§5.2 Step 4). Visible as a small fraction of packets classified via the LPM-only path instead of the hybrid path; functionally correct |

### Tier 4 — Subtle correctness

| # | Edge case | Risk | Fix |
|---|---|---|---|
| 15 | Both-side counting (sender tap + receiver tap) | Naive sum doubles the total | Aggregation picks one side per direction; metric labels include host_id |
| 16 | VM live migration | Brief tap flap | Lingering ghost (60s) prevents misattribution; few-packet loss bounded |
| 17 | Conntrack miss on Segment 1 zone classification | The optional `bpf_skb_ct_lookup` at the Amphora's tap may miss (first SYN, TTL expiry, UDP >30s idle, lookup at the wrong tap). Segment 1 zone falls back to EXTERNAL | Attribution to LB owner is unaffected — it comes from the Amphora MAC flag, not conntrack. See §6 |
| 18 | u64 wraparound | At 10 Gbps continuous, ~467 years to overflow (2⁶⁴ / 1.25 GB/s ≈ 1.5×10¹⁰ seconds). The guard is one comparison, so add it anyway | — |
| 19 | Crashed agent leaves orphan TC filters | Stale filters double-count if agent restarts | Either zombie hunter at startup, or accept until reboot |
| 20 | Multicast / broadcast | One sent packet, many receivers → ingress sum doubles | Filter or accept as <0.1% noise |
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

4. Attach TC clsact to existing taps
   → populate Interface Registry

5. Read WAL → restore GlobalState

6. BatchLookup kernel map → merge deltas into GlobalState
   → handles agent-crash recovery (kernel map persists)

7. Start GC goroutine (lingering ghost + map pressure relief)

8. Expose /metrics HTTP endpoint

9. Start Kafka consumer (live metadata updates)

10. Start Netlink Watcher (dynamic tap lifecycle)
```

### Failure modes if order is violated

| Skip / reorder | Consequence |
|---|---|
| TC attach before trie populated | First flows permanently keyed `dst_zone=MISS`; never reclassify |
| GC before WAL merge | Active flows evicted before `LastEbpfRaw` set → counter spike on next scrape |
| Netlink Watcher before TC attach | `RTM_NEWLINK` for an existing iface races the initial loop → double-attach |
| Skip Zombie Hunter | Restart stacks duplicate filters → every packet counted twice |

### Failure policy — Neutron API and Kafka outages

**Neutron API unreachable at cold-start** (step 3 cannot complete):
- Block with exponential backoff (start 1s, cap at 30s, indefinite retries).
- State surfaced via `cubecos_neutron_sync_age_seconds=∞` and `cubecos_internal_errors_total{subsystem="neutron"}`.
- **Do NOT proceed to step 4 (TC attach).** Without metadata, every packet classifies as `ZONE_MISS`, and once that miss is written into the kernel `flow_key` it is permanent (zone is in the key — see §3.1). Blocking at boot is the only correctness-safe policy.
- An explicit `--unsafe-allow-degraded-boot` flag may be added later for operators who want fail-open behavior during planned Neutron upgrades; default is fail-closed.

**Neutron API unreachable at runtime** (cold-start succeeded, periodic refresh fails):
- Continue serving from the in-memory snapshot.
- Each failed call increments `cubecos_neutron_api_errors_total{endpoint, code}` and ages `cubecos_neutron_sync_age_seconds`.
- The Kafka consumer keeps state fresh when it's available; the periodic Neutron refresh is a safety net (see Kafka outage below).

**Kafka unreachable** (cold-start succeeded, then Kafka becomes unreachable):
- The agent's metadata becomes increasingly stale: new VMs miss in `mac_tenant_map` → land in UnresolvedBuffer; deleted VMs over-stay their 60s ghost; route changes don't apply.
- **Periodic Neutron reconcile every 5 minutes** mitigates this. The reconcile is a full snapshot fetch (same as cold-start step 3) + diff against current state; differences are applied as if Kafka had delivered them. **Bounds metadata staleness to 5 minutes regardless of Kafka availability.**
- `cubecos_kafka_lag_messages` and `cubecos_kafka_consume_errors_total` surface the outage; alerting threshold suggested: `lag > 1000` sustained.

**Partial Neutron failures** (e.g., `GET /v2.0/ports` succeeds, `GET /v2.0/routers` returns 500):
- **Cold-start is all-or-nothing.** If any required endpoint fails, the entire cold-start fails and the boot loop retries from the top. Starting with partial metadata reproduces the same permanent-miss problem as a full Neutron outage.
- **Runtime reconcile is best-effort per endpoint.** A 500 on one endpoint doesn't invalidate state derived from successfully-fetched endpoints; the per-endpoint error counter tracks recovery. The 5-minute reconcile will retry the failed endpoint on its next cycle.

---

## 10. Crash Resilience

### Agent crash (process killed, kernel intact)

- Kernel map is pinned at `/sys/fs/bpf/telemetry` → survives.
- TC filters reference the program; program reference is held by the filter → survives.
- New agent reads [WAL](#b11-write-ahead-log-wal) → restores GlobalState (cumulative counters).
- BatchLookup reads kernel map → merges since last WAL checkpoint.
- **Net data loss: 0.**

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

**Sprint 1+ implementation note.** `max_entries` and the memory budget must be exposed as config flags (default budget 50 MB). Without this, deploying the agent on a 128-core host with `max_entries=65536` consumes ~200 MB of kernel RAM — 4× the documented budget. The `cubecos_bpf_map_max_entries` gauge (§11.4) surfaces the actual sized value per host.

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

  At high core counts the documented "5 ms" is no longer realistic; the scrape budget must account for the actual N_CPU. The `cubecos_collect_duration_seconds` histogram (§11.4) surfaces this per node.

- Map iteration during GC: same cost; runs in the same scrape goroutine (after BatchLookup).
- **WAL flush** breaks into three phases, not just fsync:

| Phase | Cost | Lock held? |
|---|---|---|
| Copy GlobalState into a temp buffer | ~5 ms for 10k entries | RLock on GlobalState, briefly |
| Marshal Go struct → JSON | ~50–100 ms for 600 KB output | no lock |
| Write + fsync + rename + rotate `.bak` | ~5–10 ms (varies wildly on slow disks) | no lock |

  The original "5–10 ms" estimate referenced only the fsync — marshaling dominates. The critical section (lock-held) is just the copy phase, so a slow disk does NOT block the scraper. Per-phase metrics: `cubecos_wal_snapshot_copy_seconds`, `cubecos_wal_marshal_seconds`, `cubecos_wal_flush_latency_seconds` (the last covers write+fsync+rename only).

### Health metrics catalog

Two tiers of metrics. **Billing metrics** (the thing we exist to produce) are
emitted by the custom `prometheus.Collector` from `GlobalState` — labels match
the design's existing fan-out (tenant, zone, direction). **Health metrics**
(operator-facing instrumentation) are bounded-cardinality; an operator running
`promql` against one node should see <100 series total.

#### Billing (cumulative counters; emitted from GlobalState)

| Metric | Type | Labels |
|---|---|---|
| `cubecos_tenant_bytes_total` | counter | `tenant_id, zone, direction` |
| `cubecos_tenant_packets_total` | counter | `tenant_id, zone, direction` |

#### Health (per-subsystem; bounded cardinality)

| Metric | Type | Labels | Source |
|---|---|---|---|
| `cubecos_bpf_map_fill_ratio` | gauge | `map="telemetry\|trie\|mac_tenant"` | sampled from BPF map info |
| `cubecos_bpf_map_max_entries` | gauge | `map="telemetry\|trie\|mac_tenant"` | configured at startup; surfaces actual sizing per host (telemetry map scales by N_CPU per §11) |
| `cubecos_gc_evictions_total` | counter | `reason="ttl\|pressure_relief"` | GC loop |
| `cubecos_gc_pressure_relief_runs_total` | counter | — | pressure-relief trigger |
| `cubecos_unresolved_buffer_depth` | gauge | — | UnresolvedBuffer |
| `cubecos_unresolved_buffer_evictions_total` | counter | `reason="lru\|expired"` | UnresolvedBuffer |
| `cubecos_unresolved_resolved_total` | counter | — | late-binding success path |
| `cubecos_wal_snapshot_copy_seconds` | histogram | — | WAL writer, copy-under-lock phase (critical section) |
| `cubecos_wal_marshal_seconds` | histogram | — | WAL writer, JSON marshal phase (no lock held) |
| `cubecos_wal_flush_latency_seconds` | histogram | — | WAL writer, write+fsync+rename phase (no lock held). Buckets: 1ms..1s |
| `cubecos_wal_flush_failures_total` | counter | `stage="write\|fsync\|rename_bak\|rename_current"` | WAL writer |
| `cubecos_wal_load_fallback_total` | counter | `from="bak\|empty"` | boot loader |
| `cubecos_neutron_sync_age_seconds` | gauge | — | last successful cold-start or full reconcile |
| `cubecos_neutron_api_errors_total` | counter | `endpoint, code` (code is HTTP status class) | Neutron client |
| `cubecos_kafka_lag_messages` | gauge | `topic` | Kafka consumer |
| `cubecos_kafka_consume_errors_total` | counter | `topic` | Kafka consumer |
| `cubecos_zombie_filters_cleaned_total` | counter | — | startup Zombie Hunter |
| `cubecos_tc_attach_failures_total` | counter | `iface_kind="tap\|other"` | Netlink Watcher |
| `cubecos_lingering_ghosts_active` | gauge | — | metadata GC |
| `cubecos_collect_duration_seconds` | histogram | — | Prometheus Collector |
| `cubecos_internal_errors_total` | counter | `subsystem` | billing-path error sink (see §13.1) |

Cardinality discipline: **never** label a health metric with `tenant_id`,
`mac`, `flow_key`, or any per-flow identifier. Anything per-flow goes only
into the billing tier, whose cardinality is already bounded by the trie /
MAC-pair model (§3.1).

SLO targets (informational, refined post-MVP):
- `cubecos_neutron_sync_age_seconds` < 120 (Kafka-driven freshness)
- `cubecos_wal_flush_latency_seconds` p99 < 50 ms
- `cubecos_unresolved_buffer_depth` < 1000 sustained (10k cap is a panic threshold)
- `cubecos_bpf_map_fill_ratio{map="telemetry"}` < 0.8 (above triggers pressure-relief GC)

### Scalability ceiling

- The `telemetry_map` upper bound is `max_entries` (computed by the formula above; ranges from 8,192 on high-core hosts to 65,536 on 32-core).
- That bound limits distinct (MAC-pair, direction, zone) combinations per node.
- On a 50-VM node: typical fill is ~850 entries (well under any tier of the cap).
- On a 500-VM node (extreme): proportional ~8,500 entries — still safe at 32-core (~13% fill), but on a 128-core host where `max_entries=16,384` this is ~52% fill, and pressure-relief GC will activate sooner.
- If the agent reports fill ratio >80% sustained on a given host, the deployment has outgrown that host's `max_entries`; raise the memory budget config or add more compute nodes.

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

### 13.2 Deferred Work

Explicitly out of MVP scope. Documented so future contributors know it's open by design, not oversight.

| # | Item | Notes |
|---|---|---|
| 1 | IPv6 zone resolution | All v6 traffic currently classifies as ZONE_MISS. Retrofit path: add a second LPM trie keyed `(tenant_id, u8[16])` alongside the existing v4 trie; branch in `lookup_zone()` on `eth_proto`. The 5-step cold-start algorithm (§5.2) is IP-version-agnostic — only insertion code changes. Estimated ~1 sprint, low risk |
| 2 | Traditional Neutron (OVS-agent + L3-agent + qrouter namespaces, with or without DVR) | Tested OVN deployments (single-node and 3-node HA) run OpenStack Yoga with OVN ML2 — verified empirically. Traditional Neutron is therefore out of scope. If a future deployment requires it, the cold-start algorithm needs a "Step 6 — DVR per-host MAC enumeration" reinstated (using the `dvr-mac-addresses` Neutron extension); see git history of this file for the removed text. Estimated ~1 sprint to re-add |
| 3 | Cross-goroutine boot sync barrier (`boot.Sequencer.Await` / `Fail`) | `Bootstrap` advances every phase straight-line in one goroutine and returns before `Run` spawns the consumer goroutines, so the boot ordering (Contract #4) holds structurally and `boot.Sequencer` is an in-`Bootstrap` order validator + phase logger. When the Kafka updater or GC advance / block on phases from their own goroutines, add channel-backed `Await(Phase)` / `Fail(err)` so consumers wait on a named phase instead of relying on straight-line execution. Deferred by design, not oversight. Estimated <1 sprint, low risk |
| 4 | Static-route EXTERNAL-fallback counter (`cubecos_neutron_static_route_fallback_total{reason}`) | `resolveStaticRouteZone` (resolve.go) has six EXTERNAL fallback exits; three warn-log (cycle, MAX_HOPS, ambiguity), the others (anchor-subnet miss, port-at miss, unknown next-router device, unknown device-owner) return EXTERNAL silently. A per-`reason` counter would make the fallback rate visible on `/metrics`. Deferred until it can be validated against a real cluster's `/metrics` deltas — it touches billing-relevant route classification, so per the project's validate-before-billing-changes rule it should not ship on theory. Observability-only (counts existing EXTERNAL returns; changes no classification). Estimated <1 sprint, low risk |

### 13.3 Construction Conventions

Several constructor idioms coexist *by design*. New code matches the closest existing one rather than inventing a sixth, and the outliers below are deliberately **not** normalised — converting them only churns tests for no behavioural gain.

| Idiom | Used by | When |
|---|---|---|
| Options struct | `agent.New(Options)`, `netlink.New(Options)`, `config.Load(Options, …)` | More than ~2 inputs, or any optional / defaulted field. The reference pattern — reach for it first |
| Positional params | `scraper.New(reader, st, interval)`, `metadata.NewResolver(m)` | ≤2 unambiguous required args, no options |
| Bare `New()` | `state.New`, `boot.New`, `metadata.New`, `netlink.NewRegistry`, every per-package `NewMetrics` | Zero-config value types. Metric bundles are uniformly `type Metrics` + `NewMetrics()` |
| Functional options | `neutron.BuildTrie(…, WithMetrics(m))` | Reserved for `BuildTrie` alone — keeps its many test call-sites argument-free; not spread to other constructors |
| `Run(Config)` | `perfbench.Run`, `loadtest.Run` | Single-shot CLI harnesses, not long-lived services |

---

## Appendix A — Design Decisions Table

| Decision | Chosen | Rejected | Why |
|---|---|---|---|
| eBPF hook | TC clsact (ingress + egress) | XDP | XDP is ingress-only on tap; no `bpf_skb_ct_lookup` for Octavia. [C.1](#c1-xdp-hook-instead-of-tc) |
| Octavia LB attribution (LB-owner) | Amphora MAC flag in `mac_tenant_map` | Conntrack tuple recovery as the primary mechanism | HAProxy creates two distinct TCP connections (verified empirically); client_ip isn't recoverable at the backend's tap. MAC-flag attribution works at every tap and matches AWS/GCP segment-by-segment billing |
| Segment 1 zone (LB) | Optional `bpf_skb_ct_lookup` at Amphora's tap | Always EXTERNAL for LB Segment 1 traffic | Conntrack recovery refines the zone to OTHER/SAME when the client is internal; EXTERNAL is the safe-billing fallback on miss |
| Crash resilience | Read, don't clear (pinned map persists) | Clear after each scrape | Zero data loss on agent restart |
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

**VXLAN** — overlay tunneling protocol that wraps an Ethernet frame in UDP/IP for transport between hypervisors. Each tenant network gets a unique 24-bit **VNI** (VXLAN Network Identifier). At our tap layer, packets are pre-encapsulation; we never see the VXLAN header.

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

**Atomic write pattern**: write to `path.tmp`, fsync, then `os.Rename` to `path`. The rename is atomic on POSIX filesystems, so readers either see the old file or the new file — never a partial write.

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
