# CubeCOS Network Telemetry — Design Document

> Per-tenant, line-rate network telemetry for OpenStack via eBPF TC.
> This document is the canonical reference for the design.
> Use it to onboard engineers, review changes, or evaluate trade-offs.

---

## Reading Guide

This document assumes general systems engineering background. Specialized terminology is defined in [Appendix B — Concept Primer](#appendix-b--concept-primer); links appear at first use in the main text.

| Topic | First needed in | Primer |
|---|---|---|
| eBPF, TC, BTF | §2, §3 | [B.1](#b1-ebpf-in-60-seconds), [B.2](#b2-tc-clsact-qdisc), [B.3](#b3-btf-bpf-type-format) |
| `BPF_MAP_TYPE_PERCPU_HASH` | §3 | [B.4](#b4-percpu_hash) |
| `BPF_MAP_TYPE_LPM_TRIE` | §3, §5 | [B.5](#b5-lpm-trie) |
| `bpf_skb_ct_lookup`, conntrack | §6 | [B.6](#b6-bpf_skb_ct_lookup-and-conntrack) |
| Netlink, RTM_NEWLINK | §9 | [B.7](#b7-netlink) |
| OpenStack: Neutron / OVS / VXLAN / DVR / Floating IP | §1, §5, §7 | [B.8](#b8-openstack-networking-primer) |
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
13. [Open Issues](#13-open-issues)
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

- Linux 5.10+ with [BTF](#b3-btf-bpf-type-format), x86_64
- Deployed as a daemon per OpenStack compute node
- Standard [OVS kernel datapath](#b8-openstack-networking-primer) ([DPDK/SR-IOV](#b10-dpdk--sr-iov--smart-nic) are out of scope — see [§8](#8-edge-cases--accuracy-ceiling))
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

**Why MAC-pair, not 5-tuple.** MAC-pair scales with topology (~850 entries on a 50-VM node). 5-tuple scales with connection count and explodes both the map and downstream Prometheus labels. Detailed comparison in [C.4](#c4-5-tuple-flow-key-instead-of-mac--zone).

**Why `dst_zone` is in the key.** When VM-A in subnet-1 sends to VM-B in subnet-2 via the tenant router, the L2 destination MAC at VM-A's tap is the router's MAC — *identical* to VM-A talking to the internet via the same router. Without an L3 classification baked into the key, the four billing categories collapse into one ambiguous bucket. `dst_zone` is the L3 tiebreaker, populated by an in-kernel [LPM lookup](#b5-lpm-trie).

#### `subnet_zone_trie` — the L3 zone resolver

```
Type:        BPF_MAP_TYPE_LPM_TRIE       ← see B.5
Max entries: 4,096
Flags:       BPF_F_NO_PREALLOC

KEY:   struct lpm_key
   ┌──────────────────────────────────────────────────────────┐
   │ prefixlen  u32   (bits in tenant_id ++ ip)               │
   │ tenant_id  u32   (always exact-matched, 32 bits)         │
   │ ip         u32   (host byte order, IPv4)                 │
   └──────────────────────────────────────────────────────────┘

VALUE: u8  zone code

Insertion examples:
  Catchall for tenant 1001:
    {prefixlen=32, tenant_id=1001, ip=0}             → ZONE_EXTERNAL
  /24 subnet for tenant 1001:
    {prefixlen=56, tenant_id=1001, ip=10.0.1.0}      → ZONE_SAME_TENANT
  Single-host /32 (e.g., metadata svc):
    {prefixlen=64, tenant_id=1001, ip=169.254.169.254} → ZONE_INFRA
```

**Why `(tenant_id, ip)` and not just `ip`.** Two tenants can have the same CIDR (e.g., both register `10.0.1.0/24`). Zone is **always relative to the source VM's tenant** — `10.0.1.0/24` may be `SAME_TENANT` for tenant 1001 and `OTHER_TENANT` for tenant 1002. Scoping the key by `tenant_id` makes both views coexist in one trie.

#### `mac_tenant_map` — MAC-to-tenant lookup

```
Type:        BPF_MAP_TYPE_HASH
Max entries: 1,024

KEY:   u64  (MAC packed into low 48 bits, big-endian byte order)
VALUE: u32  (tenant_id)
```

Populated for VMs, plus router interface MACs (`network:router_interface`). NOT populated for external/internet MACs.

### 3.2 Userspace structures (Go agent)

```
ShardedMetadataMap                  64 shards × sync.RWMutex
  shard_idx = mac_uint64 & 63
  Key:   MAC as uint64
  Value: *TenantMeta { ProjectID, VMName, IsAmphora, DeleteAt }

  INVARIANT: TenantMeta is immutable.
             Multiple MACs may share the same pointer.
             Updates replace the pointer atomically — never mutate fields.

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

WAL                                 /var/lib/cubecos/network_agent_state.json
  Atomic JSON snapshot of GlobalState (see B.11).
  .tmp + os.Rename every 60 seconds.
  Read on boot before any other operation.
```

### 3.3 Lingering Ghost (60s TTL on metadata deletion)

When Neutron emits `port.deleted` or `subnet.deleted`, the metadata entry is **NOT** removed immediately. Instead `DeleteAt = now + 60s`. A GC sweeps every 60s and drops expired entries. Reason: dying TCP FIN/RST packets can arrive after the VM is gone — without the lingering ghost they would mis-attribute to `unknown`.

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

---

## 5. Trie Construction at Cold Start

The kernel performs a single LPM lookup per packet; all classification intelligence resides in **how Go assembles the trie** before traffic starts flowing.

### 5.1 Data sources (Neutron v2.0 API)

| Endpoint | Fields used |
|---|---|
| `GET /v2.0/networks` | `id, tenant_id, shared, router:external` |
| `GET /v2.0/subnets` | `id, network_id, cidr, tenant_id, gateway_ip` |
| `GET /v2.0/ports` | `id, network_id, mac_address, device_id, device_owner, fixed_ips, tenant_id` |
| `GET /v2.0/routers` | `id, tenant_id, external_gateway_info, routes` |
| `GET /v2.0/address-scopes` + `subnetpools` | optional, for explicit cross-tenant peering |

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
      add (T, S.cidr) → ZONE_OTHER_TENANT
    (or ZONE_INFRA if your billing model treats shared infra separately)

  Step 4 — Infrastructure ports
    for each port P with device_owner in {network:dhcp, network:metadata}:
      add (T, P.fixed_ip/32) → ZONE_INFRA
    Add Nova metadata service:
      add (T, 169.254.169.254/32) → ZONE_INFRA

  Step 5 — Static routes (extraroutes) on T's routers   [the hard part]
    for each router R where R.tenant_id == T:
      for each (destination_cidr, nexthop) in R.routes:
        zone = resolve_static_route_zone(R, destination_cidr, nexthop)
        add (T, destination_cidr) → zone
```

### 5.3 The static route resolver (the heart of step 5)

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
  if owner_tenant == source_tenant:       return SAME_TENANT
  if network.shared == true:              return OTHER_TENANT
  return OTHER_TENANT
```

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

---

## 6. Octavia LB Attribution

### Context

An [Octavia](#b9-octavia-and-amphora-vms) load balancer is implemented by an **Amphora** VM in the admin project. Traffic flow:

```
external client ──→ floating IP ──[DNAT]──→ Amphora VM ──[NAT]──→ backend VM
```

At the backend VM's tap, the packet appears to come from the Amphora — `src_ip = Amphora_ip`, `src_mac = Amphora_mac`. Naively, bytes get attributed to the admin project (Amphora's owner). But the actual customer using the LB is the LB's owning tenant.

### Solution: [`bpf_skb_ct_lookup`](#b6-bpf_skb_ct_lookup-and-conntrack)

In the kernel, before classifying the flow, check if either MAC belongs to an Amphora (lookup metadata flag `IsAmphora=true`). If yes, call `bpf_skb_ct_lookup` to retrieve the conntrack entry for the packet. The conntrack entry carries the **pre-NAT tuple** — the original `(client_ip, floating_ip)`.

Re-run classification using the pre-NAT tuple. The flow is then bucketed under the LB's owner-tenant with `dst_zone=EXTERNAL` (since the client was external).

### Why `bpf_skb_ct_lookup` is TC-only

This helper is only available in TC programs, not XDP. It's another reason TC was chosen — see [C.1](#c1-xdp-hook-instead-of-tc).

---

## 7. Scenario Walkthroughs

Each scenario traces the packet path, the resulting classification, and correctness on each side.

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
| VM-A tap, ingress | AA→T1 | router_qr1_mac | likely yes (router iface) | hybrid: tenants match | SAME ✓ |
| VM-B tap, egress | BB→T1 | router_qr2_mac | yes | hybrid: tenants match | SAME ✓ |

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
client 1.2.3.4 ──→ floating IP ──→ Amphora ──[NAT]──→ VM-B (T1 backend)
```

At VM-B's tap (egress): `src_ip=Amphora_ip, dst_ip=B_ip, src_mac=Amphora_mac`.

| Without conntrack lookup | dst_zone |
|---|---|
| LPM (T1, Amphora_ip) → likely SAME (Amphora lives on T1's net) | wrong: actual client is external |

| With `bpf_skb_ct_lookup` | dst_zone |
|---|---|
| Recover original tuple (1.2.3.4 → floating_IP). Re-classify: remote_ip = 1.2.3.4 → catchall | EXTERNAL ✓ |

Tenant attribution: floating IP → LB → owner_tenant (T1). Bytes billed to T1 even though Amphora is admin-owned.

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
| VM-A tap, ingress | 0 | AA→T1 | R1's `qr` MAC (router) | `(T1, 10.99.0.0/16)` | OTHER ✓ |

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
| 11 | DVR with per-host router MACs | Each compute node's [DVR](#b8-openstack-networking-primer) router has a different MAC | Cold-start enumerates all DVR router MACs per host |
| 12 | VM uses its own GRE/VXLAN/IPsec | We see outer headers; classification on tunnel endpoint | Document; treat as external |
| 13 | IPv6 not in trie | All v6 → ZONE_MISS | Extend trie schema to 32-byte v6 keys (future work) |
| 14 | Late Kafka delivery (new VM not yet in MAC map) | First packets → ZONE_MISS | UnresolvedBuffer late-binding + write-back to LastEbpfRaw |

### Tier 4 — Subtle correctness

| # | Edge case | Risk | Fix |
|---|---|---|---|
| 15 | Both-side counting (sender tap + receiver tap) | Naive sum doubles the total | Aggregation picks one side per direction; metric labels include host_id |
| 16 | VM live migration | Brief tap flap | Lingering ghost (60s) prevents misattribution; few-packet loss bounded |
| 17 | Conntrack miss on first SYN | First Octavia-NAT'd packet has no conntrack entry yet | Tiny edge — first packet to admin, then corrected |
| 18 | u64 wraparound | At 10 Gbps continuous, ~14.6 years to overflow | Add wraparound guard in delta math anyway |
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
   → populate mac_tenant_map (all VM ports + router interface MACs)
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
| `telemetry_map` PERCPU_HASH | 65,536 entries × (16 + 24×N_CPU) bytes. On a 32-core node: ~50 MB max. Typical fill (~850 flows on 50-VM node): <1 MB |
| `subnet_zone_trie` LPM | ~4,096 entries × ~24 bytes = ~100 KB |
| `mac_tenant_map` HASH | 1,024 entries × 12 bytes = ~12 KB |
| `ShardedMetadataMap` (Go) | ~200 bytes per VM. 1,000 VMs → ~200 KB |
| `GlobalState` (Go) | ~60 bytes per flow entry. ~10,000 flows → ~600 KB |
| `UnresolvedBuffer` cap | 10,000 × ~80 bytes = ~800 KB max |

**Total agent footprint (RSS)**: ~150–200 MB on a 32-core, 50-VM node. Most of it is the PERCPU map preallocation; well within budget for a daemon.

### CPU overhead

Per-packet kernel cost is dominated by:
1. Header pull (`bpf_skb_pull_data` for ~34 bytes) — negligible
2. Two map lookups (`mac_tenant_map` + maybe `subnet_zone_trie`) — ~50 ns each on cached
3. One PERCPU update — ~30 ns

Total: ~150 ns / packet. At 10 Gbps × 64-byte packets = ~14.88 Mpps × 150 ns = **~2.2 ms of CPU per second per core in worst case**, or ~0.22% per core. Empirically: <1% delta in iperf3 throughput vs. baseline.

### Throughput characteristics

- Userspace `BatchLookup` polls every 10s. Single syscall, full snapshot.
- A 10k-flow map snapshot completes in ~5 ms on commodity hardware.
- Map iteration during GC: same cost; runs once per 60s.
- WAL flush: fsync of a ~600 KB JSON file, ~5–10 ms; runs once per 60s.

### Scalability ceiling

- Map cap (65,536 flows) sets the upper bound on distinct (MAC-pair, direction, zone) combinations per node.
- On a 50-VM node: typical fill is ~850 entries (1.3% of cap).
- On a 500-VM node (extreme): proportional ~8,500 entries (~13%).
- Pressure-relief GC kicks in at >80% fill if topology unexpectedly explodes.

---

## 12. Demo Workflow

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

## 13. Open Issues

| # | Issue | Severity | Notes |
|---|---|---|---|
| 1 | `UnresolvedBuffer` size cap not enforced in code | High | During Kafka outage, buffer can OOM. Add 10k-entry LRU |
| 2 | `GlobalState` iterated in `Collect()` without read lock | High | Prometheus handler races scraper writes → fatal panic. Add RLock around the entire loop |
| 3 | `*TenantMeta` mutation rule unenforced | High | Every update path must replace pointer, not mutate. Add lint check |
| 4 | Boot sequence ordering not gated in code | High | Document per [§9](#9-boot-sequence-order-matters) and add explicit sync points between goroutines |
| 5 | IPv6 zone resolution out of scope | Medium | All v6 currently hits ZONE_MISS. Extend trie key to 32 bytes |
| 6 | u64 wraparound guard in delta math | Low | Add `if (lastRaw - current) > u64Max/2 → wrap` |
| 7 | Octavia attribution kernel-side not yet implemented | Medium | Demo uses Go-side fallback; production needs `bpf_skb_ct_lookup` inline |
| 8 | DVR per-host MAC enumeration | Medium | Cold-start needs to handle DVR specifically |

---

## Appendix A — Design Decisions Table

| Decision | Chosen | Rejected | Why |
|---|---|---|---|
| eBPF hook | TC clsact (ingress + egress) | XDP | XDP is ingress-only on tap; no `bpf_skb_ct_lookup` for Octavia. [C.1](#c1-xdp-hook-instead-of-tc) |
| Octavia attribution | `bpf_skb_ct_lookup` in TC | Userspace conntrack parsing | TC reads conntrack inline, no userspace round-trip |
| Crash resilience | Read, don't clear (pinned map persists) | Clear after each scrape | Zero data loss on agent restart |
| Concurrency | PERCPU_HASH | Global hash + atomics | Atomic contention at 10 Gbps × 32 cores becomes the bottleneck. [B.4](#b4-percpu_hash) |
| Prometheus storage | Custom collector + WAL | `CounterVec` | `CounterVec` resets on crash → negative `rate()` → billing breaks. [C.7](#c7-prometheus-countervec) |
| MAC→tenant map | 64-shard RWMutex | `sync.Map` | sync.Map is read-optimized; we write every 10s from Kafka. [C.6](#c6-syncmap-for-metadata-cache) |
| VM/subnet deletion | Lingering Ghost (60s TTL) | Immediate eviction | Dying FIN/RST packets must still attribute correctly |
| Interface lifecycle | Netlink Watcher + Registry | Static tap list | OpenStack creates/destroys taps dynamically |
| Crash-leftover filters | Zombie Hunter on startup | Ignore / let attach fail | Stacking duplicates on restart silently double-counts |
| Flow-key cardinality | MAC-pair + dst_zone | 5-tuple `(src_ip, dst_ip, ports)` | MAC-pair scales with topology; 5-tuple explodes labels. [C.4](#c4-5-tuple-flow-key-instead-of-mac--zone) |
| Cross-subnet classification | dst_zone u8 + LPM trie | dst_ip in key | dst_ip explodes cardinality and breaks IPv6; LPM scales with topology |
| Map capacity relief | Pressure-relief GC + fill metric | LRU_HASH | LRU evicts silently → unrecoverable byte loss. [C.5](#c5-lru_hash-for-map-eviction) |
| OpenStack metadata source | Neutron v2.0 API | Direct MySQL | API is versioned/stable; DB schema migrates per release. [C.3](#c3-direct-mysql-queries-instead-of-neutron-api) |
| Static route resolution | Nexthop trace through Neutron port topology | CIDR-only lookup | CIDR alone is ambiguous when tenants reuse the same prefix. [C.9](#c9-direct-cidr-lookup-without-nexthop-trace) |
| VM-appliance nexthop | `zone_for(appliance_tenant, source_tenant)` | EXTERNAL fallback | Appliance tenant is Neutron-visible; better attribution than blanket EXTERNAL. Double-billing caveat documented in §8 Tier 4 #21 and Scenario L. |
| Per-packet zone resolution | Hybrid: MAC-first, LPM fallback | Always-LPM | Direct L2 traffic gets exact tenant comparison. [C.8](#c8-always-lpm-no-mac-first-hybrid) |
| Telemetry approach | eBPF TC at tap (exact) | sFlow at OVS / NIC (sampled) | Sampling is unfit for billing. [C.2](#c2-sampling-at-ovs--vxlan-envelope-extraction) |

---

## Appendix B — Concept Primer

The main text links here when terms first appear.

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

**Why we need it for Octavia.** When a packet flowing `Amphora → backend VM` hits the backend's tap, we see the reply tuple (post-NAT). The original client IP is in the original tuple. Without `bpf_skb_ct_lookup`, we'd misclassify the bytes as Amphora-to-backend instead of client-to-LB.

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

**DVR (Distributed Virtual Routing)** — a Neutron mode where each compute node runs its own router instance. Without DVR, all routing happens centrally on a network node. With DVR, intra-tenant E-W routing happens locally. Each compute node's DVR router has its own MAC, even for the same logical Neutron router.

**Address scope** — Neutron's mechanism for allowing cross-tenant routing while preventing CIDR overlap. Subnets in the same address scope must have non-overlapping CIDRs.

External: [Neutron API reference](https://docs.openstack.org/api-ref/network/v2/).

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

The naive view: bytes are charged to whoever owns the Amphora (admin). The correct view: bytes are charged to the LB's owning tenant (because they configured the LB and benefit from the traffic). Conntrack lets us recover the original tuple to make this attribution correct. See [§6](#6-octavia-lb-attribution).

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

Each section documents the motivation for an alternative approach, the analysis that led to its rejection, and the deployment contexts where it would be appropriate.

### C.1 XDP hook (instead of TC)

**Motivation.** XDP runs even earlier than TC — at the driver level, before `skb` allocation. It's the fastest possible eBPF hook point, and Cilium and Katran use it for high-throughput packet processing.

**Why we rejected it.**

1. **XDP is ingress-only on tap interfaces.** Empirically confirmed on 2026-04-30: XDP attached to a tap captures 0% of the packets the VM *receives*. We need both directions for billing.
2. **No `bpf_skb_ct_lookup` for XDP.** XDP runs before `nf_conntrack` has matched the packet. Octavia attribution becomes impossible without conntrack.
3. **Throughput advantage is moot for us.** TC processes ~14 Mpps on a single core with our program. The bottleneck on a real OpenStack node is the OVS forwarding pipeline, not our 150ns of telemetry overhead.

**Applicable use cases.** L4 load balancers, DDoS mitigation, raw-packet analytics — contexts that do not require bidirectional coverage or conntrack access.

### C.2 Sampling at OVS / VXLAN envelope extraction

**Motivation.** sFlow on OVS samples 1-in-N packets, captures the full Ethernet frame including VXLAN headers, and ships samples to a collector. The collector parses VNI to identify the tenant network — solving the "same CIDR across tenants" problem cleanly.

**Why we rejected it as the primary mechanism.**

1. **Sampling is wrong for billing.** Default 1:1000 sampling means short-lived flows can be missed entirely; even on long flows, the byte count has statistical error proportional to `1/sqrt(packets_in_flow)`. For long-tail traffic patterns, this is unacceptable. Billing demands every-packet accuracy.
2. **Loses per-VM precision when sampled at the uplink.** sFlow on the physical NIC misses same-host VM-to-VM traffic entirely (it never leaves OVS). sFlow on br-int fixes this but loses the VNI advantage (no VXLAN encap on local traffic).
3. **MAC uniqueness already solves CIDR overlap.** Neutron assigns globally unique MACs across all tenants. The `mac_tenant_map` resolves the same ambiguity that VNI would resolve in sFlow without requiring the outer header.

**Applicable use cases.** Network-wide visibility, anomaly detection, traffic-matrix estimation, capacity planning. sFlow is appropriate as a secondary observability layer alongside this system; it is not appropriate as a primary billing source.

### C.3 Direct MySQL queries (instead of Neutron API)

**Motivation.** Direct DB queries are fast (no HTTP overhead), can do JOINs that would otherwise require many API calls, and let us see internal Neutron tables.

**Why we rejected it.**

1. **Schema migrates with every OpenStack release.** Table names, column names, and relationships change. A query that works on Wallaby silently breaks on Yoga — no warning, no error at startup, just wrong data in the trie.
2. **Security.** The agent would need MySQL credentials with read access to Neutron's full database. That's a much bigger blast radius than read-only API access scoped by Keystone token.
3. **Bypasses Neutron's business logic.** Some fields are computed on read by Neutron; querying the DB directly gives raw state without that computation. Risk of subtle correctness bugs.
4. **API performance is sufficient.** Cold-start makes 5–10 paginated API calls (with `fields=...` to trim payloads). All joins happen in Go memory after caching. Total startup overhead is under 1 second.

**Applicable use cases.** Scenarios requiring data the API does not expose, such as internal IPAM allocation pool state or raw subnet pool tracking. For the data required here — MACs, CIDRs, network ownership, router routes — the API is sufficient.

### C.4 5-tuple flow key (instead of MAC + zone)

**Motivation.** `(src_ip, dst_ip, src_port, dst_port, proto)` is the conventional flow key. It's what NetFlow uses, what conntrack uses, what every flow-analytics tool expects.

**Why we rejected it.**

1. **Cardinality explosion.** Each unique connection (browser tab, RPC call, BGP session, ARP probe) creates a new map entry. A 50-VM node easily reaches >100k entries. Our 65,536 cap is exhausted; pressure-relief GC churns constantly.
2. **Prometheus label explosion.** If we exported by 5-tuple, we'd ship millions of label combinations to Prometheus — the cardinality bomb that kills observability platforms.
3. **MAC-pair scales with topology.** 50-VM node ≈ 850 entries. 500-VM node ≈ 8,500 entries. Topology grows much slower than connection count.
4. **L4 ports add no billing signal.** We charge by tenant and zone. We don't bill TCP ports.

**Applicable use cases.** Flow-based intrusion detection, per-connection latency analytics, session reconstruction — workloads where per-connection granularity is required.

### C.5 LRU_HASH for map eviction

**Motivation.** `BPF_MAP_TYPE_PERCPU_LRU_HASH` evicts the least-recently-used entry automatically when the map fills. No userspace GC needed, no map-full errors.

**Why we rejected it.**

1. **Silent data loss.** The kernel evicts entries between scrapes. If a long-running flow's entry is evicted at second 7 of a 10-second scrape window, the bytes accumulated up to that point are gone. We never see them.
2. **No way to flush before eviction.** The LRU eviction is a one-step kernel operation. There's no "tell me when you're about to evict" hook.

**Our alternative.** Standard `PERCPU_HASH` (no auto-eviction) plus userspace pressure-relief GC at >80% fill. The Go agent reads the entry, adds its bytes to GlobalState, *then* deletes it. No bytes lost.

**Applicable use cases.** Approximate analytics where bounded data loss is acceptable — flow sampling, hot-key detection, top-N tracking.

### C.6 sync.Map for metadata cache

**Motivation.** `sync.Map` is Go's lock-free concurrent map. Avoids RWMutex contention.

**Why we rejected it.**

1. **`sync.Map` is read-optimized.** It's specifically tuned for "read-mostly, rare writes" workloads. We *write* every 10 seconds from Kafka events — that's the dirty path. Under continuous mixed read/write, `sync.Map` performs *worse* than RWMutex.
2. **64-shard RWMutex is simple and fast.** Sharding by `mac_uint64 & 63` distributes contention 64-way. Each shard's RWMutex is uncontended for ~99% of operations.
3. **Predictable performance.** We can reason about lock contention. `sync.Map`'s internal `dirty` / `read` maps make latency harder to predict.

### C.7 Prometheus CounterVec

**Motivation.** `CounterVec` is the idiomatic Prometheus type for cumulative counters with labels. The Prometheus Go client library handles all the bookkeeping.

**Why we rejected it.**

1. **Resets to zero on process restart.** When the agent restarts (planned or crash), the new process starts every `CounterVec` at 0. Prometheus sees the value drop. Its `rate()` function emits a *negative* spike.
2. **Negative `rate()` corrupts billing pipelines.** Anything downstream that integrates rate over time produces wrong totals. Some pipelines silently treat negative values as 0, others as the absolute value, others propagate `NaN`.
3. **No way to "preload" CounterVec from disk.** The library has no public API for setting an initial value above 0.

**Our alternative.** Implement `prometheus.Collector` directly. On `Collect()`, walk our `GlobalState` (which we restore from WAL on boot) and emit the cumulative values. Restart preserves the cumulative — `rate()` stays positive.

### C.8 Always-LPM (no MAC-first hybrid)

**Motivation.** Use only the LPM trie for zone classification — drop the MAC-first comparison from the per-packet path. Simpler kernel code.

**Why we rejected it.**

1. **CIDR ambiguity for direct L2 traffic.** When VM-A talks directly to VM-B in the same subnet, the trie answer depends on subnet entries being correctly populated. If Go's cold-start has a bug or stale data, classification is wrong. MAC comparison is *exact* and trie-independent.
2. **Reduces operational risk surface.** With MAC-first, a misconfigured trie only affects routed traffic. Direct VM-to-VM comms continue working correctly. Failure modes are more localized.
3. **Tiny additional cost.** One extra hash lookup per packet (~50 ns) — well within our overhead budget.

**Applicable use cases.** Test or demo builds where the routed-vs-direct L2 distinction is not required.

### C.9 Direct CIDR lookup (without nexthop trace)

**Motivation.** When resolving a static route's destination CIDR, just query Neutron for "any subnet with this CIDR" and use the first result.

**Why we rejected it.**

1. **Multiple tenants can have the same CIDR.** Tenant A's `10.0.1.0/24`, Tenant B's `10.0.1.0/24`, and Tenant C's `10.0.1.0/24` are all separate subnets in different network namespaces. Picking "the first match" is arbitrary and wrong.
2. **The static route's nexthop is the disambiguator.** The nexthop is a specific port on a specific subnet attached to a specific router. That router has a known set of attached networks. Scoping the destination CIDR search to those networks gives a deterministic, unambiguous answer.

The nexthop-trace algorithm is detailed in [§5.3](#53-the-static-route-resolver-the-heart-of-step-5).

### C.10 Userspace packet parsing

**Motivation.** Use AF_PACKET / `libpcap` / `tcpdump`-style raw socket capture. Parse packets in Go. Avoid eBPF entirely.

**Why we rejected it.**

1. **CPU at line rate.** Userspace packet capture at 10 Gbps × multiple VMs per host saturates CPU for parsing. eBPF runs the same parsing in the kernel at near-zero cost.
2. **Per-packet syscall.** Even with PACKET_MMAP, you're context-switching once per N packets. eBPF stays in-kernel.
3. **Parsing tax for already-classified traffic.** Most packets are TCP/UDP we're not interested in beyond byte counts. eBPF can short-circuit before doing expensive parsing.

**Empirical benchmarks.** Standard kernel BPF program: ~150 ns/packet. AF_PACKET + Go parser: ~3,000–5,000 ns/packet. 20–30× difference.

### C.11 In-VM agent for OS-level routes

**Motivation.** Install a small agent inside each VM. Have it report routing-table changes to a central service. Use that to populate the trie with OS-level static routes Neutron doesn't know about.

**Why we rejected it.**

1. **Defeats the eBPF design's whole premise.** The point of TC at the tap is that it works regardless of what the VM is running. An in-VM agent makes us depend on guest cooperation.
2. **Tenants run arbitrary OSes.** Windows, BSD, custom Linux distros, containers-as-VMs. Maintaining agents for all is operational pain.
3. **Tenants have admin on their VMs.** A privileged user can disable the agent and reroute traffic invisibly.
4. **Billing-safe fallback exists.** OS-level routes that Neutron doesn't know about fall to `ZONE_EXTERNAL` (charged at the higher external rate). The tenant has incentive to use Neutron-managed routing to get internal rates. This aligns incentives.

### C.12 Store IP in the flow key

**Motivation.** Keep `dst_ip` (and maybe `src_ip`) in the BPF map key so we don't need a separate trie lookup; classification happens at scrape time in Go.

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
| **DVR** | Distributed Virtual Routing — Neutron mode with per-host routers. |
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
| **ZONE** | Our four-way classification: SAME / OTHER / EXTERNAL / INFRA / MISS. |

---

*Last updated: 2026-05-02.*
