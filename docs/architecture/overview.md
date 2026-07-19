# Overview — Problem, Goals & System Architecture

> Per-tenant, line-rate network telemetry for OpenStack via eBPF TC.
> This chapter frames the problem and shows the whole machine; the rest of the
> [architecture series](./README.md) zooms into each part.

## What we're solving

CubeCOS is a multi-tenant OpenStack platform. Existing tools fail for billing-grade observability:

- **OVS counters / NetFlow / iptables** can't reliably distinguish North-South from East-West traffic.
- **Octavia load balancers** lose tenant context through NAT — bytes get attributed to the admin project, not the real end-user tenant. (See the [Octavia primer](./primer.md#octavia-and-amphora-vms).)
- **Userspace packet parsing** burns CPU at 10 Gbps line rate.

## Goals

| # | Requirement |
|---|---|
| 1 | Classify all traffic into four categories: **N-S out** (VM → internet), **N-S in** (internet → VM), **Intra-Tenant E-W**, **Inter-Tenant E-W** |
| 2 | Re-attribute Octavia LB traffic to the real end-user tenant |
| 3 | Run entirely in the kernel via [eBPF TC](./primer.md#ebpf-in-60-seconds) at line-rate (10 Gbps+) with near-zero CPU overhead |
| 4 | Maintain real-time OpenStack metadata via Neutron API cold-start + Kafka events |
| 5 | Expose Prometheus cumulative counters at `/metrics` — billing semantics defined in [billing.md](./billing.md) |
| 6 | Survive Go agent crashes and hard reboots with bounded data loss (≤60s — the WAL flush window; see [boot-and-recovery.md](./boot-and-recovery.md)) |

## Target environment

- Linux 5.10+ with [BTF](./primer.md#btf-bpf-type-format) and `bpf_skb_ct_lookup` (5.10 is the floor; verified empirically on kernels 6.10 and 6.12), x86_64
- Deployed as a daemon per OpenStack compute node
- Standard [OVS kernel datapath](./primer.md#openstack-networking-primer) with **Neutron OVN ML2 plugin** (verified empirically on OpenStack Yoga). DPDK/SR-IOV are out of scope — see [edge-cases.md](./edge-cases.md). Traditional Neutron (OVS-agent + L3-agent + qrouter namespaces) is deferred — see [contracts.md](./contracts.md#deferred-work).
- Dev: Apple Silicon Mac via Docker cross-compile

## Four layers

```
┌─────────────────────────────────────────────────────────────────────┐
│ Layer 4 — Prometheus + WAL                                          │
│   Custom Collector, GlobalState, /var/lib/lachesis/...json snapshot │
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

## Data flow

- **Packet path:** VM → tap → TC ingress/egress hook → PERCPU_HASH map. ([packet-classification.md](./packet-classification.md))
- **Read path:** Go agent `BatchLookup` every 10s (the default scrape interval; hot-tunable) → delta math → GlobalState → Prometheus. ([data-structures.md](./data-structures.md), [metrics.md](./metrics.md))
- **Metadata path:** Neutron API cold-start + Kafka-kicked reconcile → builds the trie + MAC map → kernel uses these to classify each packet. ([trie-construction.md](./trie-construction.md))

## Why TC clsact, not XDP

| Concern | TC clsact | XDP |
|---|---|---|
| Coverage on tap interfaces | Both ingress + egress | **Ingress only** (empirically confirmed: 0% TX coverage on tap) |
| Conntrack helper | [`bpf_skb_ct_lookup`](./primer.md#bpf_skb_ct_lookup-and-conntrack) available | Not available — required for Octavia attribution |
| Verdict | **Chosen** | Rejected — see [ADR 0001](../adr/0001-tc-clsact-over-xdp.md) |

## Why per-VM tap, not OVS bridge or physical NIC

| Concern | VM tap (chosen) | OVS br-int / Physical NIC |
|---|---|---|
| Per-VM attribution | Exact (each tap = one VM) | Requires inner-header parsing |
| Same-host E-W traffic | Captured (each VM has its own tap) | Misses (stays inside OVS, never hits NIC) |
| [Geneve/VXLAN](./primer.md#openstack-networking-primer) visibility | None (pre-encap) | Yes (post-encap) |
| Required for billing? | Yes | Overlay headers are not needed — MAC is unique enough |

Detailed reasoning in [ADR 0002](../adr/0002-per-tap-ebpf-over-ovs-sflow-sampling.md).

> **Implementers:** [contracts.md](./contracts.md) lists seven contracts the build must guarantee for correctness. Read those first — they cover invariants that are easy to miss (RLock around `Collect()`, kernel/userspace lifecycle ordering, `*TenantMeta` pointer-replace semantics, boot-order sync points, u64 wraparound, UnresolvedBuffer cap, monotone cumulative counters). Violating any of them produces silent billing errors that don't crash the agent.

---

Next: [data-structures.md](./data-structures.md) →
