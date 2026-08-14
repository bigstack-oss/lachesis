# Per-Packet Classification Algorithm

This is the kernel hot path: `handle_packet` in `bpf/telemetry.c`, inlined into
both TC programs (`tc_telemetry_in` for the ingress hook, `tc_telemetry_out` for
egress) and run on every packet crossing a VM tap. It produces exactly one
[`flow_key`](./data-structures.md#kernel-side-bpf-maps) and bumps its counters.

## The zone vocabulary

Every packet lands in exactly one zone, baked into the flow key:

| Code | Zone | Meaning | Billing posture |
|---|---|---|---|
| 0 | `EXTERNAL` | remote endpoint is outside the cloud (or reached via an external network) | per-direction internet rates |
| 1 | `SAME_TENANT` | remote endpoint belongs to the same tenant | $0 (recommended) |
| 2 | `OTHER_TENANT` | remote endpoint belongs to a different tenant | per-side internal rate |
| 3 | `INFRA` | platform plumbing: DHCP/metadata, router interfaces, LB segment 2 | $0 today |
| 4 | `MISS` | unclassifiable — unknown VM MAC, no trie entry, IPv6 unicast | never billed; alert-only |
| 5 | `SHARED` | remote endpoint is on a shared Neutron network (L3 path can't resolve ownership) | own line item |
| 6 | `MULTICAST` | destination MAC has the IEEE 802 group (I/G) bit set — platform-L2 chatter | never billed; not alerted |

Postures are the product contract, defined in [billing.md](./billing.md); the
codes mirror `enum zone_code` in `bpf/telemetry.c` and `internal/bpf`.

## Pseudocode (kernel-side, runs on every packet)

```
1. Pull Ethernet + IPv4 headers into the linear region
   (bpf_skb_pull_data), re-read skb->data / data_end.

2. Parse Ethernet.
   If proto not in {IPv4, IPv6}: count STAT_SKIPPED_ETHERTYPE and
   return TC_ACT_OK without counting bytes (ARP/LLDP noise normally;
   a sustained rise flags a trunk/VLAN blind spot — see edge-cases.md).

3. direction = 0  if attached to ingress hook (VM is sending)
             = 1  if attached to egress  hook (VM is receiving)

4. Multicast gate — checked FIRST, on the destination MAC:
     if dst_mac[0] & 0x01:            # IEEE 802 I/G bit
        dst_zone = ZONE_MULTICAST     # never resolves to a tenant MAC;
        goto step 8                   # covers rx group traffic AND
                                      # VM-originated multicast tx,
                                      # both IPv4 and IPv6

5. IPv6 unicast: dst_zone = ZONE_MISS; goto step 8.
   (v6 zone resolution is deferred — contracts.md, deferred item 1.)

6. Directional swap — always reason about "the VM" and "the remote
   endpoint", regardless of which hook fired:

     if direction == 0:                  # VM sending
        vm_mac    = eth->h_source
        peer_mac  = eth->h_dest
        remote_ip = iph->daddr
     else:                               # VM receiving
        vm_mac    = eth->h_dest
        peer_mac  = eth->h_source
        remote_ip = iph->saddr

7. Zone lookup (lookup_zone):
     tenant_id = mac_tenant_map[vm_mac]
     if not found: dst_zone = ZONE_MISS  (unrecognized VM — alertable)
     else:
        peer_tid = mac_tenant_map[peer_mac]
        if peer_tid is set:
           # Direct L2 between two known endpoints — exact comparison.
           # No routing involved; trie is bypassed.
           dst_zone = SAME_TENANT  if peer_tid == tenant_id
                      OTHER_TENANT otherwise
        else:
           # peer_mac is a router or external MAC — fall back to LPM.
           dst_zone = subnet_zone_trie[(tenant_id, remote_ip)]
                      or subnet_zone_trie[(0, remote_ip)]   # global-row
                                                            # sentinel
                      or ZONE_MISS                          # no catchall
                                                            # (boot bug)

8. Build flow_key { src_mac, dst_mac, eth_proto, direction, dst_zone }.

9. Look up telemetry_map[flow_key]:
     hit:   val->bytes += skb->len          # PERCPU slot, no atomics
            val->packets += 1
            val->last_seen_ns = bpf_ktime_get_ns()
     miss:  insert {skb->len, 1, ktime} with BPF_ANY;
            on -E2BIG (map full) count STAT_UPDATE_FAILURE —
            billing-path loss is never silent.
```

The two-stage trie lookup in step 7 is the global-row dedup: catchall / INFRA /
SHARED rows are stored once under sentinel `tenant_id=0` instead of once per
tenant ([data-structures.md](./data-structures.md#kernel-side-bpf-maps)). In
steady state the sentinel catchall at `0.0.0.0/0` guarantees a hit; `ZONE_MISS`
from step 7's last line means the trie was never populated — a boot-order
violation ([boot-and-recovery.md](./boot-and-recovery.md)).

## The directional swap, explained

Without the swap, the kernel always reads `h_source` and `daddr`. That's correct for the ingress hook (VM sending: `h_source` is the VM, `daddr` is the remote). But on the egress hook (VM receiving), `h_source` is the *router's* MAC and `daddr` is the *VM's own IP*.

That second case has two failures stacked:

1. **Wrong MAC** — `mac_tenant_map[router_mac]` misses → `ZONE_MISS`. Visible in metrics.
2. **Wrong IP** — even if you used the right MAC, looking up `(tenant, vm_own_ip)` matches the VM's own subnet → classifies a **10 GB Google download as same-tenant intra-traffic**. Silently misclassified, no signal.

The directional swap eliminates both. The mental model: *the kernel always asks "relative to this VM's tenant, which zone is the remote endpoint in?"* — and the values of "VM" and "remote" depend on the direction.

The kernel enum keeps hook-frame names (`TC_DIR_INGRESS` = VM sending,
`TC_DIR_EGRESS` = VM receiving) because this swap depends on them; the metric
labels translate to the NIC-conventional `tx`/`rx` — see
[metrics.md](./metrics.md) for why the hook words must never leak into labels.

## The hybrid lookup, explained

For direct L2 traffic (VM-A → VM-B, same broadcast domain, no router), the destination MAC IS the destination VM's MAC. We can look it up in `mac_tenant_map` and get an *exact* tenant comparison. No trie involved. No CIDR ambiguity. No misconfiguration risk.

For routed traffic (anything via a router or external), `peer_mac` is the router's MAC, which is not in `mac_tenant_map`. We fall back to the LPM trie, which uses the L3 destination IP.

This means the trie only needs to handle routed traffic. Direct L2 traffic is exact-classified without it. We considered the always-LPM approach and rejected it — see [ADR 0008](../adr/0008-hybrid-mac-first-over-always-lpm.md).

## Decision tree

```
                    packet at VM tap
                           │
                 ┌─────────┴─────────┐
              IP packet?         non-IP (ARP/LLDP)
                 │                   │
                yes              pass-through
                 │            (uncounted; skip stat)
                 ▼
        dst MAC group bit set?
                 │
         ┌───────┴───────┐
        yes              no
         │                │
         ▼                ▼
     MULTICAST      IPv6 unicast? ──yes──▶ MISS
   (never billed)         │
                          no
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
                           │          (tenant_id, remote_ip),
                 ┌─────────┤          then (0, remote_ip)
                eq        neq              │
                 │         │               ▼
                 ▼         ▼            one of:
               SAME      OTHER            SAME_TENANT
                                          OTHER_TENANT
                                          INFRA / SHARED
                                          EXTERNAL
                                          MISS (no catchall)
```

**Octavia.** One branch sits inside the direct-L2 arm, ahead of the tenant
comparison: when either end's `mac_tenant_map` value carries the Amphora marker
(the value's top bit), that end's own IP is tested against the `amphora_base_ip`
set. A hit is Octavia Segment 2 — load-balancer plumbing — and returns INFRA. A
miss is Segment 1 and falls through to the tenant comparison unchanged, so an
internal client's load-balancer traffic keeps billing `same_tenant` /
`other_tenant`. An external client's Segment 1 never reaches the branch: its peer
MAC is a router interface, so it takes the routed fallback and lands EXTERNAL.

Attribution is untouched by this — it follows the VM-side MAC as always. What
makes an Amphora's bytes bill the load balancer's owner is a userspace
substitution in the port's metadata, not a hot-path branch. See
[octavia.md](./octavia.md).

---

Next: [trie-construction.md](./trie-construction.md) →
