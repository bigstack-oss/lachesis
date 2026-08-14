# Scenario Walkthroughs

For each scenario: where the packet appears, what the classification produces,
whether it's counted correctly on each side. Where a live regression exists in
`cmd/scenariotest` it is named — the [coverage table](#live-regression-coverage)
at the end maps all of them.

## Scenario A — Same tenant, same subnet (direct L2)

```
VM-A (T1, 10.0.1.5, mac=AA) ──→ VM-B (T1, 10.0.1.6, mac=BB)
```

| Hook | direction | vm_mac | peer_mac | Lookup | dst_zone |
|---|---|---|---|---|---|
| VM-A tap, ingress | 0 | AA → T1 | BB → T1 | tenants match (hybrid) | SAME ✓ |
| VM-B tap, egress | 1 | BB → T1 | AA → T1 | tenants match (hybrid) | SAME ✓ |

Trie not touched. Pure MAC-based classification. Live regression: `twovms-same-tenant`.

## Scenario B — Same tenant, different subnets via tenant router

```
VM-A (T1, subnet1) ──→ router-T1 ──→ VM-B (T1, subnet2)
```

| Hook | vm_mac | peer_mac | peer in map? | Path | dst_zone |
|---|---|---|---|---|---|
| VM-A tap, ingress | AA→T1 | router_iface_mac (subnet1) | yes (router interfaces are admitted, keyed by the router's tenant) | hybrid: tenants match | SAME ✓ |
| VM-B tap, egress | BB→T1 | router_iface_mac (subnet2) | yes | hybrid: tenants match | SAME ✓ |

Router interface MACs are in `mac_tenant_map`, so this stays exact; the LPM entries for subnet1/subnet2 are the fallback if a router MAC is ever absent.

## Scenario C — Cross-tenant via shared network or address scope

```
VM-A (T1) ──→ shared bus ──→ router-T2 ──→ VM-X (T2)
```

| Hook | vm_mac | peer_mac | Path | dst_zone |
|---|---|---|---|---|
| VM-A tap, ingress | AA→T1 | router_mac (T2's router) | peer hits `mac_tenant_map` keyed T2 → tenants differ | OTHER ✓ |
| VM-X tap, egress | XX→T2 | router_mac (T2's router) | peer hits, same tenant as VM-X... falls to router's tenant comparison | see note |

The exact path depends on whose router carries the hop: a peer router MAC in
`mac_tenant_map` resolves by tenant comparison; a routed hop whose peer MAC
misses falls back to the LPM trie, which needs the cold-start to have
populated cross-tenant entries via extraroute resolution (per-tenant step-5
rows like `(T1, X's subnet) → OTHER`). Both endings produce OTHER for a
cross-tenant transfer. Live regressions: `cross-tenant-shared`,
`cross-tenant-routed`.

## Scenario D — External egress (VM → internet)

```
VM-A (T1, 10.0.1.5) ──→ tenant router ──→ NAT GW ──→ 8.8.8.8
```

| Hook | direction | vm_mac | remote_ip | LPM | dst_zone |
|---|---|---|---|---|---|
| VM-A tap, ingress | 0 | AA→T1 | 8.8.8.8 | sentinel catchall `(0, 0.0.0.0/0)` | EXTERNAL ✓ |

Live regressions: `vm-to-internet`; `multi-external-path` additionally asserts *which* external network each flow bills under ([billing.md](./billing.md)).

## Scenario E — External ingress (internet → VM via floating IP)

```
client 1.2.3.4 ──→ floating IP 203.0.113.5 ──[DNAT]──→ VM-A
```

DNAT happens before the tap. At VM-A's tap: `src_ip=1.2.3.4, dst_ip=10.0.1.5` (the internal IP).

| Hook | direction | vm_mac | remote_ip | LPM | dst_zone |
|---|---|---|---|---|---|
| VM-A tap, egress | 1 | AA (h_dest) | 1.2.3.4 (saddr) | catchall | EXTERNAL ✓ |

## Scenario F — Octavia LB (client → Amphora → backend VM)

```
client 1.2.3.4 ──→ floating IP ──[DNAT]──→ Amphora (admin) ──[HAProxy NEW conn]──→ VM-B (T1 backend)
                                            ↑                                       ↑
                                            two TCP connections (Seg1, Seg2);       both at the wire level
                                            HAProxy terminates Seg1 and             — NOT one transparent flow
                                            originates Seg2
```

The Amphora's ports are re-attributed at cold-start from the Octavia service
project to T1, the load balancer's owner. Which segment a packet belongs to is
decided by **the Amphora's own address on the wire**: the VIP means Segment 1,
the port's base address means Segment 2.

**Segment 1: client ↔ Amphora.** At the Amphora's tap (egress, Amphora receiving):

| direction | vm_mac | peer_mac | Amphora-side IP | dst_zone | Attribution |
|---|---|---|---|---|---|
| 1 | Amphora_mac (h_dest) | FIP-gateway (h_source), external client | VIP → not Segment 2 | EXTERNAL (peer misses `mac_tenant_map`, trie catchall) | **LB owner (T1)** — NOT the service project |
| 1 | Amphora_mac (h_dest) | VM-C_mac (h_source), internal client in T2 | VIP → not Segment 2 | OTHER_TENANT | **LB owner (T1)** |

**Segment 2: Amphora ↔ backend.** At VM-B's tap (egress, VM-B receiving):

| direction | vm_mac | peer_mac | Amphora-side IP | dst_zone | Attribution |
|---|---|---|---|---|---|
| 1 | VM-B_mac (h_dest) | Amphora_mac (h_source) | base IP → Segment 2 | **INFRA** | VM-B's own project |

Segment 2 also crosses the Amphora's tap in the other direction, where the
Amphora is the VM side; it zones INFRA there too, so the transfer's `tx` and `rx`
series share a zone ([billing.md](./billing.md) emission invariant).

**Critical:** an internal client's Segment 1 must NOT collapse into INFRA. The
Amphora's MAC is on both segments, so only the address test separates them — and
a cross-tenant client's request is billable per side. See
[octavia.md](./octavia.md); verified on-wire.

Total billed to T1 = Segment 1 at the Amphora's taps. Segment 2 is `infra`, $0
today, at both taps.

## Scenario G — Static route, Neutron-managed

```
T1's router has extraroute: dest=192.168.50.0/24 via 10.0.1.100
```

Resolution at cold-start: nexthop 10.0.1.100 → port → device → reachable subnets → owner of 192.168.50.0/24. Trie entry pre-baked. Per-packet: just an LPM lookup, looks identical to a directly-attached subnet.

## Scenario H — Static route, OS-level (inside the VM)

```
Operator runs inside the VM:
  ip route add 172.16.0.0/12 via 10.0.1.100
```

Neutron has no record. Trie has no entry. Packet falls to the catchall → `ZONE_EXTERNAL`.

**Verdict:** Unsolvable without an in-VM agent (which defeats the eBPF design — see [ADR 0011](../adr/0011-no-in-vm-agent.md)). The fallback is the safest billing failure mode — tenant gets charged at the external rate. Documented exception.

## Scenario I — Same-host, same-tenant (VM-A and VM-B on same hypervisor)

OVS forwards the packet within br-int, no tunnel. Each tap sees the packet.

| Hook | Result | dst_zone |
|---|---|---|
| VM-A tap, ingress | counted | SAME ✓ |
| VM-B tap, egress | counted | SAME ✓ |

Both-sides counting is intentional: the transfer emits exactly one `tx` series (VM-A's tap) and one `rx` series (VM-B's tap). The per-side charging postures ([billing.md](./billing.md)) make the pair safe by construction — `same_tenant` bills $0, so nothing is double-charged.

## Scenario J — Cross-host, same-tenant (Geneve tunneled)

```
VM-A on host1 ──→ OVS encap ──→ Geneve ──→ host2 OVS decap ──→ VM-B
```

| Hook | What it sees | dst_zone |
|---|---|---|
| VM-A tap on host1, ingress | plain Ethernet (pre-encap) | SAME ✓ |
| VM-B tap on host2, egress | plain Ethernet (post-decap) | SAME ✓ |

The overlay tunnel is invisible to TC at the tap layer, which is correct. (OVN ML2 tunnels with Geneve, not VXLAN; the distinction has zero behavioral impact here — we observe pre-encap/post-decap frames either way.) Live regression: `cross-host-same-tenant` — proven on a 3-node staging cluster with the `tx` delta appearing only on the sender's host agent and the `rx` delta only on the receiver's.

## Scenario K — Multi-hop static route across multiple tenants

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

The hard work happens at **cold-start**, not per-packet. The trie entry `(T1, 10.99.0.0/16) → OTHER_TENANT` was pre-baked by the iterative resolver walking R1 → R2 → R3 → R4 → R5 and finding T5 at the end. See the [multi-hop worked example](./trie-construction.md#worked-example--multi-hop-chain) for the step-by-step trace.

The kernel does **one** LPM lookup per packet regardless of how many routers the trace traversed during boot. Multi-hop and single-hop routes are indistinguishable at runtime.

## Scenario L — Static route via VM appliance (compute:nova nexthop)

```
T1's router has extraroute: dest=172.16.99.0/24 via 10.0.1.50
Port at 10.0.1.50: device_owner=compute:nova, tenant_id=T1  (T1's own VM appliance)
```

At cold-start the resolver reaches 10.0.1.50, identifies `compute:nova`, and calls `zone_for(T1, T1, net-T1)` → SAME_TENANT. Trie entry baked: `(T1, 172.16.99.0/24) → SAME`.

At packet time (VM-A → 172.16.99.x):

| Hook | direction | vm_mac | remote_ip | LPM | dst_zone |
|---|---|---|---|---|---|
| VM-A tap, ingress | 0 | AA→T1 | 172.16.99.x | `(T1, 172.16.99.0/24)` → SAME | SAME |

**Double-billing.** When the VM appliance at 10.0.1.50 forwards the packet onward, that forwarded egress is independently counted at the appliance's own tap — attributed to T1 again. The same bytes are billed at both hops as separate flows (different MAC pairs). Billing aggregation must account for this when tenants deploy forwarding appliances. See [edge-cases.md](./edge-cases.md).

## Live-regression coverage

| Walkthrough | Live scenario (`cmd/scenariotest`) |
|---|---|
| A / I — same tenant, direct L2 | `twovms-same-tenant` |
| B — same tenant via router | — (backlog; catalog audit) |
| C — cross-tenant | `cross-tenant-shared`, `cross-tenant-routed` |
| D — external egress | `vm-to-internet`, `multi-external-path` |
| E — external ingress via FIP | exercised implicitly (drive sinks are reached via FIP); no dedicated assert |
| F — Octavia | `octavia-lb-attribution` |
| G/H/K/L — static routes | — (backlog; catalog audit) |
| J — cross-host same tenant | `cross-host-same-tenant` |
| infra zone (gateway/DHCP) | `vm-to-gateway` |
| lifecycle (ghost sweep, MAC reuse) | `mac-reuse` |
| live migration continuity | `live-migration-continuity` |

The catalog-audit backlog tracks scenarios for every remaining designed case;
the harness itself is documented in [development/testing.md](../development/testing.md).

---

Next: [edge-cases.md](./edge-cases.md) →
