# Edge Cases & Accuracy Ceiling

Everything the data plane cannot count, must handle explicitly, or counts under
the wrong label — tiered by severity, each row numbered (code comments reference
"Tier N row M"). The chapter ends with the honest accuracy ceiling those rows
add up to.

## Tier 1 — Hard limits

eBPF cannot count these at all.

| # | Edge case | Impact | Mitigation |
|---|---|---|---|
| 1 | [DPDK / userspace OVS datapath](./primer.md#dpdk--sr-iov--smart-nic) | TC hooks don't fire | Detect at boot; fall back to OVS sFlow for those VMs, or block at admission |
| 2 | [SR-IOV passthrough](./primer.md#dpdk--sr-iov--smart-nic) | No tap interface exists | Same as DPDK — needs NIC-level telemetry |
| 3 | Smart NIC offload (BlueField, ASAP²) | Datapath in HW, software taps bypassed | Same as SR-IOV |
| 3a | Neutron trunk ports / VLAN-aware VMs | 802.1Q-tagged frames (`0x8100`/`0x88A8`) on the trunk parent tap fail the ethertype gate in `bpf/telemetry.c` and pass uncounted — subport traffic is invisible (not even ZONE_MISS). The loss is asymmetric: host→VM may still count where OVS leaves the tag in skb metadata (VLAN tag offload) and the linear data starts at the inner IP header, while VM→host carries the tag in-band and never counts — corrupting in/out ratio sanity checks. Meanwhile the metadata layer admits `trunk:*` subport MACs into `mac_tenant_map` — entries the data plane can never hit | Cold-start warn-log + `lachesis_neutron_trunk_subports` gauge whenever the snapshot contains trunk subports; the kernel skipped-ethertype counter makes the in-band loss visible under live traffic (issue 39). Real support — a single 802.1Q parse — is deferred pending a billing decision on the flow-key shape ([deferred item 8](./contracts.md#deferred-work)) |

## Tier 2 — Explicit handling

| # | Edge case | Failure | Fix |
|---|---|---|---|
| 4 | Map full (>65k flows) | `bpf_map_update_elem` returns `-E2BIG`; bytes lost | Pressure-relief GC at >80% fill; evict oldest by `last_seen_ns`, **flush to GlobalState first**. The loss is observable: the kernel counts every rejected insert into `lachesis_bpf_update_failures_total{reason="update_failure"}` ([metrics.md](./metrics.md)) |
| 5 | PERCPU first-packet TOCTOU | Two CPUs race on creation; one's BPF_ANY overwrites the other | At most 1 packet lost per new flow per race. Documented & accepted |
| 6 | GSO/TSO/GRO offload | `skb->len` is the aggregated-skb byte count — correct payload, but per-segment L2/L3/L4 headers are counted once per superpacket rather than per wire segment, so bulk MTU-1500 TCP measures ≈4.35% under wire-equivalent (verified empirically on a single-node OVN deployment; provider-favorable to the customer). Both hooks count the same aggregated-skb basis — confirmed symmetric, no direction skew. Packet counts are superpacket counts, far under the wire segment count | Bill on bytes, not packets; the byte-basis contract is stated in [billing.md](./billing.md) |
| 7 | Boot ordering: TC attached before trie populated | First flows permanently keyed `dst_zone=MISS` | Enforce sequence with sync gates ([boot-and-recovery.md](./boot-and-recovery.md)) |
| 8 | WAL window (60s) | Up to 60s data loss on hard reboot | Documented; tunable |

## Tier 3 — Misclassification

Bytes still counted, but under the wrong zone.

| # | Edge case | Failure | Fix |
|---|---|---|---|
| 9 | OS-level static route inside VM | Falls to EXTERNAL | Unsolvable; safe-billing fallback ([Scenario H](./scenarios.md)) |
| 10 | Port security disabled + MAC spoof | Classification trusts the L2 headers, so a port with `port_security_enabled=false` (common for NFV) breaks the trust model two ways: a VM can emit frames carrying *another* tenant's MAC — `mac_tenant_map[spoofed]` hits the wrong tenant and inflates that tenant's bill — and any VM can spray random peer MACs to mint flow keys in the shared per-node `telemetry_map` (max 65,536 entries), a noisy-neighbor pressure vector | Billing integrity assumes port security on (the Neutron default); ports with it disabled are **attributed-but-untrusted**. The minting attack is observable: the spray pressures the map toward full and the resulting rejected inserts land in `lachesis_bpf_update_failures_total{reason="update_failure"}` |
| 11 | DVR with per-host router MACs (traditional Neutron only — n/a on OVN) | Each compute node's [DVR](./primer.md#openstack-networking-primer) router has a different MAC | Not encountered on OVN deployments (single MAC per logical router across chassis); if a traditional Neutron deployment is ever supported, reinstate the cold-start enumeration step — [deferred item 2](./contracts.md#deferred-work) |
| 12 | VM uses its own GRE/VXLAN/IPsec | We see outer headers; classification on tunnel endpoint | Document; treat as external |
| 13 | IPv6 not in trie | All v6 *unicast* → ZONE_MISS (v6 multicast is caught by the multicast zone) | Extend trie schema to v6 keys — [deferred item 1](./contracts.md#deferred-work) |
| 14 | Late Kafka delivery (new VM not yet in MAC map) | First packets → UnresolvedBuffer | Late-binding resolution + `LastEbpfRaw` write-back ([data-structures.md](./data-structures.md#userspace-structures)) |
| 14a | OVN-synthesized DHCP `server_mac` not visible in Neutron port API (verified empirically) | DHCP responses to VMs have a `peer_mac` that misses `mac_tenant_map` | LPM trie carries the classification via `gateway_ip/32 → INFRA` ([trie-construction.md](./trie-construction.md#the-five-step-algorithm)). Visible as a small fraction of packets classified via the LPM-only path instead of the hybrid path; functionally correct |
| 14b | Allowed-address-pairs / VRRP virtual MAC | A keepalived pair in vMAC mode (`00:00:5e:00:01:xx`) or an allowed-address-pair configured with an explicit MAC sources frames from a MAC that is not a Neutron port MAC → `mac_tenant_map` miss → bytes land in `tenant_id="unknown"`, `zone="miss"` (unbillable). Default keepalived (GARP over the real port MACs) classifies correctly | Counted as a structural revenue-leak contributor ([billing.md](./billing.md)). Deferred fix: fetch `allowed_address_pairs` in `ListPorts` and admit those MACs — [deferred item 9](./contracts.md#deferred-work) |
| 14c | VM→FIP hairpin | Same-cloud (even same-hypervisor, same-subnet) traffic addressed via a peer's floating IP bills `external` on *both* taps — OVN hairpin-SNATs the source to the client's own FIP, so each side sees an external-net address | Deliberate, not a misclassification to fix: documented as the chosen posture in [billing.md](./billing.md) (public-cloud norm; tenants avoid it by addressing fixed IPs). Verified empirically on a single-node OVN deployment |
| 14d | Broadcast / multicast destinations | Any frame with a group destination MAC (`255.255.255.255` DHCP broadcast, `224.0.0.0/4` / `ff00::/8` mDNS / SSDP / IGMP / VRRP chatter) is classified `multicast` by the kernel — a dedicated never-billed zone — from the destination MAC's I/G bit, before the trie is consulted | **Resolved (lachesis#150).** Was `external` (sent) / `miss` (received on provider taps, the revenue-leak-SLO inflater). Now counted-but-never-billed in `zone="multicast"` and excluded from the SLO numerator; see [billing.md](./billing.md) |

## Tier 4 — Subtle correctness

| # | Edge case | Risk | Fix |
|---|---|---|---|
| 15 | Both-side counting (sender tap + receiver tap) | Naive cross-tap sum doubles the total | Deliberate, not a bug: each transfer emits exactly one `tx` series (sender's tap) and one `rx` series (receiver's tap). No host label exists on the metric — host identity is the Prometheus `instance` scrape label, so the pair lands on different `instance` series; billing consumes per-instance series and sums downstream. The per-side charging postures ([billing.md](./billing.md)) make the pair harmless: each side pays its own direction (`same_tenant` bills $0), never summed as one flow |
| 16 | VM live migration | Tap vanishes on the source host, appears on the destination host | Handled by the Netlink Watcher: DELLINK detaches on the source, NEWLINK attaches on the destination (the Neutron port is *not* deleted, so the Lingering Ghost path plays no role). Each host's agent emits its own cumulative series under its own `instance` label — one VM accrues up to N instances' series over its lifetime; the billing pipeline sums them. Few-packet loss during the cutover is bounded. Live regression: `live-migration-continuity` |
| 17 | Conntrack miss on Segment 1 zone classification (Octavia design) | The optional `bpf_skb_ct_lookup` at the Amphora's tap may miss (first SYN, TTL expiry, UDP >30s idle, lookup at the wrong tap). Segment 1 zone falls back to EXTERNAL | Attribution to LB owner is unaffected — it comes from the Amphora MAC flag, not conntrack. See [octavia.md](./octavia.md) |
| 18 | u64 wraparound | At 10 Gbps continuous, ~467 years to overflow (2⁶⁴ / 1.25 GB/s ≈ 1.5×10¹⁰ seconds). The guard is one comparison, so add it anyway | [Contract 5](./contracts.md#required-contracts) |
| 19 | Crashed agent leaves orphan TC filters | Stale filters double-count if the agent restarts | Zombie Hunter at startup ([boot-and-recovery.md](./boot-and-recovery.md)) |
| 20 | Multicast / broadcast | One sent packet, many receivers → ingress sum doubles (this row is the *counting* angle; the *zone* angle is Tier 3 row 14d — these frames classify `multicast`, never billed) | Accept as <0.1% noise; the never-billed `multicast` zone means the double-count carries no billing consequence |
| 21 | VM-appliance forwarding double-billing | Traffic via a compute nexthop is billed at the originating VM's tap (at the appliance's tenant zone) AND again at the appliance's tap for the forwarded egress — same bytes, different MAC pairs, different flows | Documented; billing aggregation must dedup forwarding chains. [Scenario L](./scenarios.md) |

## Honest accuracy ceiling

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

The static ceiling claimed here is verified at runtime by the revenue-leak SLO
([billing.md](./billing.md)) — the unbilled fraction of observed bytes.

## Platform floor

The 5.10+ kernel requirement ([overview.md](./overview.md)) has two distinct origins worth recording. `BPF_MAP_LOOKUP_BATCH`, the syscall the scraper drains the map with, needs ≥5.6. The per-CPU zero-fill of recycled `PERCPU_HASH` elements — so a map slot reused after pressure-relief GC deletes an entry never returns a previous flow's stale counter on a CPU that didn't touch it — needs ≥5.10; this only starts to matter once GC actually deletes entries. Both staging clusters run 6.12.x, comfortably above the floor.

One related GC design rule: `last_seen_ns` is `CLOCK_MONOTONIC`, which resets at every boot. The GC must never compare a WAL-restored timestamp from a prior boot against a current-boot kernel value — they live on different monotonic timelines, and a cross-boot subtraction yields garbage. WAL-restored state carries cumulative byte counters across boots; the eviction-age clock does not.

---

Next: [boot-and-recovery.md](./boot-and-recovery.md) →
