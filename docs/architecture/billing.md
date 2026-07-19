# Billing Model & Consumption Contract

The measurement layers produce billing-grade counters; this chapter defines the
product semantics on top of them — which series a billing engine reads, what
each zone should cost, and how to consume the counters without corruption. A
billing implementer should be able to work from this chapter alone (metric
shapes and label vocabularies: [metrics.md](./metrics.md)).

## The emission invariant

Every byte transfer the data plane can see appears in **exactly one `tx` series and one `rx` series**: counted once at the sender's tap as `direction="tx"` and once at the receiver's tap as `direction="rx"`, each keyed by `(tenant_id, zone, external_network, direction)` on `lachesis_bytes_total` / `lachesis_packets_total`. The agent **never deduplicates** — both-sides emission is the contract, not an artifact ([Scenario I](./scenarios.md); [edge-cases.md](./edge-cases.md) Tier 4 row 15). When only one endpoint sits behind a monitored tap (internet peers, DPDK/SR-IOV VMs), only that side's series exists.

Byte basis: aggregated-skb L2 bytes. Per-segment headers are counted once per GSO/GRO superpacket, so bulk TCP measures ≈4–5% under wire-equivalent (verified empirically; ~0 on small-packet traffic — [edge-cases.md](./edge-cases.md) Tier 2 row 6), and `lachesis_packets_total` counts superpackets, not wire segments. **Bill on bytes, never on packets.**

## Per-zone charging postures

The zone vocabulary is the [metrics.md](./metrics.md) label table. The guiding principle: **each side pays for its own direction** — under these postures, no cross-tap dedup is ever needed.

| `zone` | Posture | Rationale |
|---|---|---|
| `same_tenant` | **$0** (recommended) | Makes the both-sides emission harmless by construction: an intra-tenant transfer produces one `tx` and one `rx` series for the same tenant, and 2 × $0 = $0 |
| `other_tenant` | **Per-side at the internal rate** — sender pays its `tx`, receiver pays its `rx` | The AWS cross-AZ model: each party is billed for its own direction of a cross-tenant transfer. The two series belong to different tenants, so no dedup question arises |
| `external` | **Per-direction rates** — `tx` at the egress rate (data leaving toward the internet), `rx` at the ingress rate | The universal cloud convention of asymmetric internet pricing |
| `infra` | **$0 today** | Covers DHCP/metadata chatter and Octavia Segment 2 plumbing ([octavia.md](./octavia.md)) alike. Future fork: if LB-processed-byte billing is ever wanted, either split the zone (the designed Amphora branch distinguishes Segment 2, so an `infra_lb` zone is cheap) or source LB usage from the Octavia API. Until that product decision, `infra` stays uniformly free |
| `shared` | **Own line item at an intermediate internal rate** | Owner-vs-other inside a shared CIDR is intentionally indistinguishable on the L3 path — [trie-construction.md step 3](./trie-construction.md#the-five-step-algorithm) explains why guessing either mis-bills. Price between `same_tenant` and `other_tenant` instead of guessing |
| `multicast` | **Never billed; not alerted** | Frames with a group destination MAC (mDNS/SSDP/DHCP-broadcast — the physical L2's background chatter, plus any VM-originated multicast tx). Never tenant traffic under any posture. Counted and exposed for transparency but excluded from the revenue-leak SLO numerator so a constant platform-chatter floor can't pin the ratio |
| `miss` — and any `tenant_id="unknown"` (excluding `zone="multicast"`) | **Never billed; alert-only** | Unattributable bytes must not become invoices. Tracked by the revenue-leak SLO below; `multicast` is carved out because it is expected platform chatter, not an attribution failure |

**FIP hairpin is EXTERNAL on both sides — deliberately.** When a VM reaches a same-tenant peer via the peer's floating IP, both taps classify EXTERNAL: the client's tap sees the remote FIP, and OVN hairpin-SNATs the source to the client's *own* FIP, so the server's tap also sees an external-net address (verified empirically — same tenant, same subnet, same hypervisor). The traffic never leaves the host, yet bills at external rates in both directions. This matches public-cloud norms (AWS bills public-IP hairpins as public traffic); tenants avoid the charge by addressing fixed IPs.

## The consumption contract

- **Counters are lifetime-cumulative and never decrease.** A flow row lives in GlobalState while its attribution lives, and when the attribution dies — the VM deleted and ghost-swept, or the port reassigned to another project — the row's bytes fold forward into the settled accumulator under the same label tuple ([data-structures.md](./data-structures.md#settled-bytes)). The exposed series is the live+settled sum, so its value is invariant across the fold: VM churn never decreases a tenant's series. WAL restore carries both halves across agent restarts and reboots — series never reset to zero. (A hard crash can drop up to the ≤60s WAL window of tail bytes and un-persist that window's folds — provider-unfavorable, [boot-and-recovery.md](./boot-and-recovery.md).) [Contract 7](./contracts.md#required-contracts) pins this as an implementation contract.
- **Consume by endpoint-sample subtraction, not `increase()`.** For a billing period `[T₀, T₁]`, charge `value(T₁) − value(T₀)` per series. `increase()` extrapolates to compensate for counter resets and scrape-boundary gaps; these counters never reset, so the extrapolation only adds error. Plain subtraction is exact — the no-eviction property is precisely what makes it safe.
- **Prometheus durability, retention, and HA are the platform's responsibility** (stated non-goal). The agent's promise ends at `/metrics`: cumulative, monotone, restart-surviving series. Whatever scrapes them must retain the two endpoint samples per billing period (or remote-write to something that does).
- **Host identity is the Prometheus `instance` scrape label** — there is no host label on the metric itself. A live-migrated VM accrues series under several `instance` values over its lifetime; sum them ([edge-cases.md](./edge-cases.md) Tier 4 row 16).

## Revenue-leak SLO

The unbilled fraction — bytes in `zone="miss"` or `tenant_id="unknown"` — is the runtime verification of the static [accuracy-ceiling claim](./edge-cases.md#honest-accuracy-ceiling) (~99.9%):

```yaml
- record: lachesis:unbilled_bytes:ratio_rate5m
  expr: |
    sum(
        rate(lachesis_bytes_total{zone="miss"}[5m])
      or rate(lachesis_bytes_total{tenant_id="unknown",zone!="multicast"}[5m])
    )
    /
    sum(rate(lachesis_bytes_total[5m]))
```

The `or` deduplicates series that are both `zone="miss"` and `tenant_id="unknown"`: both operands draw from the same series set, so label sets match exactly and each leaking series counts once. The `zone!="multicast"` guard on the second operand is load-bearing: received platform multicast resolves to `tenant_id="unknown"` (its group destination MAC is the VM-side MAC on the egress hook, so it misses `mac_tenant_map`), so without the guard the never-billed multicast zone would re-enter the numerator through the `unknown` clause and defeat the carve-out. The `miss` operand needs no guard — a multicast frame is classified `multicast`, never `miss`. The denominator is deliberately left as all observed bytes: multicast stays visible as a share of total, it just isn't counted as leaking.

**Target: < 0.001 (0.1%)**; alert above it. Structural contributors to expect:

- **IPv6** — all *unicast* v6 classifies `zone="miss"` until [deferred item 1](./contracts.md#deferred-work) lands (v6 multicast, e.g. mDNS `33:33:*`, is caught by the multicast zone); deployments with real v6 unicast traffic will sit above the target until then.
- **Allowed-address-pairs / VRRP virtual MACs** — a vMAC sourced by a keepalived pair is not a Neutron port MAC, misses `mac_tenant_map`, and emits `tenant_id="unknown"` ([deferred item 9](./contracts.md#deferred-work)).
- **Transient cold-start / late-Kafka windows** — self-healing via the UnresolvedBuffer; visible as short spikes, not steady-state leak.

Platform-L2 multicast (mDNS/SSDP on provider-attached taps) *was* the dominant structural contributor — a constant tens-of-KB/s numerator that pinned the ratio near 1% on quiet clusters — until it moved to the dedicated `multicast` zone and out of this numerator.

## Per-server usage export

The tenant-family contract above is deliberately **aggregate** — `tenant_id × zone × external_network × direction`, all low-cardinality, every series immortal. Per-server billing detail is a **second metric family on the same `/metrics` endpoint** with a deliberately different lifecycle promise — not a dedicated endpoint, and not a message bus:

`lachesis_server_bytes_total{server_id, tenant_id, zone, external_network, direction}` — cumulative, emitted from the same GlobalState (WAL-backed, restart-surviving) as the tenant family. `server_id` is the Neutron port `device_id` (Nova instance UUID), stable across live migration; `user` is not emitted (Neutron ports don't carry it) — the billing consumer derives ownership from `server_id`.

### External-network attribution rules

Resolution is **per flow, router-MAC first**:

- **Router-MAC rule (primary).** A routed external flow's peer MAC is a router interface's MAC — unique per logical router interface on OVN (the `duplicate_router_mac` anomaly asserts exactly this). A `router-interface-MAC → external_network` map (built from the snapshot, seeded at cold start, pointer-swapped by the reconciler) attributes each flow to the network that **actually carried it**. This dissolves the multi-path ambiguity exactly — a VM with two FIPs or an in-guest route through a second router bills each flow under its real exit network. The destination IP could never do this: the tap sits on the VM side of the router, so SNAT/DNAT happens after the measurement point — the router MAC is the only per-flow datum that identifies the exit network.
- **Per-VM fallback.** When the peer MAC is not a known router interface — a gateway-less router carrying in-guest-routed traffic, or any interface the map doesn't cover — fall back to the VM's own attribution: its floating IP's network, else the external gateway of the router owning its subnet's `gateway_ip` (the *gateway-IP rule*: several routers may attach to one subnet, but the VM's default route points only at the gateway owner; non-gateway routers count only when no gateway owner has an external gateway). A multi-path VM's fallback is a deterministic pick (lexicographically smallest label, FIP tier first) so reconcile passes never flap it.
- **Observability.** Multi-path VMs surface on `lachesis_neutron_anomalies{class="multi_external_path"}` with per-port drill-down at `/debug/anomalies` — retained as a topology cross-check; its billing meaning is only "the per-VM *fallback* would be approximate here".
- **Router re-gatewaying settles first.** When a router's gateway (or interface set) changes, the reconciler folds every live flow riding that interface MAC under the OLD label (SettleRebase) before swapping the map — the router-side twin of the per-VM attribution-change fold.
- **Known gap.** A VM directly on a provider network resolves `none` today: no FIP, no router owning its subnet's gateway — a known gap, not a fallback case.
- **Live regression.** The `multi-external-path` scenario exercises the whole ladder: default-route and second-router drives each assert their own carrying network's series, and a third drive through a gateway-less router asserts the per-VM fallback — all on both families.

### Mortality and the ETL contract

- **Mortal series.** Unlike the tenant family, a per-server series *ends* when its attribution dies (VM deleted and ghost-swept): the fold settles bytes at tenant granularity only, so there is nothing left to emit the dead server from — deliberately, because per-dead-server accumulators would grow without bound under VM churn. Dead-server history is the scraping TSDB's responsibility; its retention must exceed the consumer's maximum tolerable ETL outage (90 days on the target platform, far above the few days actually required). A mortal series is PromQL-safe: it only ever *stops*, it never *decreases* — the poison the settled fold exists to prevent is a *continuing* series that drops.
- **Compaction floor while alive:** no agent-side compaction may fold a live server's bytes past the server key (a per-live-server accumulator is the floor; that set is bounded). Tenant-level settle happens only at attribution death. Otherwise the exposed per-server series would decrease and break subtraction at server granularity.
- **Consumption contract (the billing ETL):** read a day's range per series and take boundary values — series present at both ends: `Δ = last − first`; born mid-window: `Δ = last` (a counter born in-window carries its lifetime bytes); died mid-window: `Δ = last sample − first`; negative `Δ` clamps to 0 (an agent hard crash can regress the counter by up to the WAL flush window — provider-unfavorable, self-correcting); live migration: sum `Δ` across scrape instances per `server_id`. **Never `increase()`/`rate()` for money** — PromQL's reset heuristic assumes resets go to zero, so a crash's partial regression would be double-counted.
- **The agent meters; the billing system rates.** The rate table (`zone × external_network × direction → price`) lives in the billing layer, never in the agent. Billing *ownership* is billing-layer enrichment keyed by `server_id` at rating time: platform-level owner transfer can happen entirely inside the billing system's own records, invisible to OpenStack and to this agent — so `tenant_id` on these metrics is infrastructure attribution (dashboards, revenue-leak SLO, audit), never the invoice key.
- The consumer pipeline (a scheduled ETL distilling day deltas into durable billing rows) is the platform's; the agent's promise ends at the two families' contracts. Cumulative + pull stays lossless across consumer downtime — any missed period is backfillable from the TSDB within retention.

### Why two families coexist

The tenant family is immortal (live + settled bytes): safe for `rate()`, dashboards, recording rules, and exact two-point totals through any churn — and it is the only place unattributable traffic (`zone="miss"`, `tenant_id="unknown"`) can live, since such bytes have no `server_id`; the revenue-leak SLO is computable only there. The server family is mortal (live bytes only): the billing detail feed, consumed under the ETL contract above. The pair also forms two independent accumulation paths over the same kernel counters, enabling reconciliation audits of the billing pipeline (per-tenant sums of billed rows vs. tenant-series deltas).

`external_network` is the one billing dimension that is *also* low-cardinality enough for the tenant family (a handful of external networks, no churn), so operator dashboards can split egress by external network without touching per-server series. This keeps the tenant family as the operator/aggregate plane and the server family as the billing detail feed, with the durable record-of-truth in the billing system's own store.

---

Next: [contracts.md](./contracts.md) →
