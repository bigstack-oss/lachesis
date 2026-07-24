# Metrics Catalog

Two tiers of metrics. **Billing metrics** (the thing we exist to produce) are
emitted by the custom `prometheus.Collector` from `GlobalState` as a
**four-layer family hierarchy** — total → tenant → server → port, each layer
immortal within its owner's lifetime, each absorbing the deaths of the layer
below. **Health metrics** (operator-facing instrumentation) are
bounded-cardinality; an operator running PromQL against one node should see
<100 series total (the port layer is the one deliberate exception, bounded by
port count). The product semantics on top of the billing tier — postures,
consumption rules — live in [billing.md](./billing.md).

Every name below is pinned by tests: each package defines its own `Metrics`
bundle, the agent registers them centrally, and a naming-guard test enumerates
the registry — a metric that drifts from this catalog fails CI by name.

## Billing (cumulative counters; emitted from GlobalState)

| Metric | Type | Labels | Series lifecycle |
|---|---|---|---|
| `lachesis_bytes_total` | counter | `zone, external_network, direction` | **total layer** — Σ over all tenants (incl. `unknown`) of live + settled, plus total-settled (dead projects' history); immortal |
| `lachesis_packets_total` | counter | `zone, external_network, direction` | **total layer** — packets (GSO/GRO superpackets) companion; diagnostic, never billed |
| `lachesis_tenant_bytes_total` | counter | `tenant_id, zone, external_network, direction` | **tenant layer** — live + tenant-settled; monotone for exactly the project's lifetime, ends when the project leaves the Keystone list (`unknown` never dies; [billing.md](./billing.md)) |
| `lachesis_tenant_packets_total` | counter | `tenant_id, zone, external_network, direction` | **tenant layer** — packets companion, same lifetime as the bytes family; diagnostic, never billed |
| `lachesis_server_bytes_total` | counter | `server_id, tenant_id, zone, external_network, direction` | **server layer** — Σ live rows + server-settled; monotone for exactly the server's lifetime (flat-lines while portless), ends when the server leaves the Nova list ([billing.md](./billing.md)) |
| `lachesis_server_packets_total` | counter | `server_id, tenant_id, zone, external_network, direction` | **server layer** — packets companion, same lifetime as the bytes family; diagnostic, never billed |
| `lachesis_port_bytes_total` | counter | `server_id, port_id, tenant_id, zone, external_network, direction` | **port layer** — the mortal leaf: live rows of one port; stops at port delete, restarts fresh on detach→reattach (drill-down view; billing exactness lives one layer up) |
| `lachesis_port_packets_total` | counter | `server_id, port_id, tenant_id, zone, external_network, direction` | **port layer** — packets companion, same lifetime as the bytes family; diagnostic, never billed |

### Billing label vocabulary

These value sets are an API contract — dashboards and billing pipelines pin
them, so changing any value is a breaking change once consumers exist.

| Label | Value set | Meaning |
|---|---|---|
| `tenant_id` | Neutron project UUID, or `unknown` | The tenant the flow's VM belongs to (resolved via `mac_tenant_map`); `unknown` when the VM MAC is not (yet) in the metadata map |
| `zone` | `external`, `same_tenant`, `other_tenant`, `infra`, `miss`, `shared`, `multicast` | The remote endpoint's zone relative to the VM's tenant ([packet-classification.md](./packet-classification.md)); the canonical strings from `bpf.ZoneCode.String()`. `multicast` is assigned by the kernel to any frame with a group destination MAC (platform-L2 chatter) — counted but never billed |
| `external_network` | external-network name (ID when nameless), or `none` | The network the flow's external traffic leaves through, resolved **per flow**: the peer router-interface MAC's gateway network when known, else the VM's attribution (FIP network / gateway-IP rule) — full rules in [billing.md](./billing.md). Carried **only** on `zone="external"` series; every other zone (and external traffic with no resolvable path) emits the `none` sentinel, keeping cardinality at (#external networks + 1). The single labeling source is `metadata.FlowExternalLabel`, applied identically at scrape-time aggregation and every settle fold |
| `server_id` | Nova instance UUID (Neutron port `device_id`) | Per-server family only. Never `unknown` — flows whose MAC doesn't resolve to a server are absent from the family by construction |
| `port_id` | Neutron port UUID | Port layer only. A MAC maps to exactly one port; a recreated port is a new UUID, hence a new series |
| `direction` | `tx`, `rx` | `tx` = the VM is sending; `rx` = the VM is receiving |

**Attribution changes settle first.** Any change to a live MAC's attribution
tuple (tenant, external network, server binding) folds the MAC's accumulated
rows into the settled buckets under the OLD attribution (SettleRebase,
[data-structures.md](./data-structures.md#settled-bytes)) before the new
binding takes effect — one mechanism covers tenant reassignment, FIP/gateway
re-homing (the external_network label would otherwise teleport its cumulative
between series), and server re-binding (the per-server born-series rule would
otherwise re-bill the old server's history to the new one).

**Why `tx`/`rx`, not the TC hook names.** The TC hooks attach to the **tap
interface (host side)** of each vNIC, so the raw hook names are inverted
relative to the VM: a VM *upload* fires the tap's TC **ingress** hook
(`TC_DIR_INGRESS = 0`, "VM is sending") and a VM *download* fires the
**egress** hook (`TC_DIR_EGRESS = 1`, "VM is receiving"). Exporting the
hook-frame words as label values would make `direction="egress"` mean
*download* — the opposite of the cloud-billing convention where egress is data
leaving the VM. The label vocabulary is therefore frame-free and
NIC-conventional: `tx` (VM transmits — hook ingress) / `rx` (VM receives —
hook egress), rendered by `bpf.Direction.String()`. The kernel enum keeps its
hook-frame names — the [directional swap](./packet-classification.md#the-directional-swap-explained)
depends on them. Do not reintroduce hook-frame strings into the metric labels.

## Identity info metrics (join series; emitted from the Neutron snapshot)

Two additive *info* families let dashboards render human names next to the
UUID labels without putting a name label on the billing families — the
kube-state-metrics `kube_pod_info` pattern (a value-`1` series joined with
PromQL `group_left`).

| Metric | Type | Labels | Series lifecycle |
|---|---|---|---|
| `lachesis_tenant_info` | gauge (always 1) | `tenant_id, name` | mortal — one series per Keystone project in the committed snapshot |
| `lachesis_server_info` | gauge (always 1) | `server_id, name, tenant_id` | mortal — one series per Nova server; **absent** when the Nova fetch fails |

They are emitted by a dedicated `neutron.InfoCollector` (registered under the
neutron subsystem), **not** the billing `metrics.Collector` — the billing
families stay byte-identical, and because names live only in these info series
a historical join shows the name an entity held *at that time* rather than
back-dating a rename. Each scrape re-emits from the current
`neutron.Snapshot()`, so a series vanishes the sync after its entity leaves the
snapshot (a `GaugeVec` would instead leak deleted-entity series forever).
Cardinality is one series per tenant / per server — no churn amplification.

`tenant_id` names come free from the project list `Sync` already fetches;
`server_id` names need a Nova server list, fetched **best-effort**
(`Client.ListServers`, `AllTenants`) and non-fatally (a Nova/compute failure
records `lachesis_neutron_api_errors_total{endpoint="servers"}` and leaves the
family absent, never failing the sync). Dashboards join and fall back to bare
ids when the info series is missing:

```promql
sum by (tenant_id) (rate(lachesis_tenant_bytes_total[1m]))
  * on(tenant_id) group_left(name) lachesis_tenant_info          # named rows
or sum by (tenant_id) (rate(lachesis_tenant_bytes_total[1m]))
     unless on(tenant_id) lachesis_tenant_info                   # bare-id fallback
```

## Health (per-subsystem; bounded cardinality)

| Metric | Type | Labels | Source |
|---|---|---|---|
| `lachesis_bpf_map_max_entries` | gauge | `map="telemetry_map\|subnet_zone_trie\|mac_tenant_map"` | seeded at startup from the compiled-in sizes ([performance.md](./performance.md)) |
| `lachesis_bpf_map_current_entries` | gauge | same `map` label | userspace-tracked count: kernelwriter push for mac_tenant_map / subnet_zone_trie, scraper drain for telemetry_map. Fill ratio = `current / max` in PromQL (numerator and denominator both stay visible) |
| `lachesis_bpf_update_failures_total` | counter | `reason="update_failure\|skipped_ethertype"` | kernel `telemetry_stats` PERCPU_ARRAY, CPU-summed and drained by the scraper each tick; both reason series are zero-seeded at startup. `update_failure` = telemetry_map inserts the kernel rejected (map full — those flows' bytes are lost until GC frees space), `skipped_ethertype` = non-IP frames passed through uncounted (ARP/LLDP noise normally; a sustained rise flags a trunk/VLAN blind spot) |
| `lachesis_bpf_maps_pinned` | gauge | — | 1 when the counter-bearing BPF maps are pinned to bpffs (zero-loss agent-crash recovery, [boot-and-recovery.md](./boot-and-recovery.md)); 0 when running unpinned (recovery degraded to the ≤60s WAL-bounded path) |
| `lachesis_state_flows` | gauge | — | distinct flow keys in GlobalState (Collector) |
| `lachesis_state_tenant_settled_tuples` | gauge | — | distinct buckets in the settled-bytes accumulator ([data-structures.md](./data-structures.md#settled-bytes)) |
| `lachesis_state_server_settled_tuples` | gauge | — | distinct buckets in the server-settled accumulator — the server layer's fold absorber, released on Nova-list absence ([data-structures.md](./data-structures.md#settled-bytes)) |
| `lachesis_state_total_settled_tuples` | gauge | — | distinct buckets in the total-settled accumulator — the total layer's fold absorber, credited when a deleted project's tenant-settled bucket is released; never pruned ([data-structures.md](./data-structures.md#settled-bytes)) |
| `lachesis_scraper_errors_total` | counter | — | failed BPF-map drain attempts (Collector, from scraper) |
| `lachesis_scraper_last_success_unix_seconds` | gauge | — | most recent successful drain; 0 if never (Collector, from scraper) |
| `lachesis_collect_duration_seconds` | histogram | — | one Collect pass: snapshot + aggregate + emit. Buckets 1ms..1s |
| `lachesis_config_reloads_total` | counter | `result` | SIGHUP reload outcomes ([operations/runtime.md](../operations/runtime.md)) |
| `lachesis_wal_snapshot_copy_seconds` | histogram | — | WAL writer, copy-under-lock phase (critical section) |
| `lachesis_wal_marshal_seconds` | histogram | — | WAL writer, JSON marshal phase (no lock held) |
| `lachesis_wal_flush_latency_seconds` | histogram | — | WAL writer, write+fsync+rename phase (no lock held). Buckets: 1ms..1s |
| `lachesis_wal_flush_failures_total` | counter | `stage="marshal\|write\|fsync\|rename_bak\|rename_current\|dir_sync"` | WAL writer |
| `lachesis_wal_load_fallback_total` | counter | `from="bak\|empty"` | boot loader |
| `lachesis_neutron_sync_age_seconds` | gauge | — | last successful cold-start or full reconcile; -1 = never synced |
| `lachesis_neutron_api_errors_total` | counter | `endpoint, code` (HTTP status, or `network` for connection-level failures) | Neutron client |
| `lachesis_neutron_unknown_device_owner_total` | counter | `owner` | port admissions outside the IsKnownVMOwner allowlist |
| `lachesis_neutron_builder_step_duration_seconds` | histogram | `step` | BuildTrie per-step duration ([trie-construction.md](./trie-construction.md#the-five-step-algorithm)) |
| `lachesis_neutron_anomalies` | gauge | `class="cycle\|ambiguity\|dangling_route\|zero_trie_tenant\|duplicate_router_mac\|multi_external_path"` | topology anomalies detected at the last cold-start or resync (`DetectAnomalies`; drives `/debug/anomalies`) |
| `lachesis_neutron_trunk_subports` | gauge | — | trunk subport MACs admitted to `mac_tenant_map` at the last cold-start or resync; nonzero flags the trunk blind spot ([edge-cases.md](./edge-cases.md), Tier 1 row 3a) |
| `lachesis_zombie_filters_cleaned_total` | counter | — | startup Zombie Hunter |
| `lachesis_tc_attach_failures_total` | counter | `iface_kind="tap\|other"` | Netlink Watcher |
| `lachesis_attached_interfaces` | gauge | — | current Interface Registry size |
| `lachesis_gc_evictions_total` | counter | `reason="ttl\|pressure_relief\|ghost_residual_flow"` | GC: lingering-ghost sweep (`ttl`, mac_tenant_map), scraper pressure-relief (`pressure_relief`, telemetry_map), and a swept MAC's residual telemetry_map flows removed so they are not re-billed as "unknown" (`ghost_residual_flow`) |
| `lachesis_gc_pressure_relief_runs_total` | counter | — | scraper pressure-relief pass (fill above the high watermark) |
| `lachesis_gc_settled_flows_total` | counter | — | GlobalState flow rows the ghost sweep folded into the settled-bytes accumulator, keeping deleted VMs' bytes attributed to their tenant |
| `lachesis_lingering_ghosts_active` | gauge | — | metadata entries inside the 60s ghost grace window |
| `lachesis_unresolved_buffer_depth` | gauge | — | UnresolvedBuffer occupancy (panic threshold near the cap) |
| `lachesis_unresolved_buffer_evictions_total` | counter | `reason="lru\|expired"` | UnresolvedBuffer entries folded to "unknown", by cause |
| `lachesis_unresolved_resolved_total` | counter | — | late-binding successes: a buffered flow whose MAC became known (reconcile or Kafka) attributed to the right tenant with the delta write-back |
| `lachesis_reconcile_runs_total` | counter | `result="ok\|sync_error\|apply_error"` | periodic + Kafka-kicked Neutron reconcile passes by outcome; `apply_error` is the runtime kernelwriter-failure sink |
| `lachesis_kafka_lag_messages` | gauge | `topic` | Kafka consumer lag behind the topic head; sustained growth = falling behind live updates |
| `lachesis_kafka_consume_errors_total` | counter | `topic` | Kafka consumer read failures (broker unreachable, fetch errors) |

## Planned (subsystem not yet built; add with the subsystem)

The Octavia LB attribution metrics land with [that subsystem](./octavia.md).

A drafted generic `lachesis_internal_errors_total{subsystem}` sink was dropped:
every billing-path error site today lands in a dedicated counter (scraper
errors, WAL flush-failure stages, WAL load fallback, Neutron API errors, TC
attach failures), and runtime kernelwriter failures land in
`lachesis_reconcile_runs_total{result="apply_error"}`. Revisit if a runtime
error path ever lands without a dedicated counter.

## Cardinality discipline

**Never** label a health metric with `tenant_id`, `mac`, `flow_key`, or any
per-flow identifier. Anything per-flow goes only into the billing tier, whose
cardinality is already bounded by the trie / MAC-pair model.

## SLO targets (informational)

- `lachesis_neutron_sync_age_seconds` < 120 (Kafka-driven freshness)
- `lachesis_wal_flush_latency_seconds` p99 < 50 ms
- `lachesis_unresolved_buffer_depth` < 1000 sustained (10k cap is a panic threshold)
- `lachesis_bpf_map_current_entries{map="telemetry_map"} / lachesis_bpf_map_max_entries{map="telemetry_map"}` < 0.8 (above triggers pressure-relief GC)
- `lachesis_bpf_update_failures_total{reason="update_failure"}` == 0 (any increase is billed bytes lost in the kernel; alert on `> 0` — a page, since pressure-relief GC means it should never fire)
- `lachesis:unbilled_bytes:ratio_rate5m` < 0.001 — the revenue-leak SLO; recording rule and structural contributors defined in [billing.md](./billing.md)

---

Next: [billing.md](./billing.md) →
