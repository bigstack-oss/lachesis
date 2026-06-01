# Sprint Plan — CubeCOS Network Telemetry

> Living document. Each sprint = one PR. PRs are reviewable by a single engineer in one sitting, land a working slice that demonstrates new capability, and unblock the next sprint.

This plan is scoped against [DESIGN.md](./DESIGN.md). When the design changes, update this plan; the design remains the source of truth.

## How to read it

- **Goal** — one-line outcome.
- **Scope** — what lands in the PR.
- **Done when** — testable statement that gates merge.
- **LOC** — rough net new code, excluding generated `_bpfel.go`. Use it to size review cycles.

## Visualization (Sprint 2 onward)

A Grafana dashboard set lives at `deploy/grafana/` as committed JSON, versioned with the code. Each sprint that produces new metrics adds matching panels in the same PR. By Sprint 10 the dashboards cover health, throughput, state, GC, Kafka, Octavia, and performance — a complete operator view.

| Sprint | Panels added | Visualizes |
|---|---|---|
| 2 | health, throughput, state | scrape success, bytes/sec by tenant + zone, GlobalState size |
| 3 | WAL detail | write latency, file size, restart recovery gap |
| 4 | Neutron sync | sync age, port population rate, builder step durations |
| 5 | boot health | phase completion, zombie-filter cleanup count, attach success rate |
| 6 | GC + ghosts | pressure-relief runs, eviction rate, lingering-ghost count |
| 7 | Kafka | consumer lag, consume error rate |
| 8 | Octavia | per-LB bytes, per-backend-VM breakdown, Segment 1 / Segment 2 split |
| 9 | performance | ns/packet, scrape duration, internal-error rate |

Dashboard JSON is syntax-validated in CI (`promtool query` on every panel). Metric names form an API contract — renames go through a deliberate PR with matching dashboard updates.

---

## Sprint 0 — Design fixups [DONE 2026-05-09]

Closed seven design drifts identified at project ceremony.

| Drift | Section | Change |
|---|---|---|
| B | §5.1, §5.2 | Added DVR data source + Step 6 per-host MAC enumeration; deleted §13 #8 |
| C | §13 | Renamed "Open Issues" → "Implementation Notes"; split into §13.1 Required Contracts (5) + §13.2 Deferred Work (1: IPv6) |
| D | §3.2 | WAL: `schema_version` envelope, u64-as-string, `.bak` rotation, atomic flush order, boot fallback, migration policy, JSON-not-binary rationale |
| E | §3.3 | Lingering Ghost wins over UnresolvedBuffer; tail vs. head of a MAC's life |
| F | §11 | Health metrics catalog: 2 billing + 17 health metrics, cardinality rule, SLO targets |
| G | §3.1 | Pressure-relief GC: 80% trigger / 75% floor / 1,000-entry cap / ~50 ms worst-case stall |
| H | §4.4 | Decision tree: Amphora diamond + conntrack-miss caveat |

**Decisions cemented:**

- `bpf/telemetry.c` is a placeholder, replaced in Sprint 1. DESIGN.md is the spec for the fresh build.
- IPv6 stays deferred (~1 sprint retrofit, low risk).
- Octavia is MVP scope (admin-LB misattribution would be a fatal billing hole).
- WAL keeps JSON, no compression.

DESIGN.md grew 1,416 → 1,556 lines.

---

## Sprint 0.5 — Test Infrastructure [DONE 2026-05-11]

The test rig every later sprint composes on top of. Built in five groups, all green.

| Group | Deliverable | Location |
|---|---|---|
| B | BPF unit-test driver | `internal/testenv/bpfunit/` + `bpf/test_fixtures/noop.c` |
| C | netns + traffic + e2e tying test | `internal/testenv/{netns,traffic,e2e}/` |
| D | CI workflows + zero-alloc gate + Taskfile harness | `.github/workflows/ci.yml`, `scripts/bench-gate.sh`, `task test`/`test-integration`/`bench-gate`/`ci` |
| E | `cmd/perfbench` (ns/packet via BPF_PROG_TEST_RUN) | `cmd/perfbench/main.go`, `task perfbench` |
| F | `docs/test-strategy.md`, sprint-plan sync | this file |

**Test counts at end of Sprint 0.5:** 8 integration tests (3 bpfunit + 2 netns + 1 traffic + 1 e2e + 1 other) all green via `task test-integration`.

**Scope deltas from original plan:**
- **Dropped scenario DSL from Group C.** No scenarios to deduplicate yet; Sprint 4 builds it when Neutron fixtures arrive.
- **Moved `cmd/loadtest` from Group E to Sprint 2.** Building load-test infrastructure with no agent to load-test is infra-for-absent-code; pairs naturally with the agent's first appearance in Sprint 2.
- **Dropped the iperf3 wrapper from `cmd/perfbench`.** DESIGN §12 already covers manual iperf3; perfbench provides the *unique* ns/packet measurement. Sprint 9 may automate iperf3.

**Decisions cemented:**
- All BPF C source lives under `bpf/` (production at top level, test fixtures in `bpf/test_fixtures/`). Cilium convention.
- All test infrastructure lives under `internal/testenv/`.
- BPF integration tests run via Docker with `--privileged -u 0 -e GOWORK=off`. See [test-strategy.md §Environmental gotchas](./test-strategy.md#environmental-gotchas).
- Hot-path benchmarks named `BenchmarkHotpath_*` are gated to zero allocations (`task bench-gate`).

---

## Sprint 1 — Hybrid zone lookup in kernel

**Goal.** Implement §4.3 MAC-first / LPM-fallback in the kernel.

**Scope.**
- New `bpf/telemetry.c` written from scratch (demo is gone).
- `lookup_zone()` checks `mac_tenant_map[peer_mac]` first; if found and tenants match, return SAME; if found and differ, return OTHER. Otherwise fall back to LPM trie.
- Table-driven Go test against userspace stub of the trie.
- `//go:build integration` kernel test using a transient veth pair.

**Done when.** `iperf3` between two known MACs on the same tenant classifies as SAME zone with the trie *empty* — proves the hybrid path is exercised.

**LOC.** ~150.

---

## Sprint 2 — GlobalState + delta math + custom Prometheus Collector

**Goal.** The L3↔L4 spine. Also lands the agent's first real binary and the load-test infrastructure that pairs with it.

**Scope.**
- `internal/state/`: `GlobalState` (RWMutex, per-flow `{Total, LastEbpfRaw}`).
- `internal/scraper/`: scraper calls `BatchLookup` every 10s, computes deltas, writes to GlobalState.
- `internal/metrics/`: custom `prometheus.Collector` emitting cumulative from GlobalState.
- HTTP server exposing `/metrics`.
- `cmd/loadtest/` (deferred from Sprint 0.5): synthesizes sustained traffic, samples `/proc/<pid>/{stat,status}` over a window, asserts RSS < 250 MB and CPU < 1%. Pairs with the agent built in this sprint.
- First `BenchmarkHotpath_*` benchmarks for `Collect()` and the scraper hot loop. Activates `task bench-gate` from Sprint 0.5 Group D.
- `deploy/grafana/`: dashboard-as-code scaffolding — `docker-compose.yaml` for a local Prometheus + Grafana stack, provisioning configs, and the first three dashboards (health, throughput, state) consuming the metrics added above.

**Done when.** Restart agent → `rate()` stays non-negative across the gap. `task loadtest` against the agent reports RSS/CPU within budget. `task bench-gate` enforces zero allocations on `Collect()`. The local Grafana stack renders the Sprint-2 dashboards against the agent's `/metrics`.

**LOC.** ~700 (originally ~500; +200 for loadtest moved from Sprint 0.5).

---

## Sprint 3 — WAL persistence

**Goal.** Survive agent crash with zero loss; hard reboot ≤60s loss.

**Scope.**
- `internal/wal/`: atomic tmp+rename with `.bak` rotation per §3.2.
- 60s flush ticker.
- Boot-time read → restore GlobalState before scrape starts.
- `schema_version: 1` envelope; u64-as-string encoding via `,string` struct tag.
- WAL health metrics from §11.4.

**Done when.** `kill -9` → totals continuous; reboot → ≤60s gap, no negative `rate()`. Bad-write recovery verified by injecting a malformed `wal.json` and checking fallback to `.bak`.

**LOC.** ~300.

---

## Sprint 4a — Neutron cold-start, foundations [planned split, part 1 of 2]

**Goal.** Stand up the Neutron data path end-to-end for everything except static routes. After this sprint the agent emits real `tenant_id` labels.

**Scope.**
- `internal/neutron/` HTTP client with Keystone auth; rate-limited paginated fetch for `networks`, `subnets`, `ports`, `routers`.
- `internal/metadata/` `ShardedMetadataMap` (64 shards, `sync.RWMutex` per shard) keyed by MAC. Value = `*TenantMeta{ProjectID, VMName, IsAmphora, DeleteAt}`. Pointer-replace invariant enforced by a unit test (closes the §13.1 #3 risk-of-mutation early).
- ABI: extend `internal/bpf/abi.go` with `MapSubnetZoneTrie`, `MapMacTenant`, and the `LpmKey` writer helpers.
- **Map size bump in `bpf/telemetry.c`**: `mac_tenant_map` 1024 → 8192, `subnet_zone_trie` 4096 → 16384 (matches DESIGN §3.1; the current values are flagged there as too tight for production).
- Trie builder steps 1–4 per §5.2 (catchall → owned → shared → infra). Step 5 stubbed to no-op (returns `EXTERNAL`).
- Broadened `device_owner` filter in step 4 to cover OVN values (`network:distributed`, `network:router_interface`, `network:router_gateway`) — no separate DVR/chassis enumeration step needed; logical routers have a single MAC across all OVN chassis (see DESIGN.md §B.8 OVN paragraph).
- Map writers: push the trie and `mac_tenant_map` into the kernel before TC attach (boot order §9 step 3).
- Boot order rework in `internal/agent/bootstrap_linux.go`: insert "fetch Neutron metadata → populate userspace `ShardedMetadataMap` → push to kernel maps" BEFORE `attachIfRequested`. Boot blocks with exponential backoff (1s → 30s cap, indefinite retries) if Neutron is unreachable, per DESIGN §9 fail-closed policy. The formal explicit-sync-point harness — Implementation Contract #4 — stays in Sprint 5; this sprint only gets the ordering right.
- Tenant resolver swap: replace `metrics.UnknownTenant{}` in `internal/agent/agent.go` with a resolver backed by `ShardedMetadataMap`. The Collector then emits real `tenant_id` strings (project_id UUIDs) instead of `"unknown"`.
- Health metrics from §11.4: `cubecos_neutron_sync_age_seconds`, `cubecos_neutron_api_errors_total{endpoint, code}`, `cubecos_bpf_map_fill_ratio{map="trie|mac_tenant"}`, `cubecos_bpf_map_max_entries{map=...}`.
- Grafana panels (per the visualization table above): Neutron-sync detail — sync age, port population rate, builder step durations. Land as `deploy/grafana/dashboards/30-neutron.json`.
- Golden-file unit tests on recorded Neutron API responses for scenarios A, B, C, D, E, F, I, J.

**Done when.**
- All single-hop scenarios (A, B, C, D, E, F, I, J) classify correctly in fixture tests.
- Agent boots against the real 3-chassis OVN Yoga cluster; `/metrics` shows non-empty `cubecos_bytes_total{tenant_id=<real-UUID>,...}` series (no `unknown` for tenants with active VMs).
- `cubecos_neutron_sync_age_seconds` < 60 in steady state.
- Stopping the Neutron API blocks boot with backoff (verified by log + `cubecos_neutron_api_errors_total`); recovery completes once the API returns.

**LOC.** ~900.

**Risk.** Medium. Largest piece is the boot-order rework — touches `bootstrap_linux.go` and the shape of `Bootstrap` itself. Within 4a, land the resolver swap first to derisk, then the map-write path, then the boot-order glue.

---

## Sprint 4b — Static-route resolver + scenario harness [planned split, part 2 of 2]

**Goal.** Close the cold-start algorithm — multi-hop static routes resolve correctly. After this sprint, scenarios A–L are all green.

**Scope.**
- Step 5 resolver in `internal/neutron/` per §5.3: iterative graph walk with `MAX_HOPS=16`, `visited` set for cycle detection, `zone_for` helper for VM-appliance nexthops.
- Strict-mode failure policy on ambiguity-after-scoping (§5.6): log + refuse to start. Operator override flag `--unsafe-allow-ambiguous-routes` falls back to `EXTERNAL` and continues.
- **Scenario DSL** (deferred from Sprint 0.5 per Group C). Lives at `internal/testenv/scenario/`. Declarative format: list of (tenant, network, subnet, router, port) primitives; the DSL emits the synthetic Neutron API responses the builder consumes. Replaces ad-hoc JSON fixtures from 4a.
- Golden-file scenario tests for G (single-hop static), K (5-router multi-hop chain), L (VM-appliance nexthop). Migrate the 4a fixture-based scenarios onto the DSL so all of A–L share one harness.
- End-to-end verification on the 3-chassis OVN Yoga cluster: cross-host scenarios (J) exercised; multi-chassis path explicitly hit and recorded in the test log.
- `cubecos_neutron_builder_step_duration_seconds` histogram (per-step timing, useful when route resolution is slow on big deployments).

**Done when.**
- All scenarios A–L green via the scenario DSL.
- Multi-hop K trace logged at debug level matches the §5.5 worked example step-by-step (hop count, peer router IDs, final `zone_for` call).
- 3-chassis OVN cluster: a tenant whose router has an `extraroutes` entry pointing through a peer tenant's router shows the correct `OTHER_TENANT` zone on `/metrics`.
- Cycle-injection test (R2 → R3 → R2) terminates and logs the cycle.

**LOC.** ~600.

**Risk.** Medium. The trace itself is mechanical, but the scenario DSL is new infrastructure — keep it minimal (just enough for A–L); resist generalising. Multi-chassis verification surfaces edge cases that don't appear in single-node OVN, which is why the cluster gate sits here, not in 4a.

---

## Sprint 4c — Trie dedup for global zone entries

**Goal.** Decouple `subnet_zone_trie` cardinality from tenant count. Today every tenant gets its own copy of every catchall / INFRA / SHARED row; only the SAME_TENANT rows are genuinely per-tenant. Verified empirically (27-tenant test deployment): 9270 of 9270 entries observed, of which ≈340 per tenant are global — i.e. ~96% replication. At realistic production tenant counts (≥200) the current model overflows the 16384 trie cap and hard-fails at boot via `bpf.ValidateMapSizes`. After this sprint, trie size is O(G + Σ O_t) instead of O(T × (G + O_t)), where G = global prefixes and O_t = the per-tenant SAME_TENANT prefixes.

**Shape (locked in slice 1).** Sentinel `tenant_id=0` rows in the existing `subnet_zone_trie`: cold-start writes catchall / INFRA / SHARED rows once with `tenant_id=0`; only SAME_TENANT rows replicate per tenant. The hot path adds one `bpf_map_lookup_elem` on first-lookup miss. Picked over a split-map alternative because pin-path / `ValidateMapSizes` / `LpmKey` surface area stays single-map, and `tenant_id=0` is already reserved by `metadata.TenantIDUnset` (interner starts at 1, so 0 is a natural "applies to all tenants" sentinel). The split-map alternative would have given a marginally cleaner data model at the cost of doubling kernel-ABI surface for a confined optimization. The product is pre-release and the agent does not pin maps today (`grep -rn "m\.Pin\|LoadPinned"` returns nothing outside `internal/config`), so the original §4c "pin-path / map-name bump + boot-time refusal-to-reuse" mitigation is dropped — no v1 pin exists to migrate against.

**Scope.**
- Update `internal/neutron/trie.go BuildTrie`: catchall (Step 1), shared (Step 3), and infra (Step 4) rows emit once with `TenantID=""` (resolved to `metadata.TenantIDUnset` by the writer); owned (Step 2) and extraroutes (Step 5) stay per-tenant.
- Update `bpf/telemetry.c` `lookup_zone()` to add the sentinel fallback `bpf_map_lookup_elem` on first-lookup miss, with a verifier-acceptable shape (re-key the same `lpm_key` with `tenant_id = 0`, look up again, return the zone or `ZONE_MISS`).
- Update `internal/kernelwriter` to honor the new emission rules (empty `TenantID` → `TenantIDUnset` instead of skip-with-warn).
- `internal/bpf/abi.go`: `MapSubnetZoneTrieMaxEntries` stays at 16384. Headroom is cheap on an `LPM_TRIE` with `BPF_F_NO_PREALLOC` and absorbs future per-tenant SAME_TENANT growth without another `task generate` cycle.
- Benchmark: add `BenchmarkHotpath_LpmFallback_*` for the two-lookup path; gate via `task bench-gate`. Target delta: <50 ns on the routed-fallback path vs the Sprint 4a baseline (MAC-first hot path is unchanged and must stay flat).
- Migrate scenario tests A–L (from the Sprint 4b scenario DSL) to assert the new emission pattern: each global prefix appears exactly once with `TenantID=""`, each SAME_TENANT prefix exactly per-owning-tenant.

**Slice plan.**

1. Design pin in this doc + `DESIGN.md` §3.1; no code change. (~30 LOC docs.)
2. `BuildTrie` + scenario-DSL emission-uniqueness assertions + writer change. (~150 LOC.)
3. C-side two-lookup `lookup_zone` + `task generate` + `BenchmarkHotpath_LpmFallback_*`. (~80 LOC C + bench.)
4. dev-cmp smoke; trie count drops from 14252 → <1k. cc-cluster 3-chassis check folded in if access is easy.

**Done when.**
- Single-host smoke against a real OVN deployment: trie entry count drops from ~14k → <1k.
- 3-chassis OVN cluster smoke: trie entries <1k regardless of host count — proves per-host independence at cluster scale (host count never multiplied trie size to begin with, but the test demonstrates it explicitly).
- `task bench-gate` passes within the 50 ns budget on the routed-fallback path; the MAC-first hot path remains at the Sprint 4a baseline.
- Scenarios A–L still green via the Sprint 4b DSL, plus new emission-uniqueness assertions.

**LOC.** ~250 (was ~400 before the pin-path-migration slice was dropped).

**Risk.** Low. Confined to the trie data model; orthogonal to Sprint 4b's static-route resolver. The two-lookup pattern is a well-trodden verifier shape (Cilium `pkg/maps` uses it). No pin reuse to migrate against (pre-release, agent doesn't pin maps today).

---

## Sprint 5 — Boot sync machinery + Zombie Hunter + Netlink Watcher

**Goal.** Promote the boot-order ordering 4a wired into `Bootstrap` into an inspectable, explicit-sync-point machine; replace the single static `BPFConfig.AttachInterface` with netlink-driven dynamic attach.

**Scope.**
- `internal/boot/`: sequenced phase machine that validates the step-by-one phase order and logs each transition. **Decision (this stage): kept straight-line, not a cross-goroutine barrier.** `Bootstrap` advances every phase inline in one goroutine and returns before `Run` spawns the scraper/WAL/netlink consumers, so the ordering (Implementation Contract #4) holds structurally — see DESIGN §13.1. Promoting `Sequencer` to channel-backed `Await`/`Fail` sync gates is deferred to when Kafka (Sprint 7) and GC (Sprint 6) advance/await phases from their own goroutines and actually need to block on a named gate (DESIGN §13.2 #3) — building the barrier now would be machinery with no concurrent caller.
- `internal/zombie/`: scan `tc filter` for orphan `tc_telemetry_in/out`, delete on startup.
- `internal/netlink/`: subscribe to `RTM_NEWLINK/DELLINK`; attach BPF on new taps, clean registry on delete.
- Interface Registry: in-memory map of attached taps.
- Deprecate `BPFConfig.AttachInterface` (currently a single static string in `internal/config/bpf.go:19`) in favour of the Netlink Watcher's tap-discovery loop. Keep the field for one release with a deprecation log; remove in a follow-up. **Done (2026-06-01):** the follow-up landed — the field, its `attach_interface` YAML key, its env/flag bindings, and the static-attach boot step are removed; dynamic attach via the netlink subscriber's allowlist is now the only path.
- Health metrics: `cubecos_zombie_filters_cleaned_total`, `cubecos_tc_attach_failures_total{iface_kind="tap|other"}`.

**Done when.** Crash-then-restart leaves no double-attach (verified by `tc filter show` + `cubecos_zombie_filters_cleaned_total>0`); new tap appears → BPF attached automatically with <1s latency; `boot.Sequencer` rejects a skipped/rewound `Advance` (negative test in `internal/boot/`). The cross-goroutine sync-gate tests ship with the barrier itself when it lands (DESIGN §13.2 #3).

**LOC.** ~500 (originally ~450; +50 for the `AttachInterface` deprecation + sync-point formalization on top of the ordering 4a already established).

---

## Sprint 6 — Lingering Ghost + UnresolvedBuffer + Pressure-Relief GC

**Goal.** Eviction with no byte loss, capped buffers.

**Scope.**
- **Lingering Ghost**: on `port.deleted` / `subnet.deleted`, set `DeleteAt=now+60s` on the userspace `ShardedMetadataMap` entry only. **Do NOT delete from kernel `mac_tenant_map` yet.** Sweep every 60s; expired entries deleted kernel-first, then userspace (closes §13.1 Contract #6). Insertions follow the reverse order: userspace-then-kernel. **Ghost precedence over UnresolvedBuffer** (DESIGN §3.3): a ghosted MAC is still a hit on both maps; packets matching it attribute to the ghosted tenant, never to UnresolvedBuffer. Encoded as an explicit "check ghost first" branch in the resolver, plus a unit test that fails if the order is inverted.
- **UnresolvedBuffer**: cap=10k LRU + 60s expiry → `tenant=unknown` (closes Implementation Contract #1).
- **Pressure-Relief GC**: trigger 80% / floor 75% / 1k cap per pass. Always flush to GlobalState **before** delete. **Algorithm per DESIGN §3.1**: single-pass scan + min-heap of size K=1000 tracking oldest-K by `last_seen_ns`. Cost O(N log K) — implementer must not regress to O(N log N) full-sort (the difference is ~50 ms vs ~200 ms per pass at N=52k).
- Health metrics: `cubecos_unresolved_buffer_depth`, `cubecos_unresolved_buffer_evictions_total{reason="lru|expired"}`, `cubecos_unresolved_resolved_total`, `cubecos_gc_evictions_total{reason="ttl|pressure_relief"}`, `cubecos_lingering_ghosts_active`, `cubecos_gc_pressure_relief_runs_total`, `cubecos_bpf_map_fill_ratio{map="telemetry"}` (sampled at the start of each scrape — the GC's own trigger source), `cubecos_collect_duration_seconds` histogram.

**Done when.** Stress test with 100k unknown MACs → buffer holds at 10k, no OOM, no negative `rate()`. Stress test that fills the BPF map → fill ratio drops below 75% within 4 scrapes. Ghost-precedence inversion test fails the build if a future refactor checks UnresolvedBuffer before the ghost.

**LOC.** ~450 (originally ~400; +50 for the precedence test + min-heap algorithm spec + collect-duration histogram).

---

## Sprint 7 — Kafka live updates + Neutron reconcile safety net

**Goal.** Trie + MAC map track Neutron in real time; survive Kafka outages with bounded staleness.

**Scope.**
- `internal/kafka/` consumer for `port.*`, `subnet.*`, `router.*`.
- Incremental trie diff (NOT full rebuild) — only re-resolve affected tenants. Insert-then-delete ordering per DESIGN §5.7 (deleting first creates a permanent-miskey window because `dst_zone` is baked into the kernel flow key).
- **Periodic Neutron reconcile every 5 minutes** (DESIGN §9 Kafka-outage safety net). Full snapshot fetch + diff against current state; differences applied as if Kafka had delivered them. Bounds metadata staleness to 5 minutes regardless of Kafka availability. Runtime reconcile is best-effort per endpoint (a 500 on `routers` doesn't invalidate `ports`).
- Harden the TenantMeta-immutable invariant test that 4a planted: add negative tests that mutate fields and confirm the lint catches them (closes Implementation Contract #3). The detection mechanism itself moves to Sprint 9's lint coverage sweep.
- Kafka health metrics: `cubecos_kafka_lag_messages{topic}`, `cubecos_kafka_consume_errors_total{topic}`. Internal-error sink: `cubecos_internal_errors_total{subsystem="kafka"}` on consume failures per the cross-cutting pattern.

**Done when.** Recorded Kafka stream replay against a known-state cluster → trie matches a fresh cold-start at the same point in time. Kill Kafka for >5 minutes → `cubecos_neutron_sync_age_seconds` resets to <300 after each reconcile pass; Kafka resumed → trie converges within one consume cycle.

**LOC.** ~600 (originally ~500; +100 for the 5-minute reconcile + per-endpoint failure isolation).

---

## Sprint 8 — Octavia LB attribution (kernel-side)

**Goal.** Implement the two-segment Octavia model per the revised §6 (post-empirical-verification finding).

**Scope.**
- New sidecar BPF map `amphora_meta` keyed by Amphora MAC, value = `{LBOwnerTenant u32, _pad}`. **Deliberately not extending `mac_tenant_map`'s value** — keeping its `u32 tenant_id` schema avoids a kernel-ABI break and lets the kernel test `bpf_map_lookup_elem(&amphora_meta, &peer_mac)` as a cheap "is Amphora?" probe.
- `internal/octavia/` API client (distinct from the Neutron client built in 4a — Octavia is a separate OpenStack service with its own endpoint and pagination semantics).
- Cold-start enumeration: query Octavia API, walk Amphora VMs, write each Amphora's MAC + LB-owner tenant into `amphora_meta`. Run after the Neutron cold-start of 4a so the regular `mac_tenant_map` entry for the Amphora's admin tenant is already in place.
- Kernel attribution path: when `peer_mac` is flagged Amphora → attribute bytes to `LBOwnerTenant` instead of Amphora's own admin tenant. Works at every tap, no conntrack required.
- Kernel zone path: at the Amphora's tap (Segment 1), call `bpf_skb_ct_lookup` to recover the pre-NAT client_ip and refine `dst_zone` (EXTERNAL / OTHER / SAME); fall back to EXTERNAL on miss. At the backend's tap (Segment 2), unconditionally set `dst_zone=INFRA` — **do not call `bpf_skb_ct_lookup` there**, it would return Segment 2's entry with no client_ip.
- Distinguishing "at the Amphora's tap" vs "at the backend's tap" in the kernel: at the Amphora's tap, `vm_mac` (the local VM) IS the Amphora's MAC, so `amphora_meta[vm_mac]` hits; at the backend's tap, `amphora_meta[peer_mac]` hits but `amphora_meta[vm_mac]` misses. The kernel keys off this asymmetry.
- Kafka updates: handle Amphora creation/deletion + LB ownership changes incrementally via the Sprint 7 consumer (`loadbalancer.*` topic).

**Done when.** End-to-end test on a deployment with at least one active Octavia LB: external traffic through the LB is billed to the LB owner (not admin); Segment 1 zone reflects the actual client; Segment 2 zone is INFRA; both segments visible at both taps as expected; UDP-protocol LB sparse-traffic edge case documented and accepted.

**LOC.** ~400 (originally ~350; +50 for the two-tap-asymmetry logic in the kernel and the Octavia-API client at cold-start).

**Risk register update.** The original "bpf_skb_ct_lookup behavior depends on conntrack timing" concern is now narrower in scope — it only affects Segment 1 zone refinement, not the LB-owner attribution. Severity drops from Medium to Low.

---

## Sprint 9 — Hardening + Implementation Contract verification + Ops README

**Goal.** Production-readiness sweep. Verify all five §13.1 contracts are held by tests, close the zero-allocation gate on the remaining hot paths, and ship the ops doc.

**Scope.**
- **Verification, not initial wiring.** Contracts #2 (RLock around `Collect()`) and #5 (u64 wraparound in delta math) are already in `internal/state/state.go` (landed Sprint 2 — see `Snapshot` at state.go:113 and `addDelta` at state.go:97). Contract #1 lands in Sprint 6, #3 in Sprints 4a + 7, #4 in Sprints 4a + 5, #6 in Sprint 6. This sprint's job is to confirm each contract has a test that **fails** when the contract is broken (negative tests), not to write the contracts themselves.
- **Close the bench-gate gap.** `BenchmarkHotpath_ApplyDelta` and `BenchmarkHotpath_Snapshot` exist (`internal/state/bench_test.go`) and run under `task bench-gate` today. Add `BenchmarkHotpath_Collect` (in `internal/metrics/`) and `BenchmarkHotpath_BatchLookupAndProcess` (in `internal/scraper/` against a synthetic `MapReader`) — these were promised by Sprint 2's done-when but never written.
- **Internal-error-sink coverage lint.** Each subsystem (4a Neutron, 5 TC attach, 6 GC, 7 Kafka) already wires its own `cubecos_internal_errors_total{subsystem=…}`. This sprint adds a `go vet`-style lint (or AST walker) that fails the PR if a `slog.Error` in a billing-path package isn't accompanied by the counter increment. Lives at `scripts/lint-error-sink.sh` and runs in CI.
- **Ops README**: deployment, troubleshooting, dashboards, alert rules. Moved here from Sprint 10 — by the time IPv6 lands in 10 the system is already in production, so an ops README written then is overdue. Lives at `docs/ops.md`.

**Done when.** All five §13.1 Implementation Contracts have a corresponding negative test. `BenchmarkHotpath_Collect` and `BenchmarkHotpath_BatchLookupAndProcess` exist and report `0 allocs/op` under `task bench-gate`. The internal-error-sink lint catches a deliberately broken commit on a test branch. Ops README walked through by an engineer who didn't write the code.

**LOC.** ~350 (originally ~200; +150 for the two missing benches + the error-sink lint + ops README — none of which were in scope when 9 was just "wire contracts #2 and #5", which is now retroactively recognized as Sprint 2's work).

---

## Sprint 10 — IPv6 [post-MVP]

**Goal.** Close the only §13.2 deferred work. Ops README moved to Sprint 9 — by the time this sprint runs the system is already in production.

**Scope.**
- New v6 LPM trie keyed `(tenant_id, u8[16])`.
- Branch in `lookup_zone()` on `eth_proto`.
- Cold-start emits v6 entries alongside v4.
- Update directional swap for v6 (read different IP fields).

**Done when.** v6 traffic in scenarios A, B, D classifies correctly. Existing v4 paths unchanged (verified by re-running the A-L scenario suite from 4b).

**LOC.** ~350 (originally ~400; -50 with ops README out of scope).

---

## Cadence

If sprint = 1 calendar week, total: ~13 weeks (Sprint 0 done + 11 sprints + 1 buffer). With Sprint 4 split into 4a + 4b, the original double-time slot folds into two normal-cadence sprints; Sprint 4c adds one more slot for the trie dedup surfaced by the 4a live smoke.

## Risk register

| Sprint | Risk | Reason |
|---|---|---|
| 4a | Medium | Boot-order rework in `bootstrap_linux.go`; Neutron API edge cases (deleted-but-cached entries, paginated responses, address-scope semantics); first PR to write the trie + `mac_tenant_map` from userspace |
| 4b | Medium | Multi-hop static-route resolver edge cases (cycles, VM-appliance nexthops, ambiguity-after-scoping); scenario DSL is new infrastructure; multi-chassis OVN verification surfaces cross-host issues that don't appear single-node |
| 4c | Low | Confined to the trie data model; two-lookup verifier shape is a known Cilium pattern. No pin reuse to migrate against (pre-release, agent doesn't pin maps today), so the original pin-path-migration slice is dropped |
| 5 | Low | Boot-sync-machinery formalizes ordering that already works after 4a; risk concentrated in netlink lifecycle (RTM_NEWLINK race with the initial sweep — mitigated by ordering the netlink subscribe BEFORE the initial sweep, per DESIGN §9 failure-modes table) |
| 6 | Medium | Pressure-relief GC must never delete before flushing to GlobalState; min-heap K=1000 algorithm has subtle correctness boundary at exactly the K-th oldest entry; ghost-precedence invariant is silent on violation (under-billing, not crash) |
| 7 | Medium | Incremental diff has subtle race with cold-start; replay tests need careful fixture engineering; 5-minute reconcile diff against in-memory state has its own race window with concurrent Kafka events |
| 8 | Low | Attribution-to-LB-owner uses MAC-flag (no conntrack dependency). Segment 1 zone refinement uses `bpf_skb_ct_lookup` which can miss, but fallback to EXTERNAL is the safe-billing default and doesn't affect attribution. See revised §6 |
| 9 | Low | Verification work, not new subsystems. Bench-gate additions could surface latent allocations in Collect that need a refactor — mitigated by landing the benches incrementally |
| 10 | Low | Mechanical retrofit; risk only if v6 happens to expose a latent v4 assumption in the directional-swap code |

## Dependency graph

```
                    ┌──► 2 (state+collector) ──► 3 (WAL) ──► 4a (Neutron foundations) ──► 4b (static routes) ──► 4c (trie dedup) ──► 5 (boot) ──► 6 (GC) ──► 7 (Kafka) ──► 8 (Octavia) ──► 9 (harden) ──► 10 (v6)
1 (kernel) ─────────┤
                    └──► (smoke test slice for one hardcoded VM at end of Sprint 3)
```

Sprints 1, 2, 3 can technically interleave; the linear ordering above gives a working billing-grade slice for one hardcoded VM at the end of Sprint 3 — useful as an early demo and smoke test before the Neutron complexity lands in Sprint 4a. Sprint 4b stays a hard dependency of Sprint 5: the boot-sequence harness assumes the trie is fully populated. Sprint 4c is a hard dependency of Sprint 7 (Kafka live updates) — incremental diffs against a deduplicated trie are a different algorithm than against the per-tenant-replicated trie, and it is cheaper to land them on the post-4c shape than to migrate the diff code later.

---

*Last updated: 2026-05-19 (Sprint 4c slice 1: locked sentinel `tenant_id=0` shape; dropped the pin-path-migration slice — pre-release product, agent doesn't pin maps today, so no v1 pin to refuse-reuse against; `MapSubnetZoneTrieMaxEntries` stays at 16384 for headroom; LOC re-estimated 400 → 250).*
