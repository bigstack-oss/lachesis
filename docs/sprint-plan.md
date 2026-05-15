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

## Sprint 4 — Neutron cold-start [the big one]

**Goal.** Populate `mac_tenant_map` + `subnet_zone_trie` from Neutron v2.0.

**Scope.**
- `internal/neutron/` HTTP client with Keystone auth.
- `ShardedMetadataMap` (64 shards).
- 5-step trie builder per §5.2 (catchall → owned → shared → infra → static routes).
- Iterative static-route resolver with cycle detection + `MAX_HOPS=16`.
- Broadened `device_owner` filter in Step 4 to cover OVN values (`network:distributed`, `network:router_interface`, `network:router_gateway`) — no separate DVR/chassis enumeration step needed; logical routers have a single MAC across all OVN chassis (see DESIGN.md §B.8 OVN paragraph).
- Push to BPF maps before TC attach (boot order §9 step 3).
- Golden-file tests on recorded API responses for scenarios A–L.

**Done when.** All scenarios A–L from §7 produce correct zones in a fixture-based unit test. Verified end-to-end against a real OVN Yoga cluster with ≥3 chassis — cross-host scenarios exercise the multi-chassis path.

**LOC.** ~900.

**Risk.** Largest PR in the plan. If it grows past ~1,200 lines, split into:
- **4a** — HTTP client + ShardedMetadataMap + simple builder (steps 1–4).
- **4b** — Static-route resolver (step 5).

---

## Sprint 5 — Boot sequence + Zombie Hunter + Netlink Watcher

**Goal.** The 10-step boot order in code, not just docs.

**Scope.**
- `internal/boot/`: sequenced steps with explicit sync points (closes Implementation Contract #4).
- `internal/zombie/`: scan `tc filter` for orphan `tc_telemetry_in/out`, delete on startup.
- `internal/netlink/`: subscribe to `RTM_NEWLINK/DELLINK`; attach BPF on new taps, clean registry on delete.
- Interface Registry: in-memory map of attached taps.

**Done when.** Crash-then-restart leaves no double-attach (verified by `tc filter show`); new tap appears → BPF attached automatically with <1s latency.

**LOC.** ~450.

---

## Sprint 6 — Lingering Ghost + UnresolvedBuffer + Pressure-Relief GC

**Goal.** Eviction with no byte loss, capped buffers.

**Scope.**
- **Lingering Ghost**: on `port.deleted` / `subnet.deleted`, set `DeleteAt=now+60s` on the userspace `ShardedMetadataMap` entry only. **Do NOT delete from kernel `mac_tenant_map` yet.** Sweep every 60s; expired entries deleted kernel-first, then userspace (closes §13.1 Contract #6). Insertions follow the reverse order: userspace-then-kernel.
- **UnresolvedBuffer**: cap=10k LRU + 60s expiry → `tenant=unknown` (closes Implementation Contract #1).
- **Pressure-Relief GC**: trigger 80% / floor 75% / 1k cap per pass. Always flush to GlobalState **before** delete.
- Health metrics: `cubecos_unresolved_buffer_depth`, `cubecos_gc_evictions_total`, `cubecos_lingering_ghosts_active`, `cubecos_gc_pressure_relief_runs_total`.

**Done when.** Stress test with 100k unknown MACs → buffer holds at 10k, no OOM, no negative `rate()`. Stress test that fills the BPF map → fill ratio drops below 75% within 4 scrapes.

**LOC.** ~400.

---

## Sprint 7 — Kafka live updates

**Goal.** Trie + MAC map track Neutron in real time.

**Scope.**
- `internal/kafka/` consumer for `port.*`, `subnet.*`, `router.*`.
- Incremental trie diff (NOT full rebuild) — only re-resolve affected tenants.
- Enforce TenantMeta-immutable invariant in code: pointer replace, never field mutate (closes Implementation Contract #3). Helper function + unit test that fails if any path mutates a `TenantMeta` after creation.
- Kafka health metrics: `cubecos_kafka_lag_messages`, `cubecos_kafka_consume_errors_total`.

**Done when.** Recorded Kafka stream replay against a known-state cluster → trie matches a fresh cold-start at the same point in time.

**LOC.** ~500.

---

## Sprint 8 — Octavia LB attribution (kernel-side)

**Goal.** Implement the two-segment Octavia model per the revised §6 (post-empirical-verification finding).

**Scope.**
- `IsAmphora` flag + `LBOwnerTenant` in `mac_tenant_map` metadata (sidecar map keyed by Amphora MAC).
- Cold-start enumeration: query Octavia API, walk Amphora VMs, write each Amphora's MAC + LB-owner tenant into the map.
- Kernel attribution path: when `peer_mac` is flagged Amphora → attribute bytes to `LBOwnerTenant` instead of Amphora's own admin tenant. Works at every tap, no conntrack required.
- Kernel zone path: at the Amphora's tap (Segment 1), call `bpf_skb_ct_lookup` to recover the pre-NAT client_ip and refine `dst_zone` (EXTERNAL / OTHER / SAME); fall back to EXTERNAL on miss. At the backend's tap (Segment 2), unconditionally set `dst_zone=INFRA` — **do not call `bpf_skb_ct_lookup` there**, it would return Segment 2's entry with no client_ip.
- Distinguishing "at the Amphora's tap" vs "at the backend's tap" in the kernel: at the Amphora's tap, `vm_mac` (the local VM) IS the Amphora's MAC, so `vm_mac.IsAmphora==true`; at the backend's tap, `peer_mac.IsAmphora==true` but `vm_mac.IsAmphora==false`. The kernel keys off this asymmetry.
- Kafka updates: handle Amphora creation/deletion + LB ownership changes incrementally.

**Done when.** End-to-end test on a deployment with at least one active Octavia LB: external traffic through the LB is billed to the LB owner (not admin); Segment 1 zone reflects the actual client; Segment 2 zone is INFRA; both segments visible at both taps as expected; UDP-protocol LB sparse-traffic edge case documented and accepted.

**LOC.** ~400 (originally ~350; +50 for the two-tap-asymmetry logic in the kernel and the Octavia-API client at cold-start).

**Risk register update.** The original "bpf_skb_ct_lookup behavior depends on conntrack timing" concern is now narrower in scope — it only affects Segment 1 zone refinement, not the LB-owner attribution. Severity drops from Medium to Low.

---

## Sprint 9 — Hardening + Implementation Contract burndown

**Goal.** Production-readiness sweep — close all five §13.1 contracts.

**Scope.**
- RLock around the entire `Collect()` loop (closes Implementation Contract #2).
- u64 wraparound guard in delta math (closes Implementation Contract #5).
- Zero-allocation verified by `go test -bench -benchmem` on `Collect()` and `BatchLookupAndProcess()` — fail PR if any allocation appears.
- TenantMeta pointer-replace lint test from Sprint 7 hardened (negative tests).
- Internal error sink: `cubecos_internal_errors_total{subsystem}` wired everywhere a billing-path error is logged (see DESIGN.md §13.1).

**Done when.** All five §13.1 Implementation Contracts have a corresponding test that fails if the contract is broken. Bench job in CI gates merge.

**LOC.** ~200.

---

## Sprint 10 — IPv6 + ops polish [post-MVP]

**Goal.** Close the only §13.2 deferred work.

**Scope.**
- New v6 LPM trie keyed `(tenant_id, u8[16])`.
- Branch in `lookup_zone()` on `eth_proto`.
- Cold-start emits v6 entries alongside v4.
- Update directional swap for v6 (read different IP fields).
- Ops README: deployment, troubleshooting, dashboards, alert rules.

**Done when.** v6 traffic in scenarios A, B, D classifies correctly. README walked through by an engineer who didn't write the code.

**LOC.** ~400.

---

## Cadence

If sprint = 1 calendar week, total: ~12 weeks (Sprint 0 done + 10 sprints + 1 buffer). Sprint 4 is the natural place for double-time.

## Risk register

| Sprint | Risk | Reason |
|---|---|---|
| 4 | High | Largest PR; Neutron API edge cases (deleted-but-cached entries, paginated responses, address-scope semantics); validating against both single-node and multi-node OVN deployments |
| 7 | Medium | Incremental diff has subtle race with cold-start; replay tests need careful fixture engineering |
| 8 | Low | Attribution-to-LB-owner uses MAC-flag (no conntrack dependency). Segment 1 zone refinement uses `bpf_skb_ct_lookup` which can miss, but fallback to EXTERNAL is the safe-billing default and doesn't affect attribution. See revised §6 |
| Others | Low | Mechanical and well-bounded |

## Dependency graph

```
                    ┌──► 2 (state+collector) ──► 3 (WAL) ──► 4 (Neutron) ──► 5 (boot) ──► 6 (GC) ──► 7 (Kafka) ──► 8 (Octavia) ──► 9 (harden) ──► 10 (v6)
1 (kernel) ─────────┤
                    └──► (smoke test slice for one hardcoded VM at end of Sprint 3)
```

Sprints 1, 2, 3 can technically interleave; the linear ordering above gives a working billing-grade slice for one hardcoded VM at the end of Sprint 3 — useful as an early demo and smoke test before the Neutron complexity lands in Sprint 4.

---

*Last updated: 2026-05-14 (added Sprint 2+ Grafana dashboard track).*
