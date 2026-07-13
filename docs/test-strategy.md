# Test Strategy — CubeCOS Network Telemetry

> Three tiers — unit, integration, performance — one rule each. The canonical reference for how tests are organized and run. If a test category isn't covered here, it's either deferred work or a gap worth surfacing.

The infrastructure was built in Sprint 0.5 specifically so Sprints 1–10 plug into it instead of re-inventing harnesses per PR.

---

## Tier 1 — Unit tests

**Goal.** Verify pure-Go logic and BPF kernel paths in isolation, no real network.

**Where.**
- Go logic: `*_test.go` files alongside the production code in each package.
- BPF programs: `internal/testenv/bpfunit/` and any test that exercises `Driver.Run` / `Driver.RunRepeat`.

**Build tags.**
- Pure Go tests: no tags. Run on every host. `task test`.
- BPF tests: `//go:build integration`. Require Linux + CAP_BPF. `task test-integration`.

**Dependency injection.** Production code that touches the kernel, Neutron, or the filesystem should define seam interfaces (`MapReader`, `NeutronClient`, `Clock`, etc.) so unit tests swap real impls with in-memory mocks. Interfaces live with their consuming packages, not in a central seams package.

---

## Tier 2 — Integration / e2e tests

**Goal.** Verify the full kernel↔userspace pipeline against real Linux semantics: real namespaces, real veth interfaces, real TCP connections, real BPF TC attach.

**Where.**
- `internal/testenv/netns/` — namespace + veth lifecycle helpers (`New`, `Close`, `Do`, `AddVeth`, `AttachBPF`)
- `internal/testenv/traffic/` — TCP traffic generation via `net.Dial` from inside a namespace
- `internal/testenv/e2e/` — composed scenarios

**Build tags.** `//go:build integration` and `//go:build linux`.

**How to run.** `task test-integration`. The target wraps the privileged Docker invocation (`--privileged -u 0 -e GOWORK=off`) so devs don't have to remember flags.

**Why Docker.** macOS dev hosts can't load BPF directly, and CI runners need a deterministic kernel + toolchain. The Dockerfile-built `ebpf-builder` image is the canonical Linux environment for all kernel-touching tests.

**Known limitations.**
- Timing measurements under Rosetta (Apple Silicon emulating linux/amd64) report near-zero ns due to clock resolution. Use `perfbench` on native x86 Linux for real numbers.
- Scenario DSL is deferred to Sprint 4. Until then, e2e tests are plain table-driven Go — perfectly readable for the few we have.

---

## Tier 3 — Performance tests

**Goal.** Verify CPU and memory budgets from DESIGN §11.

### ns/packet via `perfbench`

`cmd/perfbench` drives `BPF_PROG_TEST_RUN` with a configurable repeat count and reports kernel-measured time.

```sh
task perfbench                                          # default: 1M repeats, human output
task perfbench -- -output json -repeat 100000000        # JSON for CI ingestion
```

DESIGN §11 target: **~150 ns/packet**. Sprint 1 produces the first real number on a real OVN compute node.

### Zero-allocation gate

Hot-path code (`Collect()`, scraper, packet handlers) must allocate zero memory per call to keep GC pressure off the 15s scrape rate.

**Convention:**
- `BenchmarkHotpath_<Name>` → gated; must report `0 allocs/op`. CI fails the PR if violated.
- `Benchmark_<Name>` → informational, no gate.

**Status:** currently dormant. Sprint 2 lands the first `BenchmarkHotpath_*` benchmarks (`Collect`, `BatchLookupAndProcess`). Run via `task bench-gate`.

### Throughput delta (manual, today)

iperf3-measured BPF overhead is documented in DESIGN §12 ("Demo Workflow"). Not automated; Sprint 9 may wrap as a Taskfile target.

### Load test (deferred to Sprint 2)

`cmd/loadtest` — synthesizes sustained traffic, samples `/proc/<pid>/{stat,status}`, asserts RSS/CPU thresholds — was originally planned for Sprint 0.5 but moved to Sprint 2 where the agent binary first lands. Building load-test infrastructure without an agent to load-test is infra for absent code.

---

## Tier 4 — Live-cluster validation

**Goal.** Verify per-tenant / zone / direction byte attribution end to end against a **real OVN cluster** — the automated form of the deploy → traffic → scrape → assert → teardown loop previously run by hand on staging every sprint. Tiers 1–3 prove the pipeline in isolation; Tier 4 proves it against live OpenStack, and de-risks the Octavia billing path by giving it a repeatable live-assertion harness.

**Where.** `cmd/scenariotest` (the operator-run binary) and `internal/scenariotest` (the library). Scenarios are declarative Go literals under `cmd/scenariotest/scenarios/`, one per file. The registered set covers all five billing zones — `same_tenant`, `infra`, `external`, `shared`, `other_tenant` — mirroring the proven in-memory topologies in `internal/neutron/scenarios_test.go`.

**Lifecycle.** Subcommands compose the loop:

| Subcommand | Does |
|---|---|
| `list` | Show registered scenarios. |
| `preflight <name>` | Read-only: verify prerequisites (image, flavor, keypair, secgroup, external network), validate any pinned hypervisors, confirm each agent's `/metrics` is reachable and exposes `cubecos_bytes_total` + `cubecos_attached_interfaces`. |
| `up <name>` | Reuse-or-create projects (never deleted), realize the topology (name-mangled `<prefix>-<runid>-<dsl-id>`), allocate a floating IP per VM, and block on the **attach-ready gate** before returning. Writes run-state. |
| `drive <name>` | Re-check the attach gate against the run-state record, snapshot the pre-traffic `cubecos_bytes_total` baseline into run-state, then push the declared flows over SSH (VM targets: `dd \| nc` at the internal IP into a sink started via the target's FIP; external targets: sized pings — transmitted bytes count at the tap with or without replies). |
| `assert <name>` | Poll-until-settle evaluation of every `Expect` as a `MinBytes` lower bound on the delta vs the drive-time baseline (tuples summed across agents; DSL tenant names resolved to project UUIDs via run-state). Emits human/json and persists the report to `<state>-report.json` — the evidence survives `down`. Negative deltas are flagged "baseline invalidated — re-run drive" (ghost GC can evict a prior run's flows after a baseline is captured). |
| `down` / `run` | Tear the topology down (projects excepted) and the full sequence. |

**Run-state.** `up` records every created resource — plus the DSL-name → Keystone-UUID project map — to a JSON file (`.scenariotest/<prefix>-<runid>.json` by default). `down` and `assert` consume it; a partial `up` still leaves a record `down` can clean up.

**Credentials.** Config mirrors the agent's two-mode pattern: `credentials_file` (admin-openrc-style) **or** inline. Credentials must be admin-scoped — reuse-or-create projects and host-pinned placement both require it. No SSH-source-openrc auto-discovery.

**Key facts the assertions hinge on.** The `tenant_id` label is the Keystone **project UUID** (not the DSL name), so `assert` resolves DSL name → UUID via run-state before matching. The `direction` label is `tx`/`rx` (VM-frame), not ingress/egress. The attach gate watches the `cubecos_attached_interfaces` **count** gauge — there is no per-interface HTTP surface — so it can be perturbed by background tenant churn; that limitation is inherent to the available signal.

**How to run.** Not part of `go test ./...` — it is an operator binary, not a tagged test, and needs a live cluster. `go test` covers the library (config, name-mangling, the snapshot→resource translation, metrics parsing, the attach gate) with the OpenStack / SSH / metrics IO behind seam interfaces. Run live with `scenariotest preflight -config <cfg> <scenario>` then `scenariotest up -config <cfg> <scenario>` against a staging cluster.

---

## CI

`.github/workflows/ci.yml` runs three jobs on every push to `develop`/`main` and on every PR:

| Job | Where | Why |
|---|---|---|
| `unit` | macOS + Ubuntu | Cross-platform compile + non-integration tests |
| `integration` | Ubuntu, privileged Docker | Full kernel/network pipeline; `continue-on-error: true` until Sprint 9 hardens |
| `bench-gate` | Ubuntu | Zero-alloc enforcement for `BenchmarkHotpath_*` |

Local equivalent: `task ci` runs unit + bench-gate (skips integration because it requires Docker setup). Run this before pushing.

---

## How to add a new test

| Want to test... | Tier | Naming | Tags |
|---|---|---|---|
| A pure-Go function | 1 | `TestPkg_Behavior` | none |
| A BPF program in isolation | 1 | `TestDriver_Behavior` in bpfunit | `integration` |
| A real packet flowing through real Linux | 2 | `TestE2E_<Topology>_<Behavior>` | `integration` |
| Hot-path performance | 3 | `BenchmarkHotpath_<HotPathName>` | none |
| Informational benchmark | 3 | `Benchmark_<Function>` | none |

---

## Environmental gotchas

- **`-u 0`** is required even with `--privileged`. The Dockerfile sets `USER bigstack` (UID 1000); without overriding to UID 0, `--privileged` grants nothing. Symptom: misleading `BTF not supported (requires >= v4.18)` error.
- **`GOWORK=off`** is required because of the parent workspace at `/Users/arashi87/Work/go.work` (developer-specific). The `task test-integration` target sets this automatically.

---

*Last updated: 2026-06-29 (Tier 4 — live-cluster validation added).*
