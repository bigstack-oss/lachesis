# Test Strategy

> Four tiers — unit, integration, performance, live-cluster — one rule each.
> The canonical reference for how tests are organized and run. If a test
> category isn't covered here, it's either deferred work or a gap worth
> surfacing.

The shared infrastructure (`internal/testenv`) exists so new work plugs into
it instead of re-inventing harnesses per PR.

## Tier 1 — Unit tests

**Question.** Is each unit of Go logic and each BPF path correct in isolation?

**Goal.** Verify pure-Go logic and BPF kernel paths in isolation, no real network.

**Where.**
- Go logic: `*_test.go` files alongside the production code in each package.
- BPF programs: `internal/testenv/bpfunit/` and any test that exercises `Driver.Run` / `Driver.RunRepeat`.

**Build tags.**
- Pure Go tests: no tags. Run on every host. `task test`.
- BPF tests: `//go:build integration`. Require Linux + CAP_BPF. `task test-integration`.

**Dependency injection.** Production code that touches the kernel, Neutron, or the filesystem defines consumer-side seam interfaces (`MapReader`, `MetadataSource`, …) so unit tests swap real impls with in-memory fakes. Interfaces live with their consuming packages, never in a central seams package — the full rule is in [conventions.md](./conventions.md#package-anatomy).

Table-driven tests are the norm for delta math and zone attribution. Metric assertions use `testutil.GatherAndCompare` against exposition format — never substring-match protobuf text.

## Tier 2 — Integration / e2e tests

**Question.** Does the full kernel↔userspace pipeline behave against real Linux semantics?

**Goal.** Verify the full pipeline against real namespaces, real veth interfaces, real TCP connections, real BPF TC attach.

**Where.**
- `internal/testenv/netns/` — namespace + veth lifecycle helpers (`New`, `Close`, `Do`, `AddVeth`, `AttachBPF`)
- `internal/testenv/traffic/` — TCP traffic generation via `net.Dial` from inside a namespace
- `internal/testenv/e2e/` — composed scenarios

**Build tags.** `//go:build integration` and `//go:build linux`.

**How to run.** `task test-integration`. The target wraps the privileged Docker invocation (`--privileged -u 0 -e GOWORK=off`) so devs don't have to remember flags.

**Why Docker.** macOS dev hosts can't load BPF directly, and CI runners need a deterministic kernel + toolchain. The Dockerfile-built `ebpf-builder` image is the canonical Linux environment for all kernel-touching tests.

**Known limitation.** Timing measurements under Rosetta (Apple Silicon emulating linux/amd64) report near-zero ns due to clock resolution. Use `perfbench` on native x86 Linux for real numbers.

## Tier 3 — Performance tests

**Goal.** Verify the CPU and memory budgets from [performance.md](../architecture/performance.md).

### ns/packet via the per-packet ceiling gate

**Question.** How much CPU does the classifier burn per packet?

`internal/perfbench.Run` loads the real classifier (`tc_telemetry_in`) and drives it through `BPF_PROG_TEST_RUN`, reporting kernel-measured time. The maps load empty, so every packet takes the lookup-miss path — the number covers the parse plus the full lookup chain. There is no standalone binary; the measurement is driven only by the gate below.

Design target: **~150 ns/packet**. `TestPerfbench_PerPacketCeiling` (build tag `integration`, package `internal/perfbench`) runs on the `integration` CI job and fails above an absolute `PerRunNs` ceiling — a generous bound that catches a new map lookup or classification branch, not a 10% drift detector. The ceiling is **300 ns**, ~2× the 135 ns amd64-runner baseline.

To read the number on real hardware, run the gate with `-v` on a native x86 OVN node (macOS/Rosetta reports near-zero ns):

```sh
go test -tags integration -run TestPerfbench_PerPacketCeiling -v ./internal/perfbench
```

### Zero-allocation gate

**Question.** Does the hot path allocate on the scrape/packet path?

Hot-path code (`Collect()`, scraper, packet handlers) must allocate zero memory per call to keep GC pressure off the scrape cadence.

**Convention:**
- `BenchmarkHotpath_<Name>` → gated; must report `0 allocs/op`. CI fails the PR if violated.
- `Benchmark_<Name>` → informational, no gate.

Both `BenchmarkHotpath_*` families are alloc-gated at `0 allocs/op`, split by build tag:

- The untagged pure-Go hot paths — `internal/state`'s `BenchmarkHotpath_ApplyDelta` and `BenchmarkHotpath_Snapshot` — run in the `bench-gate` CI job (`task bench-gate` → `go test -bench=^BenchmarkHotpath_ -benchmem`).
- The kernel hot paths — `internal/kernelwriter`'s `BenchmarkHotpath_LpmHit` and `BenchmarkHotpath_LpmFallback` — are `//go:build integration` (they drive `BPF_PROG_TEST_RUN`), so the non-privileged bench-gate job can't build them. They are gated in the `integration` job via `task bench-gate-integration` (`bench-gate.sh integration` under privileged Docker).

### Throughput delta (manual)

End-to-end BPF overhead is measured by hand with iperf3 against a real VM tap, attach/detach around the runs:

```
─── Terminal 1 (server, on the VM) ───
iperf3 -s

─── Terminal 2 (baseline — NO eBPF) ───
iperf3 -c <vm_ip> -t 30 -P 4          # record throughput

─── start the agent (attaches TC) ───

─── Terminal 2 (with eBPF active) ───
iperf3 -c <vm_ip> -t 30 -P 4          # compare; expect <1% delta

─── stop the agent; re-run baseline for clean back-to-back runs ───
```

Not automated; the per-packet ceiling gate is the regression net, this is the
occasional end-to-end sanity check.

### Load test via `loadtest`

**Question.** Does the long-running agent stay inside its RSS/CPU budget under sustained load?

`cmd/loadtest` forks the agent as a subprocess, drives sustained TCP traffic through a netns + veth, samples `/proc/<pid>/{stat,status}`, and exits non-zero if peak RSS or average CPU exceeds the configured budget (defaults: 250 MiB, 1% CPU over a 15s window). It runs as its own **blocking** `loadtest` CI job (privileged Docker: builds the agent, then loads it); the budget was validated on the shared runner (~29 MiB RSS, 0% CPU). The harness runs the agent without Neutron, so no VM MAC resolves — it sets a short `Unresolved.TTL` so buffered flows fold to the "unknown" tenant within the window, making the observed-bytes liveness floor meaningful.

```sh
task loadtest                                           # default: 15s window, 4 workers
```

## Tier 4 — Live-cluster validation

**Question.** Is per-tenant / zone / direction byte attribution correct end to end against live OpenStack?

**Goal.** Verify attribution end to end against a **real OVN cluster** — the automated form of the deploy → traffic → scrape → assert → teardown loop previously run by hand on staging. Tiers 1–3 prove the pipeline in isolation; Tier 4 proves it against live OpenStack.

**Where.** `cmd/scenariotest` (the operator-run binary) and `internal/scenariotest` (the library). Scenarios are declarative Go literals under `cmd/scenariotest/scenarios/`, one per file. The registered set covers all five billable zones plus lifecycle and multi-node cases — the [scenario coverage table](../architecture/scenarios.md#live-regression-coverage) maps them to the design walkthroughs.

**Lifecycle.** Subcommands compose the loop:

| Subcommand | Does |
|---|---|
| `list` | Show registered scenarios. |
| `preflight <name>` | Read-only: verify prerequisites (image, flavor, keypair, secgroup, external network), validate any pinned hypervisors, confirm each agent's `/metrics` is reachable and exposes `lachesis_bytes_total` + `lachesis_attached_interfaces`. |
| `up <name>` | Reuse-or-create projects (never deleted), realize the topology (name-mangled `<prefix>-<runid>-<dsl-id>`), allocate a floating IP per VM, and block on the **attach-ready gate** before returning. Writes run-state. |
| `drive <name>` | Re-check the attach gate against the run-state record, snapshot the pre-traffic `lachesis_bytes_total` baseline into run-state, then push the declared flows over SSH (VM targets: `dd \| nc` at the internal IP into a sink started via the target's FIP; external targets: sized pings — transmitted bytes count at the tap with or without replies). |
| `assert <name>` | Poll-until-settle evaluation of every `Expect` as a `MinBytes` lower bound on the delta vs the drive-time baseline (tuples summed across agents; DSL tenant names resolved to project UUIDs via run-state). Emits human/json and persists the report to `<state>-report.json` — the evidence survives `down`. Negative deltas are flagged "baseline invalidated — re-run drive" (ghost GC can evict a prior run's flows after a baseline is captured). |
| `down <name>` | Idempotent reverse-order teardown of everything in run-state: FIPs by exact recorded ID (never a listing), servers (waited gone), router interfaces, ports, routers, a residual port sweep scoped to the scenario's own networks (platform ports like `cube:mgr` block deletion but appear in no run-state), subnets, networks. Every delete tolerates already-gone, so re-runs converge. Projects and the run-state/report files are never touched. |
| `run <name>` | The whole loop in one command: preflight → up → drive → assert → down. Teardown runs on every exit path once `up` created anything (even after drive/assert failures) unless `-keep` is set; the report and run-state survive as the run's evidence. Exit 0 iff all expectations passed; a scenario needing more nodes than the config provides is SKIPPED (exit 0, or a failure under `--no-skip`). |
| `run mac-reuse` | The step-scripted ghost-sweep + MAC-reuse billing regression: drive tenant A → delete its VM mid-run → poll `lachesis_gc_settled_flows_total` until the agent's ghost sweep folds the flows → assert tenant A's tuples are monotone and nothing re-bucketed to `unknown` → boot the deferred VM on tenant B's port pinning the deleted MAC → assert zero inheritance → drive tenant B → assert its delta and tenant A once more. Refuses agents that predate the settled-bytes fold. |

**Step scripts.** A scenario may declare `Steps` — an ordered program `run` executes between up and down — when the classic drive-all/assert-all line can't express it (mid-run VM deletion, waiting out an agent GC cadence, booting a `Deferred` VM with a captured MAC, live-migrating a VM, sleeping across an operational window). The vocabulary (`DriveStep`, `AssertStep`, `CaptureStep`, `DeleteVMStep`, `AwaitSweepStep`, `MonotoneStep`, `MaxGrowthStep`, `BootVMStep`, `MigrateStep`, `SleepStep`) is an open interface: a new operational step is one new type, no executor change. Scenarios without steps are untouched — empty `Steps` is exactly the classic loop.

**Multi-node.** Scenarios pin VMs to cluster nodes with symbolic `node:<i>` placement slots resolved against the configured agents; per-node `Expect` targeting asserts which host's agent observed the bytes. A scenario whose slots need more nodes than configured reports SKIPPED rather than failing.

**Run-state.** `up` records every created resource — plus the DSL-name → Keystone-UUID project map — to a JSON file (`.scenariotest/<prefix>-<runid>.json` by default). `down` and `assert` consume it; a partial `up` still leaves a record `down` can clean up.

**Credentials.** Config mirrors the agent's two-mode pattern: `credentials_file` (admin-openrc-style) **or** inline. Credentials must be admin-scoped — reuse-or-create projects and host-pinned placement both require it. No SSH-source-openrc auto-discovery.

**Key facts the assertions hinge on.** The `tenant_id` label is the Keystone **project UUID** (not the DSL name), so `assert` resolves DSL name → UUID via run-state before matching. The `direction` label is `tx`/`rx` (VM-frame), not ingress/egress. The attach gate watches the `lachesis_attached_interfaces` **count** gauge — there is no per-interface HTTP surface — so it can be perturbed by background tenant churn; that limitation is inherent to the available signal.

**How to run.** Not part of `go test ./...` — it is an operator binary, not a tagged test, and needs a live cluster. `go test` covers the library (config, name-mangling, the snapshot→resource translation, metrics parsing, the attach gate) with the OpenStack / SSH / metrics IO behind seam interfaces. Run live with `scenariotest preflight --config <cfg> <scenario>` then `scenariotest run --config <cfg> <scenario>` against a staging cluster.

**Known-infeasible at this tier.** The resolver's Step-C **ambiguity** fallback (duplicate destination CIDR with two owners on one router → `lachesis_neutron_anomalies{class="ambiguity"}`) cannot be produced through the Neutron API: any two prefixes that both contain a destination necessarily overlap each other, and Neutron rejects attaching overlapping-CIDR subnets to one router (`Bad router request: Cidr … overlaps with cidr …` — verified live on OVN/Yoga, 2026-07-24, lachesis#171). The condition is reachable only from a stale or corrupted snapshot, which no API-driven scenario can stage; the **unit tier owns it** (`internal/neutron/resolve_test.go`'s ambiguity cases build the snapshot directly).

## CI

`.github/workflows/ci.yml` runs on every push to `develop`/`main` and on every PR:

| Job | Where | Why |
|---|---|---|
| `unit` | Ubuntu | `go build ./...` + non-integration tests across every package |
| `integration` | Ubuntu, privileged Docker | Full kernel/network pipeline; also runs the `perfbench` per-packet ceiling gate and the integration-tagged hot-path alloc gate |
| `bench-gate` | Ubuntu | Zero-alloc enforcement for `BenchmarkHotpath_*` |
| `lint` | Ubuntu | `golangci-lint` (with `--build-tags=integration`) |
| `loadtest` | Ubuntu, privileged Docker | Agent RSS/CPU budget under sustained load (blocking; validated on the shared runner) |

Local equivalent: `task ci` runs unit + bench-gate (skips integration because it requires Docker setup). Run this before pushing.

## How to add a new test

| Want to test... | Tier | Naming | Tags |
|---|---|---|---|
| A pure-Go function | 1 | `TestPkg_Behavior` | none |
| A BPF program in isolation | 1 | `TestDriver_Behavior` in bpfunit | `integration` |
| A real packet flowing through real Linux | 2 | `TestE2E_<Topology>_<Behavior>` | `integration` |
| Hot-path performance | 3 | `BenchmarkHotpath_<HotPathName>` | none |
| Informational benchmark | 3 | `Benchmark_<Function>` | none |
| Live billing attribution | 4 | a scenario literal in `cmd/scenariotest/scenarios/` | — (operator binary) |

## Environmental gotchas

- **`-u 0`** is required even with `--privileged`. The Dockerfile sets a non-root `USER`; without overriding to UID 0, `--privileged` grants nothing. Symptom: misleading `BTF not supported (requires >= v4.18)` error.
- **`GOWORK=off`** is required when the developer's machine has a parent Go workspace above the repo. The `task test-integration` target sets this automatically.
