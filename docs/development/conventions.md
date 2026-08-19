# Code Conventions

Contributor-facing structural rules: how constructors look, what shape a
package is allowed to have, and where the cross-cutting surfaces (metrics,
logging, interfaces) live. The *design* rationale behind the code lives in
[../architecture/](../architecture/README.md); this page is about keeping the
codebase uniform.

## Construction conventions

Several constructor idioms coexist *by design*. New code matches the closest existing one rather than inventing a sixth, and the outliers below are deliberately **not** normalised — converting them only churns tests for no behavioural gain.

| Idiom | Used by | When |
|---|---|---|
| Options struct | `agent.New(Options)`, `netlink.New(Options)`, `gc.New(Options)`, `kafka.New(Options)`, `reconcile.New(Options)`, `unresolved.NewBuffer(Options)`, `config.Load(Options, …)` | More than ~2 inputs, or any optional / defaulted field. The reference pattern — reach for it first |
| Positional params | `scraper.New(reader, st, interval)`, `metadata.NewResolver(m)`, `tunables.New(initial)` | ≤2 unambiguous required args, no options |
| Bare `New()` | `state.New`, `boot.New`, `metadata.New`, `netlink.NewRegistry`, every per-package `NewMetrics` | Zero-config value types. Metric bundles are uniformly `type Metrics` + `NewMetrics()` |
| Functional options | *(none — retired)* | `BuildTrie`'s `WithMetrics` (the sole user) was retired when its only metrics-passing caller moved in-package (`Neutron.Sync` → unexported `buildTrie(snap, m)`); the external call-sites stay argument-free via `BuildTrie(snap)`. Don't reintroduce without a cross-package optional-dependency need |
| `Run(Config)` | `perfbench.Run`, `loadtest.Run` | Single-shot CLI harnesses, not long-lived services |

## Package anatomy

Every `internal/` package is one of four shapes. A new package starts by picking the archetype that matches its job — don't invent a fifth shape, and don't mix surfaces from two archetypes into one package. Uniformity holds *within* an archetype, never across archetypes (the Kubernetes analog: `component-base` daemons share an options-plus-`Run(ctx)` shape while client-go stores/listers stay plain structs). A one-size-fits-all package surface and producer-side interface-per-package were both considered and rejected — the repo already rejected a `Runnable` interface once in favour of the concrete `workers()` table.

**Decision rule:** does it own a loop? → Service. Is it shared mutable state? → Store. Does one owner call verbs on it while others only read? → Driven subsystem. None of the above → Library.

| Archetype | Surface | Examples |
|---|---|---|
| **Service** — owns a long-running loop | Constructor per the idiom table → struct; a blocking `Run(ctx) error` (or equivalent step methods the agent's worker table wraps); cheap health accessors for observability. Services never spawn their own goroutines: long-lived goroutines start in exactly one place, the agent's `workers()` table (drain-ordered, goleak-enforced) | `scraper.Scraper` (`Run`/`Tick`/`ErrorCount`/`LastSuccessUnix`), `netlink.Subscriber`, `gc.GhostSweeper`, `kafka.Consumer`, `reconcile.Reconciler` |
| **Store** — passive shared state | Bare `New()` (or the smallest idiom that fits); concrete methods; explicit lock discipline (`RWMutex` or sharding, acquire-late/release-early, never hold a lock across IO) or atomic snapshot swap. No `ctx`, no goroutines, no IO | `state.GlobalState`, `metadata.ShardedMetadataMap`, `metadata.TenantInterner`, `netlink.Registry`, `tunables.Store`, `unresolved.Buffer` |
| **Driven subsystem** — a caller sequences its verbs | Constructor per the idiom table; imperative verb methods the owner calls in a documented order; lock-free read accessors for everyone else (atomic pointer-swap retention, whole-value replace). Single-writer discipline documented on the type | `neutron.Neutron` (`Sync` → kernel push → `Commit`; accessors feed /debug), `runtime.Manager` (`Reload`/`Current`/`DebugHandler`), `boot.Sequencer` (`Advance`/`Await`/`Fail`), `metrics.Collector` (Prometheus drives `Collect`), `debug.Server` (HTTP mux drives handlers), `gc.PressureReliever` (the scraper drives its pass) |
| **Library** — stateless functions | No main type, no constructor, no lifecycle; pure functions with explicit dependencies as arguments | `kernelwriter`, `wal` (`Save`/`Load`), `zombie.Hunt`, `config.Load`, `logging.Init`, `tcattach` |

Two sanctioned one-offs (not archetypes — don't replicate): the composition root (`agent`: one struct, method files by functionality, the `workers()` table, the `subsystemMetrics` registration list) and the CLI harness shape (`perfbench.Run(Config)` / `loadtest.Run(Config)`, already in the idiom table).

### Layering and the BPF ABI

Respect the L1–L4 boundaries: L3 never imports L1's data plane, L2 never calls L4.

**One deliberate exception, which is not a violation and must not be "fixed".**
`internal/bpf`'s pure ABI surface — the `FlowKey` / `FlowMetrics` / `LpmKey`
types, the `Zone*` and `Direction*` constants, `MACKey` — is a dependency-free
kernel↔userspace *data contract*, not the data plane. L2 (`metadata`,
`neutron`), L3 (`state`) and L4 (`metrics`, `wal`) all import it by design,
because it is the shared schema they exchange rows in. Hiding those types
behind per-layer copies would mean hand-copying generated struct layouts, and
silent skew between the copies corrupts metrics.

Only the loader half of the package — `LoadTelemetry`, `ValidateMapSizes`, the
`Map*` name constants, the metrics bundle — touches real L1 machinery, and only
the agent composition root uses it.

### Cross-cutting rules (all archetypes)

- `schema.go` holds the package's consts and pure-data types; behavioural types stay in their method files (`schema_linux.go` when the consts are linux-only).
- Observability: `type Metrics` + `NewMetrics()` + `Collectors()` + nil-safe observation helpers; registered centrally via the agent's `subsystemMetrics.registrations()`. Uninstrumented subsystems are undebuggable in production ([metrics.md](../architecture/metrics.md)).
- Logging: per-package `component*` const, one vocabulary with the metric registration labels.
- Interfaces are **consumer-defined only**: the consuming package declares the minimal method set it calls, and only when a second implementation exists today (a test seam counts). Never producer-side, never speculative. Representative seams: `scraper.MapReader`, `metrics.TenantResolver`, `kernelwriter.MapUpdater`/`MapUpdateDeleter`, `reconcile.MetadataSource`, `gc.MacEvictor`, `kafka.Trigger`, `netlink.Attacher`. The full census is one grep away (`^type .* interface` under `internal/`, excluding tests) — every hit must sit in the package that *calls* it.

### Package census

| Package | Archetype | Notes |
|---|---|---|
| `agent` | composition root | one-off; owns all goroutines via `workers()` |
| `boot` | Driven | `Sequencer.Advance`/`Await`/`Fail` |
| `bpf` | Library | consts/keys/`ValidateMapSizes` + generated bindings + Metrics |
| `config` | Library | `Load` + `Validate` + the `Tunables()` hot-set projection |
| `debug` | Driven | `New(Options)` + `Handler()`; HTTP mux drives it |
| `gc` | Service + Driven | `GhostSweeper` (own worker) + `PressureReliever` (scraper-driven pass) |
| `kafka` | Service | `Consumer` decodes oslo events and kicks the reconciler |
| `kernelwriter` | Library | + consumer interfaces `MapUpdater`, `MapUpdateDeleter` |
| `logging` | Library | `Init` → `Handle` |
| `metadata` | Store | two stores + `NewResolver` adapter + `RouterMACs` swap store |
| `metrics` | Driven | custom `prometheus.Collector` (billing path, Contract 2) |
| `netlink` | Service + Store | `Subscriber` + `Registry` + Metrics |
| `neutron` | Driven | + Library surface (`BuildTrie`, `DetectAnomalies`, lookups are pure funcs) |
| `osclient` | Library | shared Keystone bootstrap (`Credentials`, `ParseOpenRC`, `Authenticate`/`AuthenticateProject`); consumed by `neutron` and `scenariotest` |
| `reconcile` | Service | the single metadata applier (timer + Kafka kicks, one goroutine) |
| `runtime` | Driven | `Manager` ([operations/runtime.md](../operations/runtime.md)) |
| `scraper` | Service | reference Service example |
| `state` | Store | reference Store example |
| `tcattach` | Library | `NewLinkAttacher` returns the `Attacher` impl |
| `testenv` | exempt | test-only builders/fixtures |
| `tunables` | Store | atomic snapshot of the hot-reloadable knobs |
| `unresolved` | Store | `Buffer` (+ `Classifier`, the scraper-driven admission adapter) |
| `wal`, `zombie` | Library | + Metrics bundles |
| `perfbench`, `loadtest` | CLI harness | `Run(Config)`-style single-shot entrypoints |
| `scenariotest` (+ sub-packages) | CLI harness | see [below](#the-scenariotest-tree) |

### The scenariotest tree

`scenariotest` is the one package in `internal/` that is a *tree* rather
than a single package, because it is a whole tool rather than one
subsystem of the agent. It follows the layering rule Kubernetes' e2e
framework and CockroachDB's roachtest both use: **sub-packages import
the core; the core imports no sub-package.**

That rule is machine-checked by `TestCoreImportsNoSubpackage` (and
`TestSubpackagesImportOnlyTheCore` keeps the three drivers leaves), the
same way `internal/docs/refs_test.go` guards doc anchors. A new
sub-package that needs something from the core moves the declaration
*down* into the core; it never reaches up.

| Package | Role |
|---|---|
| `scenariotest` | the core: the scenario DSL, `Step`/`StepEnv`, `RunState`, the report, and the `Cloud`/`MetricsSource`/`VMExec` seams. No live IO |
| `openstack` | `Cloud` via gophercloud, one file per OpenStack service (identity/network/router/floatingip/compute) |
| `agentmetrics` | `MetricsSource` via the agent's `/metrics` + `/debug` |
| `remote` | `VMExec` via the system `ssh` binary |
| `agentctl` | the agent host's systemd lifecycle, config swap and cold-restart state removal |
| `gate` | the poll-until-predicate waits (attach rise, SSH ready) |
| `realize` `drive` `assert` `down` `preflight` | the single-shot phases, each a `Run(ctx, Options)` |
| `steps` | the step vocabulary, one file per family (traffic, lifecycle, port, network, agent, and the two assertion families) |
| `run` | the orchestrator; the only package that depends on every phase |
| `fake` | the shared test double — one model of the cloud for every phase's tests |

A scenario is declared against the core plus `steps`, and nothing else
(`cmd/scenariotest/scenarios`).

## Comments

**The code is the explanation. A comment exists to stop a wrong edit, and to point.**

Design, rationale, rejected alternatives, algorithms, and schema histories live in [../architecture/](../architecture/README.md) and [../adr/](../adr/README.md). They do not live in code. A long comment is not thorough — it is unread, and it is a second copy of a document that will drift away from the first.

This repo learned that the expensive way: `bpf/telemetry.c` carried a 22-line block on `created_ns` in which every sentence was true, load-bearing, and a verbatim restatement of ADR 0014's Context and Consequences. It is now four lines and points at the ADR.

### The keep test

A comment earns its place only if a competent reader editing **that line** would otherwise get it wrong. Four categories qualify:

| Category | What only the comment can say | Example |
|---|---|---|
| Kernel / platform behaviour | why the other spelling is wrong, when both compile | `bpf_skb_pull_data` before reading `skb->data` |
| Silent-failure invariant | why the obvious simplification corrupts money | never infer a counter reset from magnitudes |
| Cross-boundary mirror | a contract no compiler checks | `enum zone_code` ↔ `internal/bpf/abi.go` |
| Empirical constant | the measurement behind a number | `subnet_zone_trie` at 16384 entries, from a 37-tenant host |

State the hazard, then stop. "Never infer a reset from counter magnitudes" does the whole job; the paragraph explaining *why* inference fails belongs in the ADR.

Outside those four, delete: restating the signature, narrating the next statement, and a bare doc pointer as the whole comment. Godoc's own conventions still win where they apply — `// Describe implements [prometheus.Collector].` stays.

### Length

**Target ≤7 lines per block. Past that, you are writing documentation in the wrong file.**

Some entry points earn more: a package comment orients a new reader (what this package is, what it must never do, where the design lives) and may run longer. Nothing else does — a function, type, or field that needs fifteen lines of prose is describing a design that belongs in `docs/`, with the code keeping the one-sentence hazard and the link.

### Moving prose out is a two-step edit

Never delete the only record. Before shortening a block:

1. Confirm the content already exists in `docs/` — search for it, do not assume.
2. If it does not, add it to the right document **first**, in its own commit or at least its own hunk.

Only then cut the comment down. A shortening pass that loses the sole copy of an invariant is strictly worse than the wall of text it replaced.

### Placement and syntax

One comment per declaration, above it. Within a declaration every member is documented the same way or not at all — a seven-member enum where two carry multi-line notes and five carry nothing tells the reader nothing about the five, and a four-field struct where one field carries a 22-line block is the same defect wearing a different shape.

- **C** — a member note is a single-line trailing `/* … */`, **all-or-none across the declaration**. No member gets a comment block of its own: anything longer than one line moves into the header above the declaration, which then names the members it covers. C has no doc tool that renders a per-member block, so inside a struct body such a block is only a visual interruption.
- **Go** — a struct field may carry a godoc block above it, because godoc renders per-field documentation and the reader sees documented-vs-bare in the rendered output. Don't mix the two forms in one struct: a field's note is either a block above it or a one-line trailing comment, not both shapes in the same declaration.
- **Go** — `//` only, godoc form, `[Ident]` doc links. No markdown emphasis: godoc has no bold, so `**x**` reaches the reader as literal asterisks.
- **C** — `/* */` block above the declaration; single-line `/* … */` trailing. Never a `*` continuation ladder inside a trailing comment.
- Section dividers are `// --- label ---`, sanctioned inside the `scenariotest` tree where one file holds several verb families.
- Wrap comments at 80 columns.

### Citations

The pointer is how a short comment stays honest: it names the hazard, the document carries the reasoning.

Write the full repo-relative path, because `internal/docs/refs_test.go` validates it and a short form would not be checkable. Put it on its own line at the end of the block, **once per block**, never mid-sentence — an anchored path runs 50–80 characters and breaks both the sentence and the 80-column wrap:

```go
// ApplyTrieDelta upserts every changed row before deleting any stale
// one. Deleting first opens a window where a packet falls through to
// the catchall and is miskeyed permanently, because dst_zone is baked
// into the kernel flow_key.
//
// docs/architecture/trie-construction.md#incremental-updates
```

Where a block genuinely needs several pointers, list them under a `# References` heading rather than scattering them through the prose.

### Package entry points

Every package has exactly one godoc package comment. A `doc.go` is warranted only when that comment is long enough to want its own file; most packages keep it on a regular file, which is fine and should not be churned. A file-scope header is a **detached** block, separated from the `package` clause by a blank line — drop that blank line and godoc silently promotes the header to package documentation.

## Performance rules (hot paths: scrape loop + packet path)

- Prefer value types over pointers for structs ≤64B; GC pressure compounds at the scrape cadence.
- No interface dispatch in tight loops — concrete types only; interfaces only at package-boundary seams.
- Zero allocations inside `Collect()` and the scrape drain. Pre-allocate at init; reuse via `sync.Pool`. Enforced by the [alloc gate](./testing.md).
- Gate all new indirection with `go test -bench -benchmem` before merging.

## Locking

Never hold a mutex across a Neutron API call or IO. `RWMutex` for read-heavy paths (`ShardedMetadataMap`, `GlobalState`). Acquire late, release early — lock at the narrowest scope.

## Billing-path errors

Never silently drop errors in `Collect()`, delta math, or WAL writes. Always log + increment a counter ([metrics.md](../architecture/metrics.md) — every billing-path error site has a dedicated one). Avoid `fmt.Errorf` in hot loops — it allocates.

## Uncertain design? Check industry standard first

- eBPF map design → Cilium `pkg/maps` patterns.
- Concurrency queues → `k8s.io/client-go/util/workqueue`.
- Rate-limiting, ring buffers → CNCF conventions before rolling custom. Link the reference in the PR.
