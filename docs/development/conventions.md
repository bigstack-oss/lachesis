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
| `perfbench`, `loadtest`, `scenariotest` | CLI harness | `Run(Config)`-style single-shot entrypoints (scenariotest: one per subcommand, live-cluster IO behind the `Cloud`/`MetricsSource` seams) |

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
