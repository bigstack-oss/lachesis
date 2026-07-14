# `internal/runtime` — Reload and Debug Manager

The `internal/runtime` package provides the live-machinery layer that turns a static `config.Config` into a controllable runtime: SIGHUP-driven YAML reload, HTTP endpoints for ad-hoc tuning, and atomic application of hot-reloadable fields.

It depends on `internal/config` (for loading and validating YAML) and `internal/logging` (for the atomic log-level handle). It is consumed by the agent binary's `main` to wire signals and HTTP routes.

---

## The `Manager` type

```go
type Manager struct { /* unexported */ }
```

A `Manager` holds three things:

- The YAML file path (so it can re-read on demand).
- The most recently applied `config.Config` snapshot — the single source of truth at runtime.
- A pointer to the `*logging.Handle` so it can change the log level atomically.

The package is small on purpose; its only job is to apply config changes to running subsystems. Use `runtime.New` to construct one and `Manager.InstallSIGHUP` plus `Manager.DebugHandler` to install its operator interfaces.

---

## Wiring in an agent main

```go
// Static config (defaults < YAML < env < flags)
cfg, err := config.Load(os.Args[1:])
if err != nil {
    fmt.Fprintln(os.Stderr, err)
    os.Exit(2)
}

// Initialise structured logging; the returned Handle is the only thing
// runtime.Manager needs to flip the level atomically.
logHandle, err := logging.Init(cfg.Logging, os.Stderr)
if err != nil {
    fmt.Fprintln(os.Stderr, err)
    os.Exit(2)
}

// The runtime manager owns the YAML path so SIGHUP can re-read it.
mgr := runtime.New(yamlPath, cfg, logHandle)

// Cancel the SIGHUP goroutine on shutdown.
ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
defer cancel()
mgr.InstallSIGHUP(ctx)

// /debug endpoints share the HTTP server with /metrics.
mux := http.NewServeMux()
mux.Handle("/metrics", promhttp.Handler())
mux.Handle("/", mgr.DebugHandler())
```

---

## Hot vs load-time fields

| Tier | Fields (current) | How they update |
|---|---|---|
| **Hot** | `logging.level` | Applied atomically on reload. No restart required. |
| **Load-time** | `http.listen`, `bpf.pin_path`, `scrape.interval`, `logging.format` | Reload logs a warning if the YAML diff includes them. They take effect on the next agent restart. |

The hot tier grows as subsystems add the atomic plumbing needed to apply changes without restart. Until a field is moved from load-time to hot, the path is: edit YAML, restart the agent.

---

## Operator interfaces

### SIGHUP — batch reload of the YAML

```bash
$ vim /etc/lachesis/agent.yaml      # change logging.level: info → debug
$ kill -HUP $(pidof agent)
# In the agent's logs:
# INFO  reload: logging.level changed  from=info to=debug
```

When to use:

- Deployment-managed config changes (Ansible / Helm / Puppet drops a new YAML).
- Permanent operational changes — anything that should survive an agent restart.

The reload is atomic at the field level. If the new YAML fails validation, **no fields are updated** and the agent continues with the previous snapshot. The failure is logged as a warning.

### `GET /debug/config`

Returns the active `Config` snapshot as JSON. Useful for diagnostics — "is the agent really running with the config I think it is?"

```bash
$ curl http://localhost:9090/debug/config | jq .logging
{
  "level": "debug",
  "format": "json"
}
```

### `PUT /debug/log-level`

Changes the log level immediately, without touching the YAML on disk. Body is JSON: `{"level": "debug" | "info" | "warn" | "error"}`.

```bash
$ curl -X PUT http://localhost:9090/debug/log-level \
       -H 'Content-Type: application/json' \
       -d '{"level":"debug"}'
```

When to use:

- One-shot debug of a production issue (revert when done).
- Verifying behaviour before committing a YAML change.

HTTP changes are **ephemeral** — they update the in-memory snapshot but don't write to YAML. The next SIGHUP reload restores whatever the YAML says.

---

## Concurrency and atomicity

- `Manager` guards its snapshot with `sync.Mutex`. Readers (`Current`) get a copy; writers (`Reload`, HTTP handlers) take the lock briefly.
- The log level is mutated via `slog.LevelVar.Set` — an atomic operation. Active log calls never block on a level change.
- The SIGHUP goroutine exits when its context is cancelled. Call `InstallSIGHUP` exactly once per process.

---

## Security considerations

The current implementation mounts `/debug/*` on the same HTTP server as `/metrics`. Both share the listen address from `http.listen` in the config.

**Threat:** anyone reachable on `http.listen` can read internal counters via `/metrics` and change runtime behaviour via `PUT /debug/log-level`. Endpoints are not authenticated and not rate-limited.

**Mitigations, cheapest to strongest:**

| Layer | What it does | Cost |
|---|---|---|
| Bind to `127.0.0.1` | Same-host callers only. | One YAML change. Prometheus on a different host then can't scrape. |
| Reverse proxy with auth | nginx / Envoy in front handles authn for `/debug`. | No agent code change. |
| Separate ports for `/metrics` and `/debug` | `/metrics` on a public-ish port; `/debug` on localhost only. | One extra `HTTPConfig` field + a second `http.Server` in main. Same pattern as kubelet. |
| mTLS | Client cert required for `/debug`. | Most secure, most setup cost. |

The two-port split is on the future-work list and is the recommended next step once production deployments need it.

---

## Adding a new hot field

1. Add the underlying atomic (e.g. `atomic.Pointer[T]`) to the consuming subsystem.
2. Expose a `SetX(...)` method on that subsystem that updates the atomic.
3. In `Manager.Reload`, after the new config validates, call `subsystem.SetX(next.Section.X)` only if `next.Section.X != m.current.Section.X`.
4. Move the field's row in the **Hot vs load-time fields** table above from load-time to hot.
5. Add a test that verifies hot reload updates the atomic.

Load-time fields stay load-time until step 1 is feasible. Typical blockers: re-binding a socket, replacing a goroutine, reloading a BPF program.

---

## See also

- [`internal/config`](../internal/config) — the static config layer this manager applies.
- [`internal/logging`](../internal/logging) — the logging handle this manager mutates.
- [`docs/sprint-plan.md`](./sprint-plan.md) — roadmap, including future hot fields and the two-port split.
