# Runtime Tuning & Reload

How an operator changes the agent's behavior without restarting it: the SIGHUP
reload path, the hot-tunable knob set, and the `/debug` control endpoints. The
machinery is `internal/runtime` (the reload `Manager`) plus `internal/tunables`
(the atomic snapshot every consumer reads).

## The mechanism

Every operational knob whose change needs no resource re-binding lives in one
atomic snapshot (`tunables.Store`) that consumers read at their own use sites —
a tick boundary, a ghost-mark, a buffer admission. On SIGHUP the `Manager`:

1. Re-reads the YAML and validates it **whole** — an invalid file rejects the
   entire reload and the agent keeps running on the previous snapshot (the
   failure is logged and counted).
2. Swaps the snapshot atomically and logs every changed field old→new
   (a reflective diff over the knob tags — nothing changes silently).
3. Warn-logs any changed **restart-only** field (listen address, paths,
   credentials, broker lists): those take effect at the next agent restart,
   never mid-flight.

Outcomes are observable on `lachesis_config_reloads_total{result}` and the
live values on `GET /debug/config`. Cadence changes take effect at the
consuming loop's next tick — the delta math is interval-agnostic, so even
`scrape.interval` is safe to change live.

**Single-source rule.** The projection in `config.Config.Tunables()` is the
one place that decides which fields are hot, and the `tunables.Store` is a
**required** dependency of every consumer — no per-package fallback values
exist, so an operational knob has exactly one source (defaults live only in
`config.Defaults`). A projection guard test fails CI by name if a knob is
added to the config but never registered in the projection.

## The hot set

| Knob | Consumer | Effect |
|---|---|---|
| `scrape.interval` | scraper | BPF drain cadence (safe live — delta math is interval-agnostic) |
| `gc.ghost_grace` | ghost sweeper | the Lingering-Ghost TTL ([data-structures.md](../architecture/data-structures.md#lingering-ghost)) |
| `gc.ghost_sweep_interval` | ghost sweeper | sweep cadence |
| `gc.pressure_high_watermark` | pressure reliever | fill ratio that triggers relief (validated < 1.0) |
| `gc.pressure_low_watermark` | pressure reliever | hysteresis floor |
| `gc.pressure_max_per_pass` | pressure reliever | per-pass eviction cap (bounds scrape stall) |
| `reconcile.interval` | reconciler | the no-Kafka staleness ceiling |
| `wal.flush_interval` | WAL flusher | durability window (the ≤60s loss bound) |
| `unresolved.cap` | UnresolvedBuffer | entry bound (floor ≥ 1 — Contract 1) |
| `unresolved.ttl` | UnresolvedBuffer | late-binding window |
| `neutron.max_static_route_hops` | static-route resolver | traversal bound, applied at the next trie rebuild ([trie-construction.md](../architecture/trie-construction.md#the-static-route-resolver); floor ≥ 1) |
| `logging.level` | all | applied atomically via the logging handle |

Everything else is **load-time**: edit the YAML, restart the agent. A field
moves into the hot set only when its consumer gains the atomic plumbing to
apply it mid-flight (see "Adding a hot knob" below).

## Operator interfaces

### SIGHUP — batch reload of the YAML

```bash
$ vim /etc/lachesis/agent.yaml      # e.g. gc.pressure_max_per_pass: 1000 → 2000
$ kill -HUP $(pidof agent)
# agent log:
# INFO  reload applied  changed="gc.pressure_max_per_pass: 1000 → 2000"
```

Use for deployment-managed config changes (Ansible/Helm drops a new YAML) and
anything that should survive a restart.

### `GET /debug/config`

Returns the active `Config` snapshot as JSON, **secrets redacted**. "Is the
agent really running with the config I think it is?"

```bash
$ curl -s http://localhost:9090/debug/config | jq .gc
```

### `PUT /debug/log-level`

Changes the log level immediately, without touching the YAML on disk:

```bash
$ curl -X PUT http://localhost:9090/debug/log-level \
       -H 'Content-Type: application/json' -d '{"level":"debug"}'
```

Use for one-shot debugging of a production issue. HTTP changes are
**ephemeral** — they update the in-memory snapshot but don't write the YAML;
the next SIGHUP reload restores whatever the YAML says.

These two endpoints are owned by the runtime `Manager`; the rest of the
`/debug` surface (index, topology, zones, lookup, anomalies, flows, pprof) is
the `debug.Server`'s operator pages, mounted on the same mux.

## Security considerations

`/debug/*` and `/metrics` share one HTTP server and listen address.

**Threat:** anyone reachable on `http.listen` can read internal counters via `/metrics` and change runtime behaviour via `PUT /debug/log-level`. Endpoints are not authenticated and not rate-limited.

**Mitigations, cheapest to strongest:**

| Layer | What it does | Cost |
|---|---|---|
| Bind to `127.0.0.1` | Same-host callers only | One YAML change; a remote Prometheus then can't scrape |
| Reverse proxy with auth | nginx / Envoy in front handles authn for `/debug` | No agent code change |
| Separate ports for `/metrics` and `/debug` | `/metrics` on a public-ish port; `/debug` on localhost only | One extra `HTTPConfig` field + a second `http.Server`. Same pattern as kubelet |
| mTLS | Client cert required for `/debug` | Most secure, most setup cost |

The two-port split is the recommended next step once production deployments need it.

## Adding a hot knob

1. Add the field to `tunables.Values` with its `knob:"section.name"` tag.
2. Project it in `config.Config.Tunables()` — the guard test fails by name if
   you forget.
3. Make the consumer read it from the `tunables.Store` snapshot at its use
   site (never cache it across ticks; never add a package-local default).
4. Add the row to the hot-set table above.
5. Add a test that a reload changes the observed value.

A field stays load-time when applying it means re-binding a resource
(a socket, a BPF map, a goroutine's identity) — that's a restart, not a knob.
