# Grafana stack for the CubeCOS network-telemetry agent

A local Prometheus + Grafana stack that visualises the agent's
`/metrics` endpoint. One all-in-one dashboard
(`dashboards/cubecos-telemetry.json`, uid `cubecos-telemetry`)
replaces the earlier per-topic set; its rows:

| Row | Focus |
| --- | --- |
| Overview            | up / flows / attached ifaces / sync age / scrape age / telemetry_map fill |
| Throughput (billing) | bytes & packets/sec by direction, zone, tenant; cumulative table |
| BPF Maps            | fill ratio + current-vs-max entries for all three kernel maps |
| Scraper & Collector | scrape errors, scrape lag, Collect pass duration p50/p99 |
| Neutron             | API error rate, BuildTrie step durations, unknown device_owner |
| WAL                 | per-phase p99 latency, flush failures, load fallbacks |
| Netlink / TC        | attached-interface trend, attach failures, zombie cleanups |
| GC & Eviction       | UnresolvedBuffer depth (vs the 10k cap), GC/buffer eviction & pressure-relief rates, lingering ghosts |

The dashboard selects its Prometheus through a `datasource` template
variable, so the same JSON imports cleanly into any Grafana that has
a Prometheus datasource (e.g. a staging host's own Grafana).

## Alerting

`alerts.rules.yml` (loaded via `rule_files` in `prometheus.yml`) ships
one paging rule: **`CubecosTelemetryMapInsertFailures`** fires when
`cubecos_bpf_update_failures_total{reason="update_failure"}` rises —
the kernel dropped flows because `telemetry_map` filled, which the
pressure-relief GC is meant to prevent, so any firing is active billing
loss. It carries `severity="page"`; route that to the on-call via
Alertmanager in a real deployment. The local stack has no Alertmanager,
so a firing rule shows in Prometheus's `/alerts` UI
(<http://localhost:9091/alerts>) only.

## Default profile — visualisation only

```sh
docker compose up
```

- Prometheus: <http://localhost:9091>
- Grafana:    <http://localhost:3000> (anonymous Editor)

Prometheus scrapes the agent at `host.docker.internal:9090` — works
out of the box on Docker Desktop (macOS/Windows) and on Linux
through the `host.docker.internal → host-gateway` mapping in
`docker-compose.yaml`. Point Prometheus at a different agent by
editing `prometheus.yml` and reloading
(`curl -X POST http://localhost:9091/-/reload`).

## `full` profile — also runs the agent in a privileged container (Linux only)

```sh
# 1. Build the agent binary into ./build/agent (from repo root)
task binary

# 2. Pick the interface(s) to attach TC clsact on (comma-separated allowlist)
export CUBECOS_BPF_ATTACH_INTERFACES=eth0   # adjust to your host

# 3. Bring up everything, including the agent
docker compose --profile full up
```

The `agent` service runs in `network_mode: host` and needs
`privileged: true` + BPF/PERFMON/NET_ADMIN/SYS_ADMIN capabilities.
On macOS Docker Desktop the host-network and BPF requirements are
not met; run the agent directly on a Linux host instead.

## Dashboards

Dashboards are provisioned at startup via
`provisioning/dashboards/cubecos.yaml` and pulled from
`/var/lib/grafana/dashboards`. UI edits are kept (`allowUiUpdates:
true`) — export and commit them when you want a change to survive a
restart.
