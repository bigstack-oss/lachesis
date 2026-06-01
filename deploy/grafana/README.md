# Grafana stack for the CubeCOS network-telemetry agent

A local Prometheus + Grafana stack that visualises the agent's
`/metrics` endpoint. Three dashboards land in this Sprint:

| File | Title | Focus |
| --- | --- | --- |
| `dashboards/00-health.json`     | Agent Health        | up / scrape errors / flow count / scrape age |
| `dashboards/10-throughput.json` | Throughput          | bytes & packets/sec by direction, zone, tenant |
| `dashboards/20-state.json`      | GlobalState         | tracked-flow trend, cumulative bytes by (zone, direction) |

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
