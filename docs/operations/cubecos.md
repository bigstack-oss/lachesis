# Running on CubeCOS

How the agent runs as a CubeCOS platform service: which nodes run it and who
starts it, what the RPM puts on disk, what the platform must provide, and how
to observe, repair, and cleanly tear it down. Everything here was verified
against a live CubeCOS 3.1.10 node (kernel `6.12.95-1.el9`, 2026-07-30);
nothing is inferred from source alone.

For tuning a *running* agent — SIGHUP reload, hot knobs, `/debug` endpoints —
see [runtime.md](./runtime.md). This page is about the platform around it.

## Where it runs and who starts it

The agent ships inside the CubeCOS image on **every** node and is started only
where VM taps exist: roles matching `IsCompute()` — `compute`,
`control-converged`, and `edge-core`. Pure `control` nodes never run it. The
decision is made at commit time by the `config_lachesis` hex_config module,
not at install time — one image serves all roles.

**`systemctl is-enabled lachesis` reports `disabled` on a healthy node. This
is correct.** CubeCOS does not use systemd enablement for any platform service
(the image ships a catch-all `disable *` preset); `hex_config` re-commits on
every boot and starts the service itself. Running `systemctl enable lachesis`
is unnecessary and against platform convention — do not "fix" it.

Restart semantics come from the unit: `Restart=always` with `RestartSec=5`,
so a crashed agent returns within seconds and its BPF maps are re-created or
re-pinned on start. `systemctl reload lachesis` sends SIGHUP — the
[runtime.md](./runtime.md) reload path.

## What is on disk

| Path | What | Owner |
|---|---|---|
| `/usr/local/bin/lachesis` | the agent binary | RPM |
| `/usr/lib/systemd/system/lachesis.service` | the unit | RPM |
| `/etc/cube/lachesis/lachesis.yaml` | active config, **rendered at commit** | `config_lachesis` |
| `/var/lib/lachesis/network_agent_state.json` | the WAL — settled billing accumulators | agent |
| `/var/log/lachesis/lachesis.log` | structured JSON log (`StandardOutput=append:`) | agent |
| `/etc/logrotate.d/lachesis` | rotation: daily, `copytruncate`, 128M cap, compressed | RPM |

Two of these deserve care:

- **The config is not yours to edit.** `config_lachesis` renders it from a
  template at every commit, substituting the control VIP into the Kafka broker
  list. Hand edits survive only until the next commit (any settings change or
  reboot). Durable behavior changes belong in the tunables flow
  ([runtime.md](./runtime.md#the-hot-set)) or a platform change.
- **The WAL is billing state.** It carries the settled per-tenant traffic
  accumulators across restarts and upgrades (the platform migrates
  `/var/lib/lachesis` on firmware update). Deleting it does not lose history
  already scraped into Prometheus, but it resets the agent's exposed counter
  baselines — downstream billing must then rely on the counters-reset
  annotations. Treat it like a database, not a cache.

## What the platform provides (requirements)

| Requirement | Floor | Observed on 3.1.10 |
|---|---|---|
| Kernel | ≥ 5.10 (BPF features the programs use) | `6.12.95-1.el9` |
| bpffs | mounted at `/sys/fs/bpf` (map pinning) | mounted, `mode=700` |
| BTF | `/sys/kernel/btf/vmlinux` (CO-RE at load time) | present |
| Neutron credentials | `/etc/admin-openrc.sh` | present on every role |
| Kafka | control VIP `:9095`, topic `notifications.info` | reachable |

**Credentials.** The agent reads OpenStack credentials from
`/etc/admin-openrc.sh` via its `neutron.credentials_file` config — the same
file `config_keystone` writes on every CubeCOS node. No extra secret plumbing
exists, and none should be added per-agent. Note the file is mode `0664
root:admin`: group-readable credentials are a pre-existing platform property,
not something this agent introduces — do not widen it further.

**Kafka degradation.** Neutron events arrive over the platform Kafka
(`notifications.info` on the control VIP). If the broker is unreachable the
agent does not stop billing: it falls back to the periodic Neutron reconcile,
and topology changes are picked up within `reconcile.interval` instead of
immediately. Sustained Kafka loss therefore shows up as *staleness* (a new
VM's traffic attributed as `unknown` until the next reconcile), not as data
loss.

## Observing it

**Prometheus.** The platform scrapes every agent as job `lachesis-agent`
(30s interval) through a file_sd target list at
`/etc/prometheus/targets/lachesis.json`, regenerated every minute by a
platform cron (`/etc/cron.d/lachesis_targets`) so compute nodes joining or
leaving the cluster are reflected without operator action — worst case ~60s
plus one scrape interval. `up{job="lachesis-agent"} == 1` per node is the
first thing to check.

**Dashboards.** Grafana ships two provisioned dashboards: **CubeCOS ·
Telemetry Agent** (agent health: attach counts, map fill, collect latency,
reload results) and **CubeCOS · Traffic** (per-tenant/zone billing series).
The node picker is populated from the `instance` label, which carries the
hostname.

**Health check.** The agent is registered with the platform checker under the
Metrics group:

```bash
hex_cli -c cluster check Metrics        # lachesis(v) = healthy
hex_cli -c cluster check_repair Metrics # restarts it if down or wedged
hex_sdk health_lachesis_report          # single-service verdict
```

Error codes: `1` = daemon down, `2` = unit active but `/metrics` not
responding (a wedged agent — repair restarts it in both cases).

**SDK entry points.**

```bash
hex_sdk lachesis_metrics             # curl the local /metrics
hex_sdk lachesis_tc_filters          # taps carrying telemetry BPF filters
hex_sdk lachesis_prometheus_targets  # (control) regenerate the target list now
```

## Troubleshooting

- **Logs**: `/var/log/lachesis/lachesis.log` — structured JSON, one line per
  event (`component` field selects the subsystem). The journal only carries
  unit start/stop; the agent's own output goes to the file.
- **Is BPF attached?** `bpftool` is **not installed** on CubeCOS nodes, and
  piping through it silently reports nothing. Use tc directly:

  ```bash
  tc filter show dev <tap> ingress   # expect: tc_telemetry_in
  tc filter show dev <tap> egress    # expect: tc_telemetry_ou
  ```

  The kernel truncates BPF program names at 15 characters — the egress
  program really is named `tc_telemetry_out`; grepping for the full name
  matches nothing. `hex_sdk lachesis_tc_filters` wraps this per-tap check.
- **A node missing from the dashboards** usually means it is missing from the
  target list: check `/etc/prometheus/targets/lachesis.json` on the control
  node, and `hex_sdk lachesis_prometheus_targets` to regenerate immediately
  rather than waiting for the cron.

## Teardown

**The agent does not detach its TC filters on shutdown — by design.** Traffic
accounting must survive agent restarts without a counter gap, so `systemctl
stop lachesis` leaves the BPF programs attached and counting. Stopping the
service is therefore *not* enough to stop packet processing on the taps.

To actually remove the datapath from a node:

1. Stop the service: `systemctl stop lachesis` (remember `hex_config` will
   start it again at the next commit unless the node's role changed).
2. List affected taps: `hex_sdk lachesis_tc_filters`.
3. On each tap, inspect before deleting — **other subsystems share the
   `clsact` qdisc**, so a blanket `tc qdisc del ... clsact` can destroy
   filters that are not ours:

   ```bash
   tc filter show dev <tap> ingress   # note pref of the tc_telemetry_* entry
   tc filter del dev <tap> ingress pref <pref>
   tc filter show dev <tap> egress
   tc filter del dev <tap> egress pref <pref>
   ```

   Only if `tc filter show` proves the telemetry filters are the *sole* users
   of the qdisc is `tc qdisc del dev <tap> clsact` a safe shortcut.
4. Pinned maps live under `/sys/fs/bpf`; they are released once no program
   references them and the pins are removed.
