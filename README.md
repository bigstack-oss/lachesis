<!-- PROJECT HEADER -->
<div align="left">
  <h2 align="left">📊 Lachesis</h2>
</div>

[![License][License-Image]][License-Url] [![made-with-Go][Go-Made-Image]][Go-Made-Url] [![Go Report Card][Go-Report-Image]][Go-Report-Url] [![CI][CI-Image]][CI-Url] [![CodeQL][CodeQL-Image]][CodeQL-Url] [![OpenSSF Scorecard][Scorecard-Image]][Scorecard-Url] [![GitHub issues][Github-Issue-Image]][Github-Issue-Url] [![GitHub last commit][GitHub-Last-Commit-Image]][GitHub-Last-Commit-Url]

⛩️ [Architecture] | 🛠️ [Operating] | 🧪 [Test strategy] | 👷 [Contributing]

<br/>

## 🥽 Overview

**Lachesis** is an eBPF-based network-telemetry daemon for OpenStack. It attributes every byte on a compute node to the tenant that owns it — classifying north-south and east-west traffic into billing zones, re-attributing Octavia load-balancer bytes to the real client tenant, and exposing per-tenant Prometheus counters at line rate via TC `clsact` hooks.

It runs as a root agent on OVN-based OpenStack (Yoga) compute nodes and is designed for **billing-grade** accounting: crash-resilient, monotonic per-tenant counters that survive agent restarts, kernel-map churn, and VM lifecycle events.

```
  L4  Prometheus + WAL      custom Collector · GlobalState · JSON write-ahead log
  L3  Go agent              scraper · delta math · Octavia attribution · Netlink watcher
  L2  OpenStack metadata    per-tenant zone trie + MAC map, synced from the Neutron API
  L1  eBPF (TC clsact)      tc_telemetry_in/out · PERCPU_HASH · LPM trie · mac_tenant_map
```

## ✨ Features

- **Per-tenant, per-zone, per-direction byte accounting** at line rate — the billing metric `lachesis_bytes_total{tenant_id,zone,direction}`.
- **Five traffic zones** — `same_tenant`, `infra`, `external`, `shared`, `other_tenant` — from a hybrid L2 MAC lookup plus an LPM zone trie.
- **Octavia re-attribution** — load-balancer bytes are folded back to the originating client tenant rather than the amphora.
- **eBPF TC data plane** — kernel-side aggregation in a `PERCPU_HASH`, no per-packet copies to userspace.
- **Crash-resilient by design** — a custom `prometheus.Collector` (no counter resets on restart), a JSON write-ahead log, and read-don't-clear kernel maps.

## 🚀 Quick start

The build is fully containerized (eBPF toolchain in Docker); the agent runs as root.

```bash
task setup      # pull the eBPF builder image
task generate   # bpf2go — compile telemetry.c, generate the loader
task binary     # build ./build/agent (linux/amd64)
```

Configure via a YAML file and/or `LACHESIS_*` environment variables (for example `LACHESIS_HTTP_LISTEN`, `LACHESIS_BPF_ATTACH_INTERFACES`). Prometheus metrics are served at the configured listener under the `lachesis_` prefix; see [Operating] for the full runbook and [Architecture] for the design and invariants.

## 🧑‍💻 Community

- [License](./LICENSE)
- [Contributing](./CONTRIBUTING.md)
- [Code of Conduct](./CODE_OF_CONDUCT.md)
- [Security](./SECURITY.md)

## 📄 License

Copyright (c) 2026 [Bigstack co., ltd](https://bigstack.co/)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

<!-- LINKS -->
[Architecture]: ./docs/DESIGN.md
[Operating]: ./docs/runtime.md
[Test strategy]: ./docs/test-strategy.md
[Contributing]: ./CONTRIBUTING.md
[License-Url]: https://www.apache.org/licenses/LICENSE-2.0
[License-Image]: https://img.shields.io/badge/License-Apache2-blue.svg
[Go-Made-Url]: https://go.dev/
[Go-Made-Image]: https://img.shields.io/badge/Made%20with-Go-1f425f.svg
[Go-Report-Url]: https://goreportcard.com/report/github.com/bigstack-oss/lachesis
[Go-Report-Image]: https://goreportcard.com/badge/github.com/bigstack-oss/lachesis
[CI-Url]: https://github.com/bigstack-oss/lachesis/actions/workflows/ci.yml
[CI-Image]: https://github.com/bigstack-oss/lachesis/actions/workflows/ci.yml/badge.svg?branch=develop
[CodeQL-Url]: https://github.com/bigstack-oss/lachesis/actions/workflows/codeql.yml
[CodeQL-Image]: https://github.com/bigstack-oss/lachesis/actions/workflows/codeql.yml/badge.svg?branch=develop
[Scorecard-Url]: https://scorecard.dev/viewer/?uri=github.com/bigstack-oss/lachesis
[Scorecard-Image]: https://api.scorecard.dev/projects/github.com/bigstack-oss/lachesis/badge
[Github-Issue-Url]: https://github.com/bigstack-oss/lachesis/issues
[Github-Issue-Image]: https://img.shields.io/github/issues/bigstack-oss/lachesis?color=brightgreen
[GitHub-Last-Commit-Url]: https://github.com/bigstack-oss/lachesis/commits/develop
[GitHub-Last-Commit-Image]: https://img.shields.io/github/last-commit/bigstack-oss/lachesis/develop
