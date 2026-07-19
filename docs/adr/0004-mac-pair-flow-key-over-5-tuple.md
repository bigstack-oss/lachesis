# ADR 0004 — MAC-pair + zone flow key over 5-tuple

**Status:** accepted

## Context

`(src_ip, dst_ip, src_port, dst_port, proto)` is the conventional flow key — what NetFlow uses, what conntrack uses, what every flow-analytics tool expects.

## Decision

Key the kernel counter map by `(src_mac, dst_mac, eth_proto, direction, dst_zone)` — 16 bytes ([data-structures.md](../architecture/data-structures.md#kernel-side-bpf-maps)).

1. **Cardinality explosion.** Each unique connection (browser tab, RPC call, BGP session) creates a new 5-tuple entry. A 50-VM node easily reaches >100k entries; the 65,536 cap is exhausted and pressure-relief GC churns constantly. MAC-pair scales with *topology*: ~850 entries on a 50-VM node, ~8,500 on a 500-VM node.
2. **Prometheus label explosion.** Exporting by 5-tuple ships millions of label combinations — the cardinality bomb that kills observability platforms.
3. **L4 ports add no billing signal.** We charge by tenant and zone. We don't bill TCP ports.

The companion decision — `dst_zone` (1 byte) in the key rather than the destination IP — is [ADR 0012](./0012-zone-code-in-key-over-ip-in-key.md).

## Consequences

- Map size and metric cardinality are bounded by topology, not traffic patterns.
- Per-connection analytics are impossible from this data — out of scope by design.

**When 5-tuple is the right answer:** flow-based intrusion detection, per-connection latency analytics, session reconstruction. Different problem.
