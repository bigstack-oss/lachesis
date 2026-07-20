# Architecture Decision Records

Every considered-and-rejected alternative, with its reasoning, in Nygard format
(context → decision → consequences). Numbered files are full records; the table
below is the complete decision register — decisions whose full reasoning lives
in an architecture chapter link there instead of carrying a record of their own.

| Decision | Chosen | Rejected | Where |
|---|---|---|---|
| eBPF hook | TC clsact (ingress + egress) | XDP | [ADR 0001](./0001-tc-clsact-over-xdp.md) |
| Telemetry approach | eBPF TC at the tap (exact) | sFlow at OVS / NIC (sampled) | [ADR 0002](./0002-per-tap-ebpf-over-ovs-sflow-sampling.md) |
| OpenStack metadata source | Neutron v2.0 API | Direct MySQL | [ADR 0003](./0003-neutron-api-over-direct-mysql.md) |
| Flow-key cardinality | MAC-pair + dst_zone | 5-tuple `(src_ip, dst_ip, ports)` | [ADR 0004](./0004-mac-pair-flow-key-over-5-tuple.md) |
| Map capacity relief | Pressure-relief GC + fill gauges | PERCPU_LRU_HASH | [ADR 0005](./0005-pressure-relief-gc-over-lru-hash.md) |
| MAC→tenant cache | 64-shard RWMutex | `sync.Map` | [ADR 0006](./0006-sharded-rwmutex-over-sync-map.md) |
| Prometheus storage | Custom collector + WAL | `CounterVec` | [ADR 0007](./0007-custom-collector-over-countervec.md) |
| Per-packet zone resolution | Hybrid: MAC-first, LPM fallback | Always-LPM | [ADR 0008](./0008-hybrid-mac-first-over-always-lpm.md) |
| Static route resolution | Nexthop trace through port topology | CIDR-only lookup | [ADR 0009](./0009-nexthop-trace-over-cidr-only-lookup.md) |
| Packet processing plane | Kernel eBPF | Userspace AF_PACKET/libpcap parsing | [ADR 0010](./0010-kernel-ebpf-over-userspace-parsing.md) |
| OS-level guest routes | Safe-billing EXTERNAL fallback | In-VM agent | [ADR 0011](./0011-no-in-vm-agent.md) |
| L3 discriminator in flow key | 1-byte zone code (kernel-classified) | dst_ip in key | [ADR 0012](./0012-zone-code-in-key-over-ip-in-key.md) |
| Billing export | Pull: cumulative counters on `/metrics` | Push: usage records to Kafka / billing API / Pushgateway | [ADR 0013](./0013-pull-metrics-over-push-export.md) |
| Octavia LB attribution | Amphora MAC flag in `mac_tenant_map` | Conntrack tuple recovery as primary mechanism | [octavia.md](../architecture/octavia.md) — HAProxy creates two distinct TCP connections (verified empirically); client_ip isn't recoverable at the backend's tap; MAC-flag attribution works at every tap and matches AWS/GCP segment-by-segment billing |
| Segment 1 zone (LB) | Optional `bpf_skb_ct_lookup` at the Amphora's tap | Always EXTERNAL | [octavia.md](../architecture/octavia.md) — conntrack refines the zone when the client is internal; EXTERNAL is the safe-billing fallback on miss |
| Crash resilience | Read-don't-clear + WAL + counter-map pinning (zero-loss agent-crash recovery) | Clear map after each scrape | [boot-and-recovery.md](../architecture/boot-and-recovery.md) |
| Kernel counter concurrency | PERCPU_HASH | Global hash + atomics | [data-structures.md](../architecture/data-structures.md#kernel-side-bpf-maps), [primer](../architecture/primer.md#percpu_hash) — atomic contention at 10 Gbps × 32 cores becomes the bottleneck |
| VM/subnet deletion | Lingering Ghost (60s TTL) | Immediate eviction | [data-structures.md](../architecture/data-structures.md#lingering-ghost) — dying FIN/RST packets must still attribute correctly |
| Interface lifecycle | Netlink Watcher + Registry | Static tap list | [boot-and-recovery.md](../architecture/boot-and-recovery.md) — OpenStack creates/destroys taps dynamically |
| Crash-leftover filters | Zombie Hunter on startup | Ignore / let attach fail | [boot-and-recovery.md](../architecture/boot-and-recovery.md) — stacked duplicates silently double-count |
| Shared-network attribution | ZONE_SHARED (distinct zone) | Guess SAME for owner / OTHER for others | [trie-construction.md](../architecture/trie-construction.md#the-five-step-algorithm) — the trie can't resolve per-VM ownership inside a shared CIDR; either guess systematically mis-bills one side |
| VM-appliance nexthop | `zone_for(appliance_tenant, source_tenant)` | Blanket EXTERNAL fallback | [trie-construction.md](../architecture/trie-construction.md#the-static-route-resolver) — the appliance's tenant is Neutron-visible; double-billing caveat documented |
| Control-plane target | OVN-first (single architecture) | Dual-track OVN + traditional Neutron | [contracts.md](../architecture/contracts.md#deferred-work) item 2 — verified deployments run OVN exclusively; supporting traditional Neutron would be infra-for-absent-code |
| Chassis MAC enumeration | Standard port API, broadened `device_owner` filter | OVN Southbound / OVS DB query | [ADR 0003](./0003-neutron-api-over-direct-mysql.md) — DB-direct reintroduces the schema-migration and blast-radius problems |

## Adding a record

New decision with a rejected alternative worth remembering → next number,
same format: **Status / Context / Decision (numbered reasons) / Consequences**,
plus a "when the rejected option is right" note if one exists. Add a row here.
Records are immutable once accepted; a reversal gets a new record that
supersedes the old one (note it in both).
