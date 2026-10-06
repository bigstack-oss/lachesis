# ADR 0015 — Bucketed L4 protocol class in the flow key

**Status:** proposed

## Context

The CubeCOS dashboards that replaced the removed sFlow panels can split a tenant's or a
VM's traffic by zone, direction, server and port, but not by transport protocol: the
flow key carries the L2 EtherType (`eth_proto`) and no L4 information at all. The
"Application" and "Layer 4 TCP / UDP / Others" views the sFlow panels used to offer have
no data source.

[ADR 0004](./0004-mac-pair-flow-key-over-5-tuple.md) rejected the 5-tuple because it
scales with connection count. A protocol *class* is a different quantity: it is a fixed,
small enum per (MAC pair, direction, zone), so it multiplies the key space by a bounded
constant rather than by traffic. This record decides whether that constant is worth
paying, and how to add it without disturbing the billing families.

## Decision

Add a 1-byte **L4 protocol class** to `flow_key`, classified in the kernel, and expose it
through a **separate metric family** on the port leaf. The billing families keep their
exact label sets and values.

1. **Encoding: four classes plus a reserved zero.** `enum l4_proto { L4_UNKNOWN = 0,
   L4_TCP = 1, L4_UDP = 2, L4_ICMP = 3, L4_OTHER = 4 }`. Values are stable — they are
   persisted to the WAL. The kernel never writes `L4_UNKNOWN`; it marks rows restored
   from a pre-v9 WAL (decision 4). ICMPv4 (1) and ICMPv6 (58) share `L4_ICMP`. Every
   other IP protocol — GRE, ESP, SCTP, … — is `L4_OTHER`. Storing the raw IP protocol
   number instead would hand any VM up to 256 keys per MAC pair to mint at will (the
   [edge-cases.md](../architecture/edge-cases.md) row 10 spray vector) for a distinction
   no dashboard draws.

2. **Classification: one header byte, no chain walk.** IPv4 reads `iph->protocol`;
   non-first fragments carry the same field, so they classify correctly. IPv6 reads the
   fixed header's `nexthdr`; an extension header (hop-by-hop, routing, fragment,
   destination options, AH, ESP) classifies as `L4_OTHER` rather than walking the chain,
   which would need a verifier-bounded loop for a rare case. Both bytes lie inside the
   34 bytes the program already pulls, so the hot path gains one bounds check and one
   load. Non-IP frames stay uncounted, exactly as today (`STAT_SKIPPED_ETHERTYPE`); the
   class applies only to frames that were already counted.

3. **Key layout: append `l4_proto` plus an explicit pad, 16 → 18 bytes.** The new byte
   and a zeroed `pad` byte go after `dst_zone`. 18 bytes is naturally aligned for the
   key's widest member (the `u16` `eth_proto`), so the layout has no implicit padding
   whether or not the compiler honours `packed`; the explicit pad keeps the kernel's
   byte-wise hash deterministic and is the Cilium `pkg/maps` convention (named padding
   fields, always zero). `packed` stays for continuity. Narrowing `eth_proto` to make
   room was rejected: it would change the meaning of a field the WAL already persists.

4. **WAL v9: `l4_proto` on each flow key; v7 and v8 rows restore as `L4_UNKNOWN`.** v8 is
   the per-row attribution `owner` (the bug 317 fix); v9 keeps it and adds this field. The
   field is additive and decodes as 0 from a v7 or v8 file. Those rows keep their
   cumulative totals (and a v8 row its `owner`) under the `L4_UNKNOWN` class. The kernel
   never emits that class, so no kernel entry ever matches a restored pre-v9 row again —
   its `LastEbpfRaw` and `created_ns` are never
   consulted, and the [ADR 0014](./0014-in-band-entry-identity-over-inferred-resets.md)
   three-way rule is untouched (a stored stamp of 0 still means "identity unknown",
   never a reset). The upgrade boot finds the pinned 16-byte-key map incompatible, so
   `loadCollection` removes and recreates it; every v9 kernel entry is therefore a
   brand-new key, and `ApplyDelta` counts it whole. Totals neither double nor drop
   across the upgrade. The legacy rows age out as their ports churn through the normal
   settle paths.

5. **Exposure: a separate port-leaf family; billing families sum over the class.**
   `lachesis_port_proto_bytes_total` and `lachesis_port_proto_packets_total` with labels
   `{server_id, port_id, tenant_id, proto, direction}`, where `proto` is `tcp`, `udp`,
   `icmp`, `other` or `unknown`. The four billing tiers aggregate on keys that do not
   include the class, so their series are byte-identical to today. Adding a `proto`
   label to them instead would change every billing series' identity at upgrade — the
   old series end, new ones start from zero, and the billing ETL's endpoint subtraction
   breaks (Contract 7).

6. **The protocol family is mortal, like the port leaf — no settled absorber.** It is a
   breakdown of `lachesis_port_bytes_total`: at any instant, summing it over `proto`
   equals the port family summed over `zone` and `external_network` for the same port.
   Contract 7 already names the port family as the mortal leaf with no absorber, on
   purpose; a finer breakdown of that leaf inherits its lifetime. An absorber would need
   a new WAL section and a lifecycle owner for a series no billing consumer reads.
   `zone` and `external_network` are left off to keep the family at
   `ports × classes-in-use × 2` series; a zone split by protocol is a dashboard join
   away from the port family if it is ever wanted.

## Consequences

- **Map sizing.** `max_entries` stays 65,536. The entry estimate becomes
  `entries ≈ Σ_ports (peer MACs × directions × zones-in-use × classes-in-use)`. Classes
  in use per MAC pair are typically 1–2 (TCP, plus UDP for DNS), at most 4, so the
  topology estimates scale by ~2× (~1,700 entries on a 50-VM node, ~17,000 on a 500-VM
  node) and by 4× in the worst case (~34,000) — still under the 80% pressure-relief
  watermark (52,428). The formula lives in the comment on `telemetry_map`.
- **Memory.** The map is preallocated, so its size does not change with fill. The
  kernel rounds the hash element's key to 8 bytes, so 16 → 18 costs +8 bytes per
  element: +512 KiB per node at 65,536 entries, independent of CPU count.
- **One-time upgrade loss, bounded.** The incompatible pin is recreated, so the bytes
  the old map counted after the last pre-upgrade scrape — at most one scrape interval plus the
  restart gap — are not recovered. This is the accepted cost of every map-ABI bump
  ([boot-and-recovery.md](../architecture/boot-and-recovery.md)); the v6 → v7 value
  change in ADR 0014 paid the same.
- **Series.** The new family adds about `ports × 2 classes × 2 directions` series per
  node per metric (4,000 for 1,000 ports), plus one `unknown` series per pre-upgrade port
  and direction until it churns.
- **What it does not give.** Destination ports and peer addresses stay out of scope
  (ADR 0004, [ADR 0012](./0012-zone-code-in-key-over-ip-in-key.md)). A dashboard shows
  "TCP", not ":443 vs :22".

## Alternatives considered

**Raw IP protocol number in the key.** One byte either way, and more precise. Rejected —
it lets any VM mint up to 256 keys per MAC pair with crafted packets, and the extra
precision serves no consumer. If a fifth class is ever needed, it is a new enum value.

**A second counter map keyed `(vm_mac, l4_proto, direction)`.** Leaves `flow_key`, the
WAL and the delta math alone. Rejected — every packet pays a second map update (~20–30
ns against an 82–110 ns budget), and the map needs its own scrape, delta state, entry
identity, pressure relief and WAL section: a parallel copy of the machinery this one
byte reuses.

**A `proto` label on the existing families.** No new family to document. Rejected — it
renames every billing series at upgrade (decision 5).

**Walking the IPv6 extension-header chain.** Classifies a TCP segment behind a
hop-by-hop header correctly. Rejected for now — a verifier-bounded loop and extra pulls
on the hot path for traffic that is rare on tenant networks. Revisit if `other` on IPv6
turns out to hide real volume.

**When the raw protocol number is the right answer:** protocol-level abuse detection
(e.g. spotting GRE or ESP tunnels by number) — a security product, not byte metering.
