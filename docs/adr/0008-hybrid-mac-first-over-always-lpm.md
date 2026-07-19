# ADR 0008 — Hybrid MAC-first lookup over always-LPM

**Status:** accepted

## Context

Zone classification could use only the LPM trie — drop the MAC-first comparison from the per-packet path. Simpler kernel code, one lookup mechanism.

## Decision

Look up the peer MAC in `mac_tenant_map` first; compare tenant IDs on a hit. Fall back to the LPM trie only when the peer MAC is unknown (routed/external traffic). See [packet-classification.md](../architecture/packet-classification.md#the-hybrid-lookup-explained).

1. **CIDR ambiguity for direct L2 traffic.** When VM-A talks directly to VM-B in the same subnet, the trie answer depends on subnet entries being correctly populated. If cold-start has a bug or stale data, classification is wrong. MAC comparison is *exact* and trie-independent.
2. **Reduces operational risk surface.** With MAC-first, a misconfigured trie only affects routed traffic; direct VM-to-VM classification keeps working. Failure modes are more localized.
3. **Tiny additional cost.** One extra hash lookup per packet (~50 ns) — well within the overhead budget.

## Consequences

- The trie only needs routed-traffic rows; shared-network L2 traffic classifies exactly even though the trie deliberately answers `SHARED` there ([trie-construction.md](../architecture/trie-construction.md#the-five-step-algorithm)).
- `dst_zone` in the flow key must be present for the routed case anyway ([ADR 0012](./0012-zone-code-in-key-over-ip-in-key.md)).

**When always-LPM is right:** a simpler test/demo build where routed-vs-direct distinction doesn't matter.
