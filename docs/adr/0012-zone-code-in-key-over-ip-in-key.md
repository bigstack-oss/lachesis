# ADR 0012 — Zone code in flow key over IP in flow key

**Status:** accepted

## Context

The flow key needs an L3 discriminator (the router-MAC ambiguity — [data-structures.md](../architecture/data-structures.md#kernel-side-bpf-maps)). Keeping `dst_ip` (maybe `src_ip`) in the BPF map key would let classification happen at scrape time in Go, with no in-kernel trie lookup.

## Decision

Store a 1-byte `dst_zone` code, classified in the kernel at packet time; never store IPs in the key.

1. **Cardinality explosion (the ADR 0004 problem again).** Every distinct remote IP creates a new entry — `1.2.3.4`, `1.2.3.5`, `1.2.3.6` are separate map entries even when they're all just "the internet".
2. **Breaks IPv6 cleanly.** v6 addresses are 16 bytes vs v4's 4 — different key sizes need different maps or padding tricks. A 1-byte zone code keeps the key uniform across IP versions.
3. **Loses kernel-side classification.** With IPs in the key, the kernel is just a counter and every scrape re-derives zones in Go against *current* metadata — historical flows would reclassify whenever metadata changes. Baking the zone at packet time freezes the classification that was true when the bytes flowed.

## Consequences

- The key stays 16 bytes and topology-bounded.
- The zone is immutable per flow entry — which is why boot order and trie-update order matter so much (a wrong zone written under a mispopulated trie is permanent; see [boot-and-recovery.md](../architecture/boot-and-recovery.md) and [trie-construction.md](../architecture/trie-construction.md#incremental-updates)).
