# Architecture

The design narrative for the lachesis telemetry agent — per-tenant, line-rate
network telemetry for OpenStack via eBPF TC. The chapters are ordered: read
top to bottom and you have read the whole design, the way a single design
document would read. Each chapter ends with a `Next:` link, so you can also
just start at the first one.

| # | Chapter | One-liner |
|---|---|---|
| 1 | [overview.md](./overview.md) | The problem, the goals, the four layers, and why TC-at-the-tap |
| 2 | [data-structures.md](./data-structures.md) | The three BPF maps, the Go stores, the WAL, the Lingering Ghost, and settled bytes |
| 3 | [packet-classification.md](./packet-classification.md) | The per-packet kernel algorithm: zones, the directional swap, the hybrid MAC-first lookup |
| 4 | [trie-construction.md](./trie-construction.md) | How cold-start assembles the LPM trie: the five-step algorithm and the static-route resolver |
| 5 | [octavia.md](./octavia.md) | LB attribution design — two connections, the Amphora MAC flag *(designed, not yet built)* |
| 6 | [scenarios.md](./scenarios.md) | Twelve traffic walkthroughs, A–L, each mapped to its live regression |
| 7 | [edge-cases.md](./edge-cases.md) | What we can't count, what needs handling, what miscounts — and the honest accuracy ceiling |
| 8 | [boot-and-recovery.md](./boot-and-recovery.md) | The boot order and why it matters; outage policies; what survives a crash |
| 9 | [performance.md](./performance.md) | Memory model, per-packet CPU cost, scrape and WAL costs, scalability ceiling |
| 10 | [metrics.md](./metrics.md) | Every exported metric: billing families, label contract, health catalog, SLO targets |
| 11 | [billing.md](./billing.md) | The product semantics: charging postures, the consumption contract, the revenue-leak SLO, per-server export |
| 12 | [contracts.md](./contracts.md) | The seven implementation contracts and the deferred-work register |

Reference material outside the sequence:

- [primer.md](./primer.md) — concept primer (eBPF, TC, BTF, OVN, Octavia, …) and glossary. If a term in any chapter is unfamiliar, it's explained here.

Decision records — every considered-and-rejected alternative with its
reasoning — live in [../adr/](../adr/README.md). Contributor-facing material
(testing strategy, code conventions) lives in
[../development/](../development/); operator material in
[../operations/](../operations/).

**For implementers:** [contracts.md](./contracts.md) is the safety net — seven
properties that must hold in any build, each traceable to the chapter that
motivates it. Code comments cite these chapters by heading anchor; a guard
test in the repo fails CI if a cited file or anchor disappears, so the links
you see in source are trustworthy.
