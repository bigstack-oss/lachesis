# ADR 0014 — In-band entry identity over inferred counter resets

**Status:** accepted

## Context

Userspace tracks each flow's bytes by **differencing** the kernel's cumulative
counter: `delta = current − LastEbpfRaw`. That subtraction is only meaningful if the
`telemetry_map` entry which produced `current` is the *same entry* that produced
`LastEbpfRaw`. Nothing in the data says whether it is.

The kernel owns that entry's lifetime, and it ends in several ways:

| Destruction path | Who removes the entry | How userspace learns |
|---|---|---|
| Pressure-relief GC | `gc.PressureReliever` | out-of-band call (`state.InvalidateBaseline`, added by lachesis#287) |
| UnresolvedBuffer TTL / cap fold | `unresolved.Buffer` | out-of-band (`state.Resolve` writes an explicit baseline) |
| Ghost sweep residual flows | `gc.GhostSweeper` | out-of-band (`Settle` folds and deletes the row) |
| Agent restart without pinned maps | the kernel, at map re-creation | **inferred** from `current < LastEbpfRaw` |
| u64 wraparound | never (theoretical) | **inferred** from `current < LastEbpfRaw` |

So entity identity is reconstructed two ways, both external to the data: by
**notification** (each deleter must remember to speak) and by **inference** (the
`current < lastRaw` guard in `state.AddDelta`, Contract 5).

Both are unsound in ways that produce wrong numbers rather than errors.

**Inference fails when resets are frequent.** The guard assumes a reset leaves `current`
far below `lastRaw`. That holds for a reboot or wraparound — one event, counter restarts
at ~0. It does not hold for eviction, which recurs at a cadence comparable to the flow's
own accumulation: the re-created entry climbs back into the same range as the old
baseline, `current >= lastRaw` reads as an ordinary advance, and `lastRaw` worth of
traffic is discarded. Measured on dev-cmp: **17.6 % of transmitted bytes counted**
(lachesis#287).

**Notification fails when someone forgets.** Nothing in the types, tests, or docs
states the obligation. Pressure relief deleted entries without telling `GlobalState`
for as long as the feature has existed, and no compiler error, test failure, or metric
flagged it — the only symptom was under-billing, which is invisible unless something
asserts on it. A fourth deletion path added later inherits the bug by default.

Both failure modes are the same root cause: **identity is tracked out-of-band from the
thing whose identity it describes.**

## Decision

Carry entry identity **in the map value**, and make userspace compare identity rather
than infer it from magnitudes.

Add one field to the value struct, stamped exactly once, in the branch that creates a
new entry:

```c
struct flow_metrics {
	__u64 bytes;
	__u64 packets;
	__u64 last_seen_ns;
	__u64 created_ns;   /* set only in the else-branch, never updated */
};
```

Userspace keeps the last-seen `created_ns` alongside `LastEbpfRaw` and applies a
three-way rule:

- stored stamp is **0** → identity unknown (a v6 WAL restore, or a baseline seeded
  before the stamp existed) → fall back to the value guard for this one observation,
  then adopt the kernel's stamp. Not treated as a reset — see the migration note below;
- stamps **differ** → **a different entry** → `delta = current` (count it whole);
- stamps **match** → same entry → `delta = current − lastRaw`, as today.

**Per-CPU correctness.** `telemetry_map` is a `PERCPU_HASH`, and only the CPU that
creates an entry runs the else-branch; the other CPUs' slots are zero-initialised and
subsequently take the `if (val)` path, so they never stamp. The reader already folds
slots with `sum` for counters and **`max` for `LastSeenNs`**
(`agent/reader_linux.go`); `created_ns` folds with `max` for the same reason, which
yields the creating CPU's stamp and, after a delete-and-recreate (all slots zeroed),
the new one. No new aggregation rule is introduced.

## Consequences

**One mechanism replaces three.** The identity signal subsumes:

- the `current < lastRaw` inference (Contract 5's guard) for eviction *and* for the
  unpinned-restart case, where the map is re-created empty while the WAL restores a
  baseline for entries that no longer exist;
- the `gc.BaselineInvalidator` notification added for lachesis#287;
- the implicit obligation on any *future* deleter, because the signal rides with the
  data instead of depending on the deleter's good manners.

**Contract 5 narrows to its original job.** The wraparound guard stays for genuine u64
overflow (~467 years at 10 Gbps), which no in-band stamp detects. It stops being the
catch-all for "the counter went backwards".

**Memory is the real cost, and it is not small.** `PERCPU_HASH` allocates the value per
*possible* CPU. At `max_entries = 65536`, the value grows 24 B → 32 B:

| Possible CPUs | today (24 B) | with `created_ns` (32 B) | delta |
|---|---|---|---|
| 8 | 12 MiB | 16 MiB | +4 MiB |
| 32 | 48 MiB | 64 MiB | +16 MiB |
| 64 | 96 MiB | 128 MiB | +32 MiB |

A +33 % increase in the map's locked memory. If that is unacceptable on the target
hardware the honest lever is `max_entries`, which is currently 2× a headroom estimate
rather than a measured ceiling — but that is a separate decision and should not be
bundled in.

**Migration is not free:**

- `bpf/telemetry.c` change → `task generate` → regenerated bindings;
- WAL schema bump (v7) to persist the last-seen `created_ns`. **Zero must mean
  "unknown", not "different entry".** A v6 WAL decodes the field as 0; if that were
  read as a mismatch, the first post-restart scrape of a *pinned* (surviving) map would
  count its entire cumulative a second time — a large double-count, not a bounded one.
  The rule is therefore three-way: unknown (0) falls back to the value guard for that
  one observation and then adopts the kernel's stamp; a differing non-zero stamp is a
  new entry; equal stamps diff as today. `bpf_ktime_get_ns()` is never 0 in practice,
  so 0 is a safe sentinel;
- one extra store on the entry-creation path only. The hot path (`if (val)`) is
  untouched, so the bench-gate's zero-allocation and per-packet budgets are unaffected.

**What it does not fix.** The drain→delete window: the scraper reads at T0 and eviction
deletes at T1 > T0, so bytes the kernel counts in (T0, T1] are destroyed unread.
Sub-millisecond and orthogonal to identity — no stamp recovers a value nobody read.

## Alternatives considered

**Keep out-of-band notification (the status quo after lachesis#287).** Correct today,
and cheap. Rejected as the *end state* because it leaves the obligation invisible: the
next deletion path inherits the bug, and the only thing standing between us and silent
under-billing is that someone remembers. Worth keeping until this ADR is accepted —
which is why lachesis#287 shipped that way.

**Read-and-clear (`bpf_map_lookup_and_delete_elem`).** Removes differencing entirely:
no cumulative, no baseline, no identity problem. Rejected — it trades this bug class for
a worse one. Read-don't-clear is what makes agent-crash recovery lossless
([ADR 0005](./0005-pressure-relief-gc-over-lru-hash.md), the "never clear the map"
corollary; [boot-and-recovery.md](../architecture/boot-and-recovery.md)): the kernel
holds the counter, so a crash between scrapes loses nothing. Clearing also races the
datapath for bytes arriving between read and clear.

**A userspace-only generation counter.** Have GC increment a per-key epoch on eviction
instead of the kernel stamping one. Rejected — it is the notification model wearing a
different hat: it still requires every deleter to participate, and still cannot see a
kernel-side reset (unpinned restart) that no deleter caused.

**Widen the flow key with a generation.** Makes each incarnation a distinct key, so no
identity tracking is needed at all. Rejected — it multiplies key cardinality per
eviction, defeating [ADR 0004](./0004-mac-pair-flow-key-over-5-tuple.md)'s bounded
key-space, and every incarnation would surface as a separate series.
