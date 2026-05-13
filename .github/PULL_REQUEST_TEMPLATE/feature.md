## Sprint
<!-- Which sprint from docs/sprint-plan.md? e.g. "Sprint 1 — hybrid zone lookup".
     1 sprint = 1 PR. If this PR spans multiple sprints, split it. -->

## Summary
<!-- 2-3 bullets. What changed and why. Keep it narrow — surgical changes only.
     If the diff includes drive-by cleanups or refactors not tied to the sprint, call them out. -->
-
-

## Test plan
<!-- Tick what was run. Add specifics (test names, scenarios) where useful. -->
- [ ] Unit — `task test`
- [ ] Integration — `task test-integration` (Docker, BPF caps)
- [ ] Bench-gate — `task bench-gate` (required if hot-path code touched: `Collect()`, `BatchLookupAndProcess()`, packet path)

## Contract impact
<!-- The 5 Implementation Contracts from CLAUDE.md. Tick any this PR touches
     and explain how the contract is preserved (or why a change is justified). -->
- [ ] UnresolvedBuffer capped at 10k with LRU eviction
- [ ] `Collect()` holds RLock around full GlobalState iteration
- [ ] TenantMeta pointer-replace, never in-place mutation
- [ ] Boot sequence enforced via explicit sync points
- [ ] u64 wraparound guard in delta math
- [ ] None of the above

## Performance
<!-- Hot-path PRs only. Paste `benchstat` output or write "N/A — not on hot path".
     Allocations on hot paths must be zero. -->

## DESIGN.md sections touched
<!-- e.g. §4.2 (directional swap), §C.8 (hybrid lookup). Helps reviewers locate the
     spec the code is implementing. -->
