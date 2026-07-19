<!-- PR title: a natural sentence, no prefix (e.g. "Settle dying flows' bytes so per-tenant series stay monotonic") -->

## Closes
Closes #
<!-- Story lives in the scrum repo? Use: Closes bigstack-oss/cubecos#<n> -->

## What & why
<!-- What changed and why — enough context for a reviewer who didn't watch it happen. -->

## Test plan
- [ ] Unit — `task test`
- [ ] Integration — `task test-integration` (Docker, BPF caps)
- [ ] Bench-gate — `task bench-gate` (hot-path changes only)
- [ ] Scenario — `scenariotest run <name>`
- [ ] Manual e2e on a live cluster

## Live validation (optional)
<!-- Detail behind the Scenario / Manual-e2e boxes, when you ran them: which env
     (dev-cmp | cc), date, and the /metrics deltas or behaviour you observed. -->

## Scope / deliberately not touched
<!-- Optional — what you left out on purpose, to keep the change surgical. -->

## Notes
<!-- Optional — reviewer notes, risk / rollback, follow-ups.
     Touches billing / packet / boot / GC? Say which contract(s) in docs/architecture/contracts.md it
     affects and how this PR preserves them. -->

## DoD
- [ ] Linked issue's DoD met, incl. **Handbook knowledge update** (`/bigstack-core:save-to-handbook`)
