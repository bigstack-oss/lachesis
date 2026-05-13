## Bug
<!-- One-line description. Link the issue, alert, or incident report. -->

## Repro
<!-- Concrete reproduction steps:
     - which env (staging cluster / local)
     - what to run
     - what to grep in logs / Prometheus / WAL
     - or a failing test name -->

## Root cause
<!-- Be specific. Avoid generic labels like "race condition" or "off-by-one".
     Name the variables, the goroutines, the order of operations.
     If the cause is a violated invariant from CLAUDE.md or DESIGN.md, cite it. -->

## Fix
<!-- What this PR does to fix it. Keep it narrow — no drive-by refactors.
     If you noticed adjacent issues, mention them but don't fix them here. -->

## Regression test
- [ ] A test exists that fails on `develop` and passes with this PR
<!-- If you can't add one, explain why (e.g. requires real hardware, dependent on
     timing) and how we'll catch a regression instead. -->

## Risk
<!-- What else could this break? Anything subtle in delta math, boot ordering,
     or kernel-userspace consistency? Rollback plan if it goes sideways? -->
