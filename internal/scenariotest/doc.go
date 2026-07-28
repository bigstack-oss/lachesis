// Package scenariotest is the core of the live-validation harness: the
// scenario DSL, the step seam, the run-state, the report, and the
// interfaces through which everything reaches a real cluster.
//
// # Layering
//
// The harness is one core package plus a set of sub-packages, and the
// dependency edge only ever points one way:
//
//	sub-packages import the core; the core imports no sub-package.
//
// That rule is what keeps the split real rather than cosmetic, and
// [TestCoreImportsNoSubpackage] enforces it. Everything the core needs
// from the outside world it declares here as an interface ([Cloud],
// [MetricsSource], [VMExec]) or as a plain value type; the live
// implementations live below it.
//
//	scenariotest            the core — DSL, Step/StepEnv, RunState, report, seams
//	  openstack/            Cloud, via gophercloud (split by OpenStack service)
//	  agentmetrics/         MetricsSource, via the agent's /metrics and /debug
//	  remote/               VMExec, via the system ssh binary
//	  agentctl/             agent-host lifecycle: systemd, config swap, state removal
//	  gate/                 the poll-until-predicate waits every phase shares
//	  realize/ drive/ assert/ down/ preflight/
//	                        the single-shot phases, each a Run(ctx, Options)
//	  steps/                the step vocabulary a scripted scenario is written in
//	  run/                  the orchestrator that composes the phases and the script
//
// A scenario is declared against the core plus steps/ and nothing else
// (see cmd/scenariotest/scenarios).
//
// # Archetype
//
// The harness is the repo's sanctioned CLI-harness shape rather than
// one of the four internal/ package archetypes: each phase package
// exposes a single-shot Run(ctx, Options) and all live IO sits behind
// the seams above (docs/development/conventions.md#package-anatomy).
package scenariotest
