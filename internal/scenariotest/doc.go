// Package scenariotest is the core of the live-validation harness: the
// scenario DSL, the step seam, the run-state, the report, and the
// [Cloud] / [MetricsSource] / [VMExec] interfaces through which
// everything reaches a real cluster.
//
// ONE layering rule holds the tree together: sub-packages import the
// core; the core imports no sub-package. Anything the core needs from
// outside it declares here as an interface or a plain value type.
// [TestCoreImportsNoSubpackage] enforces it — a sub-package needing
// something shared moves it DOWN into the core, never reaches up.
//
// docs/development/conventions.md#the-scenariotest-tree
package scenariotest
