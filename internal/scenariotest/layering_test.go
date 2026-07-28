package scenariotest_test

import (
	"os/exec"
	"strings"
	"testing"
)

// corePkg is the harness core; everything under it is a sub-package.
const corePkg = "github.com/bigstack-oss/lachesis/internal/scenariotest"

// TestCoreImportsNoSubpackage enforces the one rule the package split
// rests on: sub-packages import the core, never the other way around
// (doc.go, "Layering"). Without it the split is cosmetic — the first
// core→sub-package edge re-tangles the graph and the next reader has no
// way to tell which direction was intended.
//
// The same discipline, machine-checked, is why Kubernetes' e2e
// framework keeps a .import-restrictions file next to its core: "sub
// packages get to use the framework, not the other way around".
func TestCoreImportsNoSubpackage(t *testing.T) {
	for _, imp := range imports(t, corePkg) {
		if strings.HasPrefix(imp, corePkg+"/") {
			t.Errorf("the core imports its own sub-package %s\n"+
				"sub-packages import the core, never the reverse — move the shared\n"+
				"declaration down into the core instead of reaching up from it", imp)
		}
	}
}

// TestSubpackagesImportOnlyTheCore keeps the tree one level deep in
// dependency terms: a sub-package may lean on the core (and on the
// phase packages beneath it), but a driver reaching sideways into
// another driver would reintroduce exactly the tangle this split
// removed. Only the composed layers — steps and run — may depend on
// other sub-packages.
func TestSubpackagesImportOnlyTheCore(t *testing.T) {
	// Drivers are leaves by construction: they wrap one external system.
	for _, leaf := range []string{"openstack", "agentmetrics", "remote"} {
		for _, imp := range imports(t, corePkg+"/"+leaf) {
			if strings.HasPrefix(imp, corePkg+"/") {
				t.Errorf("driver %s imports sibling sub-package %s — drivers are leaves; "+
					"put anything shared in the core", leaf, imp)
			}
		}
	}
}

// imports lists pkg's direct imports, skipping the package entirely if
// it does not exist yet (the tree grows a package at a time).
func imports(t *testing.T, pkg string) []string {
	t.Helper()
	out, err := exec.Command("go", "list", "-f", "{{range .Imports}}{{println .}}{{end}}", pkg).Output()
	if err != nil {
		t.Skipf("go list %s: %v (package not present)", pkg, err)
	}
	return strings.Fields(string(out))
}
