// Package scenarios is the canonical registry of scenariotest
// scenarios. Each scenario gets one file declaring a builder
// function; [All] returns the registered set. Adding a new scenario
// is one new file plus one entry in [All].
//
// The registered set covers all five billing zones — same_tenant,
// infra, external, shared, other_tenant — one scenario each, so the
// harness can validate per-zone attribution end to end. (The sixth
// zone, "miss", is the unclassified bucket and is not a target.)
package scenarios

import (
	"fmt"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
)

// All returns every registered scenario, freshly constructed each
// call. Builder functions are stateless; rebuilding keeps callers
// from accidentally mutating shared state.
func All() []*scenariotest.Scenario {
	return []*scenariotest.Scenario{
		twoVMsSameTenant(),
		vmToGateway(),
		vmToInternet(),
		crossTenantShared(),
		crossTenantRouted(),
		macReuse(),
		multiExternalPath(),
		crossHostSameTenant(),
		liveMigrationContinuity(),
		walRestartContinuity(),
		agentColdRestart(),
		liveMigrateRoundTrip(),
		multiPortPartialDelete(),
		portRecreateSameServer(),
		interfaceDetachReattach(),
		macPinnedPortRecreate(),
		portMoveAcrossServers(),
		multicastZone(),
		fipIngressRx(),
		sameTenantRouted(),
		fipHairpin(),
		byteAccuracyBounds(),
		resolverCycle(),
		resolverDanglingRoute(),
		extrarouteSameTenant(),
		multiHopChain(),
		maxHopsAtLimit(),
		maxHopsExceeded(),
		spoofedMACUntracked(),
		vrrpVMACLeak(),
		extrarouteMutation(),
		routerRegateway(),
		ghostGraceWindow(),
		unresolvedLatebind(),
		vmApplianceNexthop(),
		gcPressureRelief(),
	}
}

// Get returns the scenario named name, or an error listing the
// known names.
func Get(name string) (*scenariotest.Scenario, error) {
	var names []string
	for _, s := range All() {
		if s.Name == name {
			return s, nil
		}
		names = append(names, s.Name)
	}
	return nil, fmt.Errorf("unknown scenario %q; known: %v", name, names)
}
