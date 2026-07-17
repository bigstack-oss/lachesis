package scenariotest

import (
	"fmt"
	"strconv"
	"strings"
)

// slotPrefix marks a symbolic [Placement] value: "node:<i>" names the
// i-th (0-based) entry of the config's cluster.agents list instead of
// a literal hypervisor. Slots keep scenario literals cluster-portable
// — "these two VMs on different hosts" without baking in hostnames —
// and guarantee the resolved host carries a configured agent, which
// per-node assertions depend on.
const slotPrefix = "node:"

// resolvePlacement returns p with every "node:<i>" slot replaced by
// agents[i].Host; literal hypervisor names and empty values pass
// through unchanged. A malformed or out-of-range slot is an error —
// callers resolve before creating anything, so a scenario asking for
// more nodes than the config lists fails with nothing to clean up.
// placementAZ returns the Nova availability-zone pin ("nova:<host>")
// for vm, or "" when vm is unpinned. Both boot paths (realize-time
// and deferred BootVMStep) go through here so the AZ scheme has one
// owner. p must already be resolved.
func placementAZ(p Placement, vm string) string {
	if host := p[vm]; host != "" {
		return "nova:" + host
	}
	return ""
}

func resolvePlacement(p Placement, agents []AgentConfig) (Placement, error) {
	if len(p) == 0 {
		return p, nil
	}
	resolved := make(Placement, len(p))
	for vm, val := range p {
		if !strings.HasPrefix(val, slotPrefix) {
			resolved[vm] = val
			continue
		}
		idx, err := strconv.Atoi(val[len(slotPrefix):])
		if err != nil || idx < 0 {
			return nil, fmt.Errorf("placement slot %q (VM %q): want %s<index>", val, vm, slotPrefix)
		}
		if idx >= len(agents) {
			return nil, fmt.Errorf("placement slot %q (VM %q): config lists %d agent(s)", val, vm, len(agents))
		}
		resolved[vm] = agents[idx].Host
	}
	return resolved, nil
}
