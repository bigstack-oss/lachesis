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
// slotIndex parses a Placement value: isSlot reports whether val uses
// the "node:<i>" syntax at all (false = literal hypervisor name), and
// a non-nil err means the slot's index is malformed. The one owner of
// the parse for [resolvePlacement], [RequiredNodes], and [SkipReason].
func slotIndex(val string) (idx int, isSlot bool, err error) {
	if !strings.HasPrefix(val, slotPrefix) {
		return 0, false, nil
	}
	idx, aerr := strconv.Atoi(val[len(slotPrefix):])
	if aerr != nil || idx < 0 {
		return 0, true, fmt.Errorf("want %s<index>", slotPrefix)
	}
	return idx, true, nil
}

// RequiredNodes returns how many cluster nodes sc needs: the highest
// "node:<i>" slot index its Placement references plus one, or zero
// when no slots are used. Literal hypervisor pins don't count — they
// are cluster-specific one-offs, not a portable node requirement.
// Malformed slots contribute nothing; [resolvePlacement] owns
// rejecting them.
func RequiredNodes(sc *Scenario) int {
	req := 0
	for _, val := range sc.Placement {
		idx, isSlot, err := slotIndex(val)
		if !isSlot || err != nil {
			continue
		}
		if idx+1 > req {
			req = idx + 1
		}
	}
	return req
}

// SkipReason returns why sc cannot run against cfg's cluster — a
// non-empty reason means SKIPPED, not FAILED: the scenario's slots
// need more nodes than the config lists, which is a property of the
// cluster, not a defect in it. Empty means runnable. A Placement
// carrying any malformed slot never skips: that is a scenario defect
// the placement check must FAIL on every cluster size — skipping
// would mask it until a big-enough cluster finally ran the scenario.
func SkipReason(sc *Scenario, cfg Config) string {
	for _, val := range sc.Placement {
		if _, isSlot, err := slotIndex(val); isSlot && err != nil {
			return ""
		}
	}
	if req := RequiredNodes(sc); req > len(cfg.Cluster.Agents) {
		return fmt.Sprintf("needs %d node(s) (placement slots); config lists %d agent(s)", req, len(cfg.Cluster.Agents))
	}
	// A scenario that drives an agent host can't run without agent-host
	// SSH creds, and a cold-restart scenario additionally needs to know
	// where the agent keeps its durable state. Both are properties of
	// the environment (creds/paths not staged), not defects, so skip
	// rather than fail — same rationale as the node-count skip above.
	needs := scenarioHostNeeds(sc)
	if needs.AgentSSH && cfg.AgentControl.KeyPath == "" {
		return "restarts an agent but agent_control.key_path is unset"
	}
	if needs.WALPath && cfg.AgentControl.WALPath == "" {
		return "removes the agent WAL but agent_control.wal_path is unset"
	}
	if needs.PinPath && cfg.AgentControl.PinPath == "" {
		return "removes the agent's map pins but agent_control.pin_path is unset"
	}
	return ""
}

// scenarioHostNeeds unions what every step in sc declares through
// [HostRequirer]. Steps that drive no host declare nothing and are
// invisible here — which is the point: the core asks the vocabulary
// what it needs instead of switching on concrete step types it would
// then have to import.
func scenarioHostNeeds(sc *Scenario) HostNeeds {
	var n HostNeeds
	for _, st := range sc.Steps {
		r, ok := st.(HostRequirer)
		if !ok {
			continue
		}
		m := r.HostNeeds()
		n.AgentSSH = n.AgentSSH || m.AgentSSH
		n.WALPath = n.WALPath || m.WALPath
		n.PinPath = n.PinPath || m.PinPath
	}
	return n
}

// resolveNode maps an [Expect.Node] target to the configured agent
// host whose samples the assertion must match: a "node:<i>" slot
// resolves like Placement does; a literal value must name a
// configured agent host (anything else would silently sum zero
// samples — an error beats a mute FAIL).
func ResolveNode(val string, agents []AgentConfig) (string, error) {
	idx, isSlot, err := slotIndex(val)
	if isSlot {
		if err != nil {
			return "", fmt.Errorf("node target %q: %w", val, err)
		}
		if idx >= len(agents) {
			return "", fmt.Errorf("node target %q: config lists %d agent(s)", val, len(agents))
		}
		return agents[idx].Host, nil
	}
	for _, a := range agents {
		if a.Host == val {
			return val, nil
		}
	}
	return "", fmt.Errorf("node target %q is not a configured agent host", val)
}

// placementAZ returns the Nova availability-zone pin ("nova:<host>")
// for vm, or "" when vm is unpinned. Both boot paths (realize-time
// and deferred BootVMStep) go through here so the AZ scheme has one
// owner. p must already be resolved.
func PlacementAZ(p Placement, vm string) string {
	if host := p[vm]; host != "" {
		return "nova:" + host
	}
	return ""
}

func ResolvePlacement(p Placement, agents []AgentConfig) (Placement, error) {
	if len(p) == 0 {
		return p, nil
	}
	resolved := make(Placement, len(p))
	for vm, val := range p {
		idx, isSlot, err := slotIndex(val)
		if !isSlot {
			resolved[vm] = val
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("placement slot %q (VM %q): %w", val, vm, err)
		}
		if idx >= len(agents) {
			return nil, fmt.Errorf("placement slot %q (VM %q): config lists %d agent(s)", val, vm, len(agents))
		}
		resolved[vm] = agents[idx].Host
	}
	return resolved, nil
}
