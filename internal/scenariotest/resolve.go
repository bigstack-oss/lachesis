package scenariotest

// resolve.go holds the small lookups that turn a scenario's DSL names
// and the config's declarations into the live identifiers a phase or a
// step actually acts on. They lived scattered across the phases before
// the harness was split into packages; collecting them here is what
// lets each phase be its own package without re-deriving them.

import (
	"fmt"
	"regexp"
)

// SkipError reports that the scenario cannot run on this cluster —
// its placement slots need more nodes than the config lists. Not a
// failure: the CLI maps it to a SKIPPED verdict and exit 0, and the
// suite counts it separately (`--no-skip` tightens both to failures,
// for clusters that are supposed to satisfy every scenario).
type SkipError struct{ Reason string }

func (e *SkipError) Error() string { return "skipped: " + e.Reason }

// LiveID resolves a DSL id to the live resource id recorded by
// realize; empty when absent.
func LiveID(refs []ResourceRef, dslID string) string {
	for _, r := range refs {
		if r.DSLID == dslID {
			return r.ID
		}
	}
	return ""
}

// ServerIDFor resolves a DSL VM id to the Nova server UUID the run
// created for it.
func ServerIDFor(rs *RunState, vm string) (string, bool) {
	for _, s := range rs.Servers {
		if s.DSLID == vm {
			return s.ID, true
		}
	}
	return "", false
}

// FlavorFor returns the flavor a scenario boots with: its own
// override, else the global prerequisite.
func FlavorFor(cfg Config, sc *Scenario) string {
	if sc.Flavor != "" {
		return sc.Flavor
	}
	return cfg.Prerequisites.FlavorName
}

// AgentURLs lists every configured agent's /metrics URL.
func AgentURLs(cfg Config) []string {
	urls := make([]string, 0, len(cfg.Cluster.Agents))
	for _, a := range cfg.Cluster.Agents {
		urls = append(urls, a.MetricsURL)
	}
	return urls
}

// AgentForNode resolves a step's Node to its [AgentConfig]: a
// placement slot or literal host, or the sole agent when node is empty.
func AgentForNode(cfg Config, node string) (AgentConfig, error) {
	if node == "" {
		if len(cfg.Cluster.Agents) != 1 {
			return AgentConfig{}, fmt.Errorf("node is required when the cluster has %d agents", len(cfg.Cluster.Agents))
		}
		return cfg.Cluster.Agents[0], nil
	}
	host, err := ResolveNode(node, cfg.Cluster.Agents)
	if err != nil {
		return AgentConfig{}, err
	}
	for _, a := range cfg.Cluster.Agents {
		if a.Host == host {
			return a, nil
		}
	}
	// ResolveNode only returns a configured host, so this is a safety
	// net, not a reachable path.
	return AgentConfig{}, fmt.Errorf("resolved host %q has no agent entry", host)
}

// CheckRequiredMetrics reports whether a scrape carries the families
// every scenario depends on, whatever its steps additionally declare
// through [MetricRequirer].
func CheckRequiredMetrics(res ScrapeResult) error {
	for _, m := range []string{MetricBytesTotal, MetricAttachedInterfaces} {
		if !res.Present[m] {
			return fmt.Errorf("agent /metrics missing %s", m)
		}
	}
	return nil
}

var shellSafeToken = regexp.MustCompile(`^[A-Za-z0-9@%.:_/+-]+$`)

// ShellSafe rejects a value with characters outside a conservative set
// (alphanumerics and common path/unit punctuation), so config- and
// scenario-supplied tokens interpolated into an SSH command line cannot
// inject shell syntax. Real unit names and file paths use only these.
func ShellSafe(field, v string) error {
	if v == "" || !shellSafeToken.MatchString(v) {
		return fmt.Errorf("%s %q contains characters unsafe for a shell command", field, v)
	}
	return nil
}
