package scenariotest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
)

// PreflightReport is the outcome of a read-only cluster-readiness
// check. OK is true only when every Check passed.
type PreflightReport struct {
	Scenario string `json:"scenario"`
	OK       bool   `json:"ok"`
	// Skip, when non-empty, means the scenario cannot run on this
	// cluster (its placement slots need more nodes than the config
	// lists) and should be SKIPPED rather than failed. No checks run:
	// the answer is in the config, and probing a cluster the scenario
	// won't use only muddies the report.
	Skip   string  `json:"skip,omitempty"`
	Checks []Check `json:"checks"`
}

// Check is one readiness probe and its result.
type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// Preflight verifies, without mutating anything, that the cluster is
// ready to run sc: every prerequisite resolves, any pinned hypervisor
// exists (placement slots resolve against the configured agents
// first), and every configured agent is scraping and exposing the
// metrics scenariotest depends on. It never returns an error — every
// failure is captured as a failed [Check] so the report shows the
// full picture in one pass.
func Preflight(ctx context.Context, cfg Config, sc *Scenario, cloud Cloud, src MetricsSource) PreflightReport {
	if reason := skipReason(sc, cfg); reason != "" {
		return PreflightReport{Scenario: sc.Name, OK: true, Skip: reason}
	}
	r := PreflightReport{Scenario: sc.Name, OK: true}
	add := func(name string, err error, ok string) {
		c := Check{Name: name, OK: err == nil, Detail: ok}
		if err != nil {
			c.Detail = err.Error()
			r.OK = false
		}
		r.Checks = append(r.Checks, c)
	}

	id, err := cloud.FindImage(ctx, cfg.Prerequisites.ImageName)
	add("image", err, "found "+cfg.Prerequisites.ImageName+" ("+id+")")

	flavor := FlavorFor(cfg, sc)
	fid, err := cloud.FindFlavor(ctx, flavor)
	add("flavor", err, "found "+flavor+" ("+fid+")")

	add("keypair", cloud.CheckKeypair(ctx, cfg.Prerequisites.KeypairName), "found "+cfg.Prerequisites.KeypairName)

	sgid, err := cloud.FindSecGroup(ctx, cfg.Prerequisites.SecGroupName)
	add("secgroup", err, "found "+cfg.Prerequisites.SecGroupName+" ("+sgid+")")

	extid, err := cloud.FindExternalNetwork(ctx, cfg.Prerequisites.ExternalNetworkName)
	add("external_network", err, "found "+cfg.Prerequisites.ExternalNetworkName+" ("+extid+")")

	if len(sc.Placement) > 0 {
		if resolved, rerr := ResolvePlacement(sc.Placement, cfg.Cluster.Agents); rerr != nil {
			add("placement", rerr, "")
		} else if hosts, err := cloud.Hypervisors(ctx); err != nil {
			add("placement", err, "")
		} else {
			add("placement", checkPlacement(resolved, hosts), fmt.Sprintf("%d host(s) validated", len(resolved)))
		}
	}

	for _, a := range cfg.Cluster.Agents {
		name := "agent:" + a.Host
		res, err := src.Scrape(ctx, a.MetricsURL)
		if err != nil {
			add(name, err, "")
			continue
		}
		add(name, CheckRequiredMetrics(res), "reachable; required metrics present")
	}
	return r
}

func checkPlacement(p Placement, hosts []string) error {
	have := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		have[h] = true
	}
	for vm, host := range p {
		if host == "" {
			continue
		}
		if !have[host] {
			return fmt.Errorf("hypervisor %q (pinned for VM %q) not in hypervisor list", host, vm)
		}
	}
	return nil
}

// EmitJSON writes the report as indented JSON. Human rendering is a
// presentation concern and lives with the CLI, not here.
func (r PreflightReport) EmitJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("encode: %w", err)
	}
	return nil
}
