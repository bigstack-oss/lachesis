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
	Scenario string  `json:"scenario"`
	OK       bool    `json:"ok"`
	Checks   []Check `json:"checks"`
}

// Check is one readiness probe and its result.
type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// Preflight verifies, without mutating anything, that the cluster is
// ready to run sc: every prerequisite resolves, any pinned hypervisor
// exists, and every configured agent is scraping and exposing the
// metrics scenariotest depends on. It never returns an error — every
// failure is captured as a failed [Check] so the report shows the
// full picture in one pass.
func Preflight(ctx context.Context, cfg Config, sc *Scenario, cloud Cloud, src MetricsSource) PreflightReport {
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

	flavor := flavorFor(cfg, sc)
	fid, err := cloud.FindFlavor(ctx, flavor)
	add("flavor", err, "found "+flavor+" ("+fid+")")

	add("keypair", cloud.CheckKeypair(ctx, cfg.Prerequisites.KeypairName), "found "+cfg.Prerequisites.KeypairName)

	sgid, err := cloud.FindSecGroup(ctx, cfg.Prerequisites.SecGroupName)
	add("secgroup", err, "found "+cfg.Prerequisites.SecGroupName+" ("+sgid+")")

	extid, err := cloud.FindExternalNetwork(ctx, cfg.Prerequisites.ExternalNetworkName)
	add("external_network", err, "found "+cfg.Prerequisites.ExternalNetworkName+" ("+extid+")")

	if len(sc.Placement) > 0 {
		hosts, err := cloud.Hypervisors(ctx)
		if err != nil {
			add("placement", err, "")
		} else {
			add("placement", checkPlacement(sc.Placement, hosts), fmt.Sprintf("%d host(s) validated", len(sc.Placement)))
		}
	}

	for _, a := range cfg.Cluster.Agents {
		name := "agent:" + a.Host
		res, err := src.Scrape(ctx, a.MetricsURL)
		if err != nil {
			add(name, err, "")
			continue
		}
		add(name, requiredMetrics(res), "reachable; required metrics present")
	}
	return r
}

// flavorFor returns the flavor a scenario boots with: its own
// override, else the global prerequisite.
func flavorFor(cfg Config, sc *Scenario) string {
	if sc.Flavor != "" {
		return sc.Flavor
	}
	return cfg.Prerequisites.FlavorName
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

func requiredMetrics(res ScrapeResult) error {
	for _, m := range []string{metricBytesTotal, metricAttachedInterfaces} {
		if !res.Present[m] {
			return fmt.Errorf("agent /metrics missing %s", m)
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
