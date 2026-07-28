package scenariotest

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// AssertOptions bundles everything `assert` needs to evaluate a
// driven scenario's expectations against live /metrics.
type AssertOptions struct {
	Config   Config
	Scenario *Scenario
	State    *RunState
	// ReportPath is where the JSON report persists (it must survive
	// `down`, which never deletes report or run-state files). Empty
	// derives "<state path minus .json>-report.json" via
	// [DefaultReportPath].
	ReportPath string
	Metrics    MetricsSource
	Log        *slog.Logger

	// StabilizeTimeout bounds the poll-until-pass loop: counters appear
	// one agent scrape interval after traffic, so assert re-evaluates
	// until every expectation passes or this deadline fires. Zero
	// uses [defaultStabilizeTimeout]. ("Stabilize", not "settle" — the
	// agent's settled-bytes fold is an unrelated concept.)
	StabilizeTimeout time.Duration
}

const (
	// defaultStabilizeTimeout gives the agent a few scrape intervals to
	// surface the driven bytes before assert gives up.
	defaultStabilizeTimeout = 45 * time.Second
	// assertPollInterval is the pause between evaluation rounds.
	assertPollInterval = 3 * time.Second
	// noteBaselineInvalidated marks a negative delta: the tenant's
	// counter dropped below the drive-time baseline, which the ghost
	// GC causes when a prior run's VMs (same reused project) get
	// their residual flows evicted after the baseline was captured.
	noteBaselineInvalidated = "baseline invalidated (counter dropped — ghost GC evicted a prior run's flows); re-run drive"
)

// Assert evaluates every declared expectation as a MinBytes lower
// bound on the delta between the drive-time baseline and the live
// counters, polling until all pass or the stabilize timeout fires. The
// report is persisted to ReportPath either way; the returned error is
// reserved for evaluation being impossible (no baseline, unknown
// tenant, scrape failure) — a failed expectation is a false OK in the
// report, not an error.
func Assert(ctx context.Context, opts AssertOptions) (AssertReport, error) {
	if opts.Log == nil {
		opts.Log = slog.New(slog.DiscardHandler)
	}
	rs := opts.State
	if len(rs.Baseline) == 0 {
		return AssertReport{}, fmt.Errorf("assert: run-state has no baseline — run drive first")
	}
	base := baselines{
		tuples:     SumByTuple(rs.Baseline),
		ext:        SumByExtTuple(rs.Baseline),
		servers:    SumByServerTuple(rs.BaselineServers),
		rawBytes:   rs.Baseline,
		rawServers: rs.BaselineServers,
	}

	timeout := opts.StabilizeTimeout
	if timeout <= 0 {
		timeout = defaultStabilizeTimeout
	}
	deadline := time.Now().Add(timeout)

	var report AssertReport
	for {
		snap, err := SampleAcross(ctx, opts.Metrics, opts.Config.Cluster.Agents)
		if err != nil {
			return AssertReport{}, fmt.Errorf("assert: scrape: %w", err)
		}
		cur := baselines{
			tuples:     SumByTuple(snap.Bytes),
			ext:        SumByExtTuple(snap.Bytes),
			servers:    SumByServerTuple(snap.Servers),
			rawBytes:   snap.Bytes,
			rawServers: snap.Servers,
		}
		report, err = evaluate(opts.Scenario, opts.Config, rs, base, cur, len(snap.Servers) > 0)
		if err != nil {
			return AssertReport{}, err
		}
		if report.OK {
			break
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		wait := assertPollInterval
		if remaining < wait {
			wait = remaining
		}
		opts.Log.Info("assert: not stabilized yet, retrying", "pass", report.PassCount(), "rows", len(report.Rows))
		select {
		case <-ctx.Done():
			return report, ctx.Err()
		case <-time.After(wait):
		}
	}

	path := opts.ReportPath
	if path == "" {
		return report, fmt.Errorf("assert: no report path")
	}
	if err := report.Save(path); err != nil {
		return report, err
	}
	opts.Log.Info("assert: report written", "path", path)
	return report, nil
}

// baselines carries the three aggregations one snapshot supports: the
// coarse {tenant, zone, direction} sums (the pre-label behavior, used
// by expectations with no ExternalNetwork/VM and by the step
// executor), the external_network-refined sums, and the per-server
// family's sums — plus the raw samples, which node-targeted
// expectations filter directly (the aggregations sum across nodes).
type baselines struct {
	tuples     map[Tuple]float64
	ext        map[ExtTuple]float64
	servers    map[ServerTuple]float64
	rawBytes   []BytesSample
	rawServers []ServerSample
}

// evaluate builds one report from a pair of aggregated snapshots.
// haveServers reports whether the live scrape exposed the per-server
// family at all — an expectation with a VM target against an agent
// predating it is an evaluation error, not a silent zero-delta fail.
func evaluate(sc *Scenario, cfg Config, rs *RunState, base, cur baselines, haveServers bool) (AssertReport, error) {
	report := AssertReport{Scenario: rs.Scenario, RunID: rs.RunID, OK: true}
	baselineHasNodes := HasNodeInfo(base.rawBytes, base.rawServers)
	for _, e := range sc.Expect {
		ref, ok := rs.Projects[e.TenantID]
		if !ok {
			return AssertReport{}, fmt.Errorf("assert: expectation references tenant %q but run-state has no such project", e.TenantID)
		}
		ext := resolveExternalNetwork(sc, cfg, rs, e.ExternalNetwork)
		row := AssertRow{
			Tenant: e.TenantID, TenantID: ref.ID,
			Zone: e.Zone, ExternalNetwork: ext, Direction: e.Direction,
			MinBytes: e.MinBytes,
		}
		node := ""
		if e.Node != "" {
			host, err := ResolveNode(e.Node, cfg.Cluster.Agents)
			if err != nil {
				return AssertReport{}, fmt.Errorf("assert: %w", err)
			}
			if !baselineHasNodes {
				return AssertReport{}, fmt.Errorf("assert: expectation targets node %q but the baseline carries no node identity — re-run drive with this scenariotest build", e.Node)
			}
			node, row.Node = host, host
		}
		switch {
		case e.VM != "":
			if !haveServers {
				return AssertReport{}, fmt.Errorf("assert: expectation targets VM %q but the agent exposes no %s (predates the per-server family?)", e.VM, MetricServerBytesTotal)
			}
			serverID, ok := ServerIDFor(rs, e.VM)
			if !ok {
				return AssertReport{}, fmt.Errorf("assert: expectation references VM %q but run-state has no such server", e.VM)
			}
			row.VM, row.ServerID = e.VM, serverID
			if node != "" {
				row.Baseline = SumServersOnNode(base.rawServers, node, serverID, e.Zone, ext, e.Direction)
				row.Current = SumServersOnNode(cur.rawServers, node, serverID, e.Zone, ext, e.Direction)
			} else {
				row.Baseline = SumServer(base.servers, serverID, e.Zone, ext, e.Direction)
				row.Current = SumServer(cur.servers, serverID, e.Zone, ext, e.Direction)
			}
		case node != "":
			row.Baseline = SumBytesOnNode(base.rawBytes, node, ref.ID, e.Zone, ext, e.Direction)
			row.Current = SumBytesOnNode(cur.rawBytes, node, ref.ID, e.Zone, ext, e.Direction)
		case ext != "":
			k := ExtTuple{ref.ID, e.Zone, ext, e.Direction}
			row.Baseline, row.Current = base.ext[k], cur.ext[k]
		default:
			k := Tuple{ref.ID, e.Zone, e.Direction}
			row.Baseline, row.Current = base.tuples[k], cur.tuples[k]
		}
		row.Delta = row.Current - row.Baseline
		row.Pass = row.Delta >= float64(e.MinBytes)
		if row.Delta < 0 {
			row.Note = noteBaselineInvalidated
		}
		if !row.Pass {
			report.OK = false
		}
		report.Rows = append(report.Rows, row)
	}
	return report, nil
}

// resolveExternalNetwork maps an expectation's ExternalNetwork to the
// label value to match — the same indirection realize applies: empty
// stays empty (no filter); a marker in [Scenario.CreateExternalNets]
// resolves to its run-mangled created name (the network Name the agent
// labels by); any other DSL external-network marker id resolves to the
// provider network the config binds it to; anything else — including
// the "none" sentinel — is literal.
func resolveExternalNetwork(sc *Scenario, cfg Config, rs *RunState, name string) string {
	if name == "" || sc.Builder == nil {
		return name
	}
	for _, created := range sc.CreateExternalNets {
		if created == name {
			return Mangle(cfg.Naming.Prefix, rs.RunID, name)
		}
	}
	for _, n := range sc.Builder.Build().Networks {
		if n.IsExternal && n.ID == name {
			return cfg.Prerequisites.ExternalNetworkName
		}
	}
	return name
}
