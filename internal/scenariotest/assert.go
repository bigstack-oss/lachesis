package scenariotest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
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

	// SettleTimeout bounds the poll-until-pass loop: counters appear
	// one agent scrape interval after traffic, so assert re-evaluates
	// until every expectation passes or this deadline fires. Zero
	// uses [defaultSettleTimeout].
	SettleTimeout time.Duration
}

const (
	// defaultSettleTimeout gives the agent a few scrape intervals to
	// surface the driven bytes before assert gives up.
	defaultSettleTimeout = 45 * time.Second
	// assertPollInterval is the pause between evaluation rounds.
	assertPollInterval = 3 * time.Second
	// noteBaselineInvalidated marks a negative delta: the tenant's
	// counter dropped below the drive-time baseline, which the ghost
	// GC causes when a prior run's VMs (same reused project) get
	// their residual flows evicted after the baseline was captured.
	noteBaselineInvalidated = "baseline invalidated (counter dropped — ghost GC evicted a prior run's flows); re-run drive"
)

// AssertReport is the persisted outcome of one assert evaluation:
// one row per declared expectation, plus the overall verdict.
type AssertReport struct {
	Scenario string      `json:"scenario"`
	RunID    string      `json:"run_id"`
	OK       bool        `json:"ok"`
	Rows     []AssertRow `json:"rows"`
}

// AssertRow is one expectation's evaluation. Tenant carries the DSL
// name; TenantID the resolved Keystone project UUID actually matched
// against the `tenant_id` label. ExternalNetwork and VM/ServerID are
// set only on expectations that declared them (ExternalNetwork already
// resolved to the label value matched).
type AssertRow struct {
	Tenant          string `json:"tenant"`
	TenantID        string `json:"tenant_id"`
	Zone            string `json:"zone"`
	ExternalNetwork string `json:"external_network,omitempty"`
	VM              string `json:"vm,omitempty"`
	ServerID        string `json:"server_id,omitempty"`
	// Node is the resolved agent host a node-targeted expectation
	// evaluated against; empty for cluster-wide rows.
	Node      string  `json:"node,omitempty"`
	Direction string  `json:"direction"`
	Baseline  float64 `json:"baseline"`
	Current   float64 `json:"current"`
	Delta     float64 `json:"delta"`
	MinBytes  int64   `json:"min_bytes"`
	Pass      bool    `json:"pass"`
	Note      string  `json:"note,omitempty"`
}

// Assert evaluates every declared expectation as a MinBytes lower
// bound on the delta between the drive-time baseline and the live
// counters, polling until all pass or the settle timeout fires. The
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
		tuples:     sumByTuple(rs.Baseline),
		ext:        sumByExtTuple(rs.Baseline),
		servers:    sumByServerTuple(rs.BaselineServers),
		rawBytes:   rs.Baseline,
		rawServers: rs.BaselineServers,
	}

	timeout := opts.SettleTimeout
	if timeout <= 0 {
		timeout = defaultSettleTimeout
	}
	deadline := time.Now().Add(timeout)

	var report AssertReport
	for {
		snap, err := sampleAcross(ctx, opts.Metrics, opts.Config.Cluster.Agents)
		if err != nil {
			return AssertReport{}, fmt.Errorf("assert: scrape: %w", err)
		}
		cur := baselines{
			tuples:     sumByTuple(snap.Bytes),
			ext:        sumByExtTuple(snap.Bytes),
			servers:    sumByServerTuple(snap.Servers),
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
		opts.Log.Info("assert: not settled yet, retrying", "pass", passCount(report), "rows", len(report.Rows))
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
	tuples     map[tuple]float64
	ext        map[extTuple]float64
	servers    map[serverTuple]float64
	rawBytes   []BytesSample
	rawServers []ServerSample
}

// evaluate builds one report from a pair of aggregated snapshots.
// haveServers reports whether the live scrape exposed the per-server
// family at all — an expectation with a VM target against an agent
// predating it is an evaluation error, not a silent zero-delta fail.
func evaluate(sc *Scenario, cfg Config, rs *RunState, base, cur baselines, haveServers bool) (AssertReport, error) {
	report := AssertReport{Scenario: rs.Scenario, RunID: rs.RunID, OK: true}
	baselineHasNodes := hasNodeInfo(base.rawBytes, base.rawServers)
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
			host, err := resolveNode(e.Node, cfg.Cluster.Agents)
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
				return AssertReport{}, fmt.Errorf("assert: expectation targets VM %q but the agent exposes no %s (predates the per-server family?)", e.VM, metricServerBytesTotal)
			}
			serverID, ok := serverIDFor(rs, e.VM)
			if !ok {
				return AssertReport{}, fmt.Errorf("assert: expectation references VM %q but run-state has no such server", e.VM)
			}
			row.VM, row.ServerID = e.VM, serverID
			if node != "" {
				row.Baseline = sumServersOnNode(base.rawServers, node, serverID, e.Zone, ext, e.Direction)
				row.Current = sumServersOnNode(cur.rawServers, node, serverID, e.Zone, ext, e.Direction)
			} else {
				row.Baseline = sumServer(base.servers, serverID, e.Zone, ext, e.Direction)
				row.Current = sumServer(cur.servers, serverID, e.Zone, ext, e.Direction)
			}
		case node != "":
			row.Baseline = sumBytesOnNode(base.rawBytes, node, ref.ID, e.Zone, ext, e.Direction)
			row.Current = sumBytesOnNode(cur.rawBytes, node, ref.ID, e.Zone, ext, e.Direction)
		case ext != "":
			k := extTuple{ref.ID, e.Zone, ext, e.Direction}
			row.Baseline, row.Current = base.ext[k], cur.ext[k]
		default:
			k := tuple{ref.ID, e.Zone, e.Direction}
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

// serverIDFor resolves a DSL VM id to the Nova server UUID the run
// created for it.
func serverIDFor(rs *RunState, vm string) (string, bool) {
	for _, s := range rs.Servers {
		if s.DSLID == vm {
			return s.ID, true
		}
	}
	return "", false
}

// tuple keys the {tenant_id, zone, direction} label set; extTuple and
// serverTuple refine it for expectations that pin the external_network
// label or a specific server.
type tuple struct{ tenant, zone, direction string }

type extTuple struct{ tenant, zone, ext, direction string }

type serverTuple struct{ server, zone, ext, direction string }

// serverPortTuple is serverTuple refined by port_id — the identity of a
// single per-port series in the mortal family. [ServerMonotoneStep]
// captures at this granularity so it can apply the mortal consumption
// rule (a deleted port's series stops; its last value still counts)
// rather than the naive current-sum, which would dip on any port delete.
type serverPortTuple struct{ server, port, zone, ext, direction string }

// sumByTuple aggregates samples per label tuple. Summing (not
// last-wins) matters on multi-node clusters, where every agent
// exposes its own series for the same tenant.
func sumByTuple(samples []BytesSample) map[tuple]float64 {
	m := make(map[tuple]float64, len(samples))
	for _, s := range samples {
		m[tuple{s.TenantID, s.Zone, s.Direction}] += s.Value
	}
	return m
}

// sumByExtTuple is sumByTuple refined by the external_network label.
func sumByExtTuple(samples []BytesSample) map[extTuple]float64 {
	m := make(map[extTuple]float64, len(samples))
	for _, s := range samples {
		m[extTuple{s.TenantID, s.Zone, s.ExternalNetwork, s.Direction}] += s.Value
	}
	return m
}

// sumByServerTuple aggregates the per-server family. A live-migrated
// server appears on several agents; summing per server is the
// consumption rule (docs/architecture/billing.md).
func sumByServerTuple(samples []ServerSample) map[serverTuple]float64 {
	m := make(map[serverTuple]float64, len(samples))
	for _, s := range samples {
		m[serverTuple{s.ServerID, s.Zone, s.ExternalNetwork, s.Direction}] += s.Value
	}
	return m
}

// sumByServerPortTuple aggregates the per-server family WITHOUT collapsing
// port_id — one bucket per live per-port series. [ServerMonotoneStep] uses
// it to track each port independently so a deleted port reads as a stop,
// not a dip.
func sumByServerPortTuple(samples []ServerSample) map[serverPortTuple]float64 {
	m := make(map[serverPortTuple]float64, len(samples))
	for _, s := range samples {
		m[serverPortTuple{s.ServerID, s.PortID, s.Zone, s.ExternalNetwork, s.Direction}] += s.Value
	}
	return m
}

// hasNodeInfo reports whether any sample carries node identity — a
// baseline captured before per-node stamping can't back a
// node-targeted expectation.
func hasNodeInfo(bytes []BytesSample, servers []ServerSample) bool {
	for _, s := range bytes {
		if s.Node != "" {
			return true
		}
	}
	for _, s := range servers {
		if s.Node != "" {
			return true
		}
	}
	return false
}

// sumBytesOnNode totals one node's tenant-family series for the
// tuple; ext "" matches any external_network (the same wildcard rule
// as the collective default path).
func sumBytesOnNode(samples []BytesSample, node, tenant, zone, ext, direction string) float64 {
	var total float64
	for _, s := range samples {
		if s.Node != node || s.TenantID != tenant || s.Zone != zone || s.Direction != direction {
			continue
		}
		if ext != "" && s.ExternalNetwork != ext {
			continue
		}
		total += s.Value
	}
	return total
}

// sumServersOnNode totals one node's per-server series; ext "" matches
// any external_network.
func sumServersOnNode(samples []ServerSample, node, server, zone, ext, direction string) float64 {
	var total float64
	for _, s := range samples {
		if s.Node != node || s.ServerID != server || s.Zone != zone || s.Direction != direction {
			continue
		}
		if ext != "" && s.ExternalNetwork != ext {
			continue
		}
		total += s.Value
	}
	return total
}

// sumServer totals a server's series for (zone, direction), across all
// external networks when ext is empty.
func sumServer(m map[serverTuple]float64, server, zone, ext, direction string) float64 {
	if ext != "" {
		return m[serverTuple{server, zone, ext, direction}]
	}
	var total float64
	for k, v := range m {
		if k.server == server && k.zone == zone && k.direction == direction {
			total += v
		}
	}
	return total
}

func passCount(r AssertReport) int {
	n := 0
	for _, row := range r.Rows {
		if row.Pass {
			n++
		}
	}
	return n
}

// DefaultReportPath colocates the report with its run-state:
// "<state path minus .json>-report.json".
func DefaultReportPath(statePath string) string {
	return strings.TrimSuffix(statePath, ".json") + "-report.json"
}

// Save writes the report as indented JSON, creating the parent
// directory if needed. `down` never deletes report files, so the
// evidence outlives the topology.
func (r AssertReport) Save(path string) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("report: mkdir %s: %w", dir, err)
		}
	}
	body, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("report: marshal: %w", err)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return fmt.Errorf("report: write %s: %w", path, err)
	}
	return nil
}

// EmitJSON writes the report as indented JSON. Human rendering is a
// presentation concern and lives with the CLI, not here.
func (r AssertReport) EmitJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("encode: %w", err)
	}
	return nil
}
