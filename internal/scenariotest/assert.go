package scenariotest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
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
	Log        io.Writer

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
// against the `tenant_id` label.
type AssertRow struct {
	Tenant    string  `json:"tenant"`
	TenantID  string  `json:"tenant_id"`
	Zone      string  `json:"zone"`
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
		opts.Log = io.Discard
	}
	rs := opts.State
	if len(rs.Baseline) == 0 {
		return AssertReport{}, fmt.Errorf("assert: run-state has no baseline — run drive first")
	}
	base := sumByTuple(rs.Baseline)

	timeout := opts.SettleTimeout
	if timeout <= 0 {
		timeout = defaultSettleTimeout
	}
	deadline := time.Now().Add(timeout)

	var report AssertReport
	for {
		snap, err := sampleAcross(ctx, opts.Metrics, agentURLs(opts.Config))
		if err != nil {
			return AssertReport{}, fmt.Errorf("assert: scrape: %w", err)
		}
		report, err = evaluate(opts.Scenario, rs, base, sumByTuple(snap.Bytes))
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
		fmt.Fprintf(opts.Log, "assert: not settled yet, retrying (%d/%d rows pass)\n", passCount(report), len(report.Rows))
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
	fmt.Fprintf(opts.Log, "assert: report written to %s\n", path)
	return report, nil
}

// evaluate builds one report from a pair of tuple-summed snapshots.
func evaluate(sc *Scenario, rs *RunState, base, cur map[tuple]float64) (AssertReport, error) {
	report := AssertReport{Scenario: rs.Scenario, RunID: rs.RunID, OK: true}
	for _, e := range sc.Expect {
		ref, ok := rs.Projects[e.TenantID]
		if !ok {
			return AssertReport{}, fmt.Errorf("assert: expectation references tenant %q but run-state has no such project", e.TenantID)
		}
		k := tuple{ref.ID, e.Zone, e.Direction}
		row := AssertRow{
			Tenant: e.TenantID, TenantID: ref.ID,
			Zone: e.Zone, Direction: e.Direction,
			Baseline: base[k], Current: cur[k],
			Delta: cur[k] - base[k], MinBytes: e.MinBytes,
		}
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

// tuple keys the {tenant_id, zone, direction} label set.
type tuple struct{ tenant, zone, direction string }

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

// Emit writes the report as "human" (a table with a PASS/FAIL
// verdict) or "json".
func (r AssertReport) Emit(w io.Writer, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r); err != nil {
			return fmt.Errorf("encode: %w", err)
		}
		return nil
	case "human", "":
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintf(tw, "ASSERT %s (run %s)\n", r.Scenario, r.RunID)
		fmt.Fprintln(tw, "TENANT\tZONE\tDIR\tBASELINE\tCURRENT\tDELTA\tMIN\tRESULT")
		for _, row := range r.Rows {
			result := "pass"
			if !row.Pass {
				result = "FAIL"
			}
			if row.Note != "" {
				result += " (" + row.Note + ")"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%.0f\t%.0f\t%.0f\t%d\t%s\n",
				row.Tenant, row.Zone, row.Direction, row.Baseline, row.Current, row.Delta, row.MinBytes, result)
		}
		tw.Flush()
		verdict := "PASS"
		if !r.OK {
			verdict = "FAIL"
		}
		fmt.Fprintf(w, "\n%s\n", verdict)
		return nil
	default:
		return fmt.Errorf("bad output format %q (want human|json)", format)
	}
}
