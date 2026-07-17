// render.go is the human presentation of the reports: lipgloss tables
// with colored verdicts. Styling is TTY-aware via termenv — piped
// output or NO_COLOR degrades to plain text automatically. The JSON
// side stays in internal/scenariotest (EmitJSON) and is byte-stable;
// only this human path is free to evolve.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
)

var (
	titleStyle  = lipgloss.NewStyle().Bold(true)
	passStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	failStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("1")).Bold(true)
	passVerdict = lipgloss.NewStyle().Foreground(lipgloss.Color("2")).Bold(true)
	failVerdict = lipgloss.NewStyle().Foreground(lipgloss.Color("1")).Bold(true).Reverse(true)
)

// emitPreflight writes the report in the requested output format.
func emitPreflight(w io.Writer, format string, r scenariotest.PreflightReport) error {
	switch format {
	case "json":
		return r.EmitJSON(w)
	case "human", "":
		renderPreflight(w, r)
		return nil
	default:
		return usageError{fmt.Errorf("bad output format %q (want human|json)", format)}
	}
}

// emitAssert writes the report in the requested output format.
func emitAssert(w io.Writer, format string, r scenariotest.AssertReport) error {
	switch format {
	case "json":
		return r.EmitJSON(w)
	case "human", "":
		renderAssert(w, r)
		return nil
	default:
		return usageError{fmt.Errorf("bad output format %q (want human|json)", format)}
	}
}

func renderPreflight(w io.Writer, r scenariotest.PreflightReport) {
	fmt.Fprintln(w, titleStyle.Render(fmt.Sprintf("PREFLIGHT %s", r.Scenario)))
	t := newTable("CHECK", "RESULT", "DETAIL")
	for _, c := range r.Checks {
		result := passStyle.Render("ok")
		if !c.OK {
			result = failStyle.Render("FAIL")
		}
		t.Row(c.Name, result, c.Detail)
	}
	fmt.Fprintln(w, t.Render())
	fmt.Fprintln(w, verdict(r.OK, "READY", "NOT READY"))
}

func renderAssert(w io.Writer, r scenariotest.AssertReport) {
	fmt.Fprintln(w, titleStyle.Render(fmt.Sprintf("ASSERT %s (run %s)", r.Scenario, r.RunID)))
	t := newTable("TENANT", "ZONE", "EXT", "VM", "DIR", "BASELINE", "CURRENT", "DELTA", "MIN", "RESULT")
	for _, row := range r.Rows {
		result := passStyle.Render("pass")
		if !row.Pass {
			result = failStyle.Render("FAIL")
		}
		if row.Note != "" {
			result += " (" + row.Note + ")"
		}
		t.Row(row.Tenant, row.Zone, dash(row.ExternalNetwork), dash(row.VM), row.Direction,
			humanBytes(row.Baseline), humanBytes(row.Current),
			humanBytes(row.Delta), humanBytes(float64(row.MinBytes)), result)
	}
	fmt.Fprintln(w, t.Render())
	fmt.Fprintln(w, verdict(r.OK, "PASS", "FAIL"))
}

// emitSuite writes the multi-scenario summary in the requested output
// format.
func emitSuite(w io.Writer, format string, r suiteReport) error {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r); err != nil {
			return fmt.Errorf("encode: %w", err)
		}
		return nil
	case "human", "":
		renderSuite(w, r)
		return nil
	default:
		return usageError{fmt.Errorf("bad output format %q (want human|json)", format)}
	}
}

func renderSuite(w io.Writer, r suiteReport) {
	fmt.Fprintln(w, titleStyle.Render(fmt.Sprintf("SUITE %d scenario(s)", len(r.Scenarios))))
	t := newTable("SCENARIO", "RESULT", "DURATION", "REPORT")
	for _, s := range r.Scenarios {
		result := passStyle.Render("pass")
		switch {
		case s.Error != "":
			result = failStyle.Render("FAIL") + " (error)"
		case !s.OK:
			result = failStyle.Render("FAIL")
		}
		dur := time.Duration(s.DurationSeconds * float64(time.Second)).Round(time.Second)
		t.Row(s.Scenario, result, dur.String(), dash(s.Report))
	}
	fmt.Fprintln(w, t.Render())
	fmt.Fprintln(w, verdict(r.OK, "PASS", "FAIL"))
}

func newTable(headers ...string) *table.Table {
	return table.New().
		Border(lipgloss.RoundedBorder()).
		BorderStyle(lipgloss.NewStyle().Faint(true)).
		StyleFunc(func(row, _ int) lipgloss.Style {
			if row == table.HeaderRow {
				return titleStyle.Padding(0, 1)
			}
			return lipgloss.NewStyle().Padding(0, 1)
		}).
		Headers(headers...)
}

func verdict(ok bool, pass, fail string) string {
	if ok {
		return passVerdict.Render(pass)
	}
	return failVerdict.Render(" " + fail + " ")
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// humanBytes renders a byte count in IEC units for the table; the
// JSON report keeps the exact values. Assertions are lower bounds, so
// the rounded display loses nothing a reader acts on.
func humanBytes(v float64) string {
	sign := ""
	if v < 0 {
		sign, v = "-", -v
	}
	if v < 1024 {
		return fmt.Sprintf("%s%.0f B", sign, v)
	}
	for _, unit := range []string{"KiB", "MiB", "GiB", "TiB"} {
		v /= 1024
		if v < 1024 || unit == "TiB" {
			return fmt.Sprintf("%s%.1f %s", sign, v, unit)
		}
	}
	return "" // unreachable
}
