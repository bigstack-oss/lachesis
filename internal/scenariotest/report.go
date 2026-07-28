package scenariotest

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
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

// PassCount is how many of the report's rows passed.
func (r AssertReport) PassCount() int {
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
