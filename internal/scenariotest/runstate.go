package scenariotest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// RunState is the on-disk record of everything one `up` invocation
// created. `up` writes it; `drive`, `assert`, and `down` read it. It
// is the only state shared between the otherwise-stateless
// subcommands.
//
// Resources are recorded as they are created so a partial `up` leaves
// a run-state `down` can still clean up. Projects are recorded too —
// to give `assert` the DSL-name → UUID mapping it needs to match the
// `tenant_id` label — but carry a Created flag so `down` knows never
// to delete a reused project (and, by policy, never deletes any).
type RunState struct {
	RunID    string                `json:"run_id"`
	Scenario string                `json:"scenario"`
	Prefix   string                `json:"prefix"`
	Projects map[string]ProjectRef `json:"projects"`
	Networks []ResourceRef         `json:"networks"`
	Subnets  []ResourceRef         `json:"subnets"`
	Routers  []ResourceRef         `json:"routers"`
	Ports    []ResourceRef         `json:"ports"`
	Servers  []ResourceRef         `json:"servers"`
	FIPs     []FIPRef              `json:"fips"`

	// Attach records the attach gate's green state at the end of
	// `up`, so a standalone `drive` can re-confirm the taps are still
	// attached before pushing traffic.
	Attach AttachRecord `json:"attach"`

	// Baseline is the pre-drive cubecos_bytes_total snapshot across
	// all agents, captured by `drive` immediately before it pushes
	// traffic; `assert` diffs against it.
	Baseline []BytesSample `json:"baseline,omitempty"`

	// TornDown marks a successful `down`: every recorded resource is
	// gone (projects excepted, by policy). The file itself is kept —
	// together with the assert report it is the run's surviving
	// evidence.
	TornDown bool `json:"torn_down,omitempty"`
}

// AttachRecord is the attach gate's result: the gauge value the gate
// required and the failure count observed when it went green.
type AttachRecord struct {
	Target   float64 `json:"target"`
	Failures float64 `json:"failures"`
}

// ProjectRef records a topology project's resolved Keystone identity.
// Created distinguishes projects `up` made (reusable, never deleted)
// from ones it reused.
type ProjectRef struct {
	Name    string `json:"name"`
	ID      string `json:"id"`
	Created bool   `json:"created"`
}

// ResourceRef records one created Neutron/Nova resource. ProjectID is
// the scope it was created under, so `down` can delete it through the
// right project-scoped client.
type ResourceRef struct {
	DSLID     string `json:"dsl_id"`
	ID        string `json:"id"`
	Name      string `json:"name"`
	ProjectID string `json:"project_id"`
}

// FIPRef records one allocated floating IP and the VM it fronts.
type FIPRef struct {
	VMID      string `json:"vm_id"`
	ID        string `json:"id"`
	Address   string `json:"address"`
	ProjectID string `json:"project_id"`
}

// NewRunState returns an empty run-state for a scenario run.
func NewRunState(runID, scenario, prefix string) *RunState {
	return &RunState{
		RunID:    runID,
		Scenario: scenario,
		Prefix:   prefix,
		Projects: map[string]ProjectRef{},
	}
}

// Save writes the run-state to path as indented JSON, creating the
// parent directory if needed. It is called repeatedly during `up` so
// the on-disk record never lags the live resources by more than one
// create.
func (rs *RunState) Save(path string) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("runstate: mkdir %s: %w", dir, err)
		}
	}
	body, err := json.MarshalIndent(rs, "", "  ")
	if err != nil {
		return fmt.Errorf("runstate: marshal: %w", err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return fmt.Errorf("runstate: write %s: %w", path, err)
	}
	return nil
}

// LoadRunState reads a run-state written by [RunState.Save].
func LoadRunState(path string) (*RunState, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("runstate: read %s: %w", path, err)
	}
	var rs RunState
	if err := json.Unmarshal(body, &rs); err != nil {
		return nil, fmt.Errorf("runstate: parse %s: %w", path, err)
	}
	return &rs, nil
}

// DefaultStatePath is where `up` writes a run's state when no -state
// flag is given: ".scenariotest/<prefix>-<runID>.json" under the
// working directory.
func DefaultStatePath(prefix, runID string) string {
	return filepath.Join(".scenariotest", fmt.Sprintf("%s-%s.json", prefix, runID))
}
