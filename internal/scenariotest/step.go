package scenariotest

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// Step is one instruction in a scripted scenario. Run performs the
// step against env, appending any assertion rows to env.Report; it
// returns an error only for mechanical failures (a failed assertion is
// a false row, not an error — the run continues so the report shows
// every check). Kind is the short name used in logs and step-scoped
// error wrapping.
//
// Step is deliberately an open interface, not a closed enum: a new
// operational step is one new type in the steps package, no executor
// changes. The two optional extensions below let a step declare what
// it needs of its environment without the core knowing its concrete
// type.
type Step interface {
	Kind() string
	Run(ctx context.Context, env *StepEnv) error
}

// MetricRequirer is an optional [Step] extension: steps that depend on
// a specific /metrics family declare it, and `run` refuses up front
// when an agent does not expose it — failing before any topology
// exists beats timing out mid-scenario for the wrong reason.
type MetricRequirer interface {
	RequiredMetrics() []string
}

// HostNeeds declares which agent_control config keys a step's
// execution requires. A cluster that has not staged them SKIPs the
// scenario rather than failing it — the creds being absent is a
// property of the environment, not a defect in the scenario.
type HostNeeds struct {
	// AgentSSH: the step drives the agent host over SSH.
	AgentSSH bool
	// WALPath: the step removes the agent's WAL.
	WALPath bool
	// PinPath: the step removes the agent's bpffs pin directory.
	PinPath bool
}

// HostRequirer is the optional [Step] extension carrying [HostNeeds].
// Declaring it is how a host-driving step registers its prerequisite;
// the alternative — a type switch over concrete step types in the
// core — would both invert the dependency and go stale silently.
type HostRequirer interface {
	HostNeeds() HostNeeds
}

// Capture is the counter snapshot a capture step takes, and the
// baseline every growth / monotonicity assertion diffs against. One
// value rather than eight parallel fields on [StepEnv], so "what does
// a capture consist of" has a single answer.
type Capture struct {
	// Tuples and Servers are the tenant- and server-tier sums at the
	// instant of capture.
	Tuples  map[Tuple]float64
	Servers map[ServerTuple]float64
	// Epochs is each agent's counters-reset epoch, keyed by host.
	Epochs map[string]float64

	SettledFlows  float64
	SettledTuples float64
	Resolved      float64
	Evictions     float64
	Ghosts        float64
}

// StepEnv is the shared environment a scripted run threads through its
// steps: the realized run-state, the seams, the accumulating report,
// and the cross-step captures (counter snapshot, MACs of deleted VMs).
type StepEnv struct {
	Config     Config
	Scenario   *Scenario
	State      *RunState
	StatePath  string
	ReportPath string
	Cloud      Cloud
	Metrics    MetricsSource
	Exec       VMExec
	// AgentExec runs commands on the agent HOSTS (not the VMs) — the
	// SSH transport for steps that restart an agent, built from
	// [Config.AgentControl]. Nil unless a scenario restarts an agent.
	AgentExec VMExec
	Log       *slog.Logger
	SinkDelay time.Duration
	// MACLearnTimeout passes through to the drive phase's MAC-learn
	// gate; zero uses the default, tests set a small value.
	MACLearnTimeout time.Duration

	// Report accumulates every step's assertion rows; `run` persists
	// it once the script completes.
	Report *AssertReport

	// Captured is the snapshot taken by the most recent capture step.
	// Monotone / growth assertions and the sweep wait diff against it.
	Captured Capture

	// macs records each deleted VM's MAC (captured just before the
	// delete) so a later boot can pin the same one.
	macs map[string]string
	// configDirty names the agent nodes whose on-host config a step has
	// modified and not yet put back, in the order they were modified.
	configDirty []string
}

// AddRow appends one evaluated assertion to the run's report,
// clearing the overall verdict when it failed.
func (e *StepEnv) AddRow(row AssertRow) {
	if !row.Pass {
		e.Report.OK = false
	}
	e.Report.Rows = append(e.Report.Rows, row)
}

// Scrape samples all configured agents once.
func (e *StepEnv) Scrape(ctx context.Context) (MetricsSnapshot, error) {
	return SampleAcross(ctx, e.Metrics, e.Config.Cluster.Agents)
}

// TakeCapture scrapes every agent and records the result as the
// baseline subsequent growth assertions diff against.
func (e *StepEnv) TakeCapture(ctx context.Context) error {
	snap, err := e.Scrape(ctx)
	if err != nil {
		return err
	}
	e.Captured = Capture{
		Tuples:        SumByTuple(snap.Bytes),
		Servers:       SumByServerTuple(snap.Servers),
		Epochs:        snap.CountersResetEpochs,
		SettledFlows:  snap.SettledFlows,
		SettledTuples: snap.SettledTuples,
		Resolved:      snap.UnresolvedResolved,
		Evictions:     snap.PressureReliefEvictions,
		Ghosts:        snap.LingeringGhosts,
	}
	e.Log.Info("capture", "tuples", len(e.Captured.Tuples),
		"server_tuples", len(e.Captured.Servers), "settled_flows", e.Captured.SettledFlows,
		"settled_tuples", e.Captured.SettledTuples, "unresolved_resolved", e.Captured.Resolved,
		"pressure_relief_evictions", e.Captured.Evictions, "lingering_ghosts", e.Captured.Ghosts)
	return nil
}

// Project resolves a DSL project name via the run-state.
func (e *StepEnv) Project(dsl string) (ProjectRef, error) {
	ref, ok := e.State.Projects[dsl]
	if !ok {
		return ProjectRef{}, fmt.Errorf("run-state has no project %q", dsl)
	}
	return ref, nil
}

// TenantLabel resolves what a step's Tenant field matches against the
// metric's tenant_id label: a DSL project name resolves to its
// Keystone UUID; anything else (notably "unknown") is taken literally.
func (e *StepEnv) TenantLabel(tenant string) string {
	if ref, ok := e.State.Projects[tenant]; ok {
		return ref.ID
	}
	return tenant
}

// VMMAC returns a VM's MAC: the value [StepEnv.RecordMAC] captured for
// VMs already gone, read live from its port otherwise.
func (e *StepEnv) VMMAC(ctx context.Context, vm string) (string, error) {
	if mac, ok := e.macs[vm]; ok {
		return mac, nil
	}
	portID := LiveID(e.State.Ports, vm)
	if portID == "" {
		return "", fmt.Errorf("run-state has no port for VM %q", vm)
	}
	return e.Cloud.PortMAC(ctx, portID)
}

// RecordMAC remembers a MAC before the resource carrying it is
// destroyed, so a later step can pin or assert on it.
func (e *StepEnv) RecordMAC(id, mac string) {
	if e.macs == nil {
		e.macs = map[string]string{}
	}
	e.macs[id] = mac
}

// RecordedMAC returns the MAC remembered for id, or "" if none was.
// Unlike [StepEnv.VMMAC] it never falls back to a live read: callers
// that want the MAC of a resource the run itself destroyed must get
// the remembered one or nothing.
func (e *StepEnv) RecordedMAC(id string) string { return e.macs[id] }

// MarkConfigDirty records that node's on-host agent config has been
// modified and owes a restore. Idempotent: a node already owing one is
// not listed twice.
func (e *StepEnv) MarkConfigDirty(node string) {
	for _, n := range e.configDirty {
		if n == node {
			return
		}
	}
	e.configDirty = append(e.configDirty, node)
}

// ClearConfigDirty drops node's outstanding restore — called when a
// scenario restores it explicitly, so the end-of-run sweep has nothing
// left to do.
func (e *StepEnv) ClearConfigDirty(node string) {
	for i, n := range e.configDirty {
		if n == node {
			e.configDirty = append(e.configDirty[:i], e.configDirty[i+1:]...)
			return
		}
	}
}

// TakeConfigDirty returns the nodes still owing a config restore, in
// the order they were modified, and clears the list. The end-of-run
// sweep claims the debt exactly once, however the run ended.
func (e *StepEnv) TakeConfigDirty() []string {
	nodes := e.configDirty
	e.configDirty = nil
	return nodes
}
