// steps.go is the step vocabulary behind scripted scenarios: a
// [Scenario.Steps] list replaces `run`'s classic drive-all/assert-all
// loop with an ordered program executed between up and down. Steps are
// how a scenario expresses mid-run lifecycle events the linear loop
// cannot — deleting a VM, waiting out the agent's ghost sweep,
// rebooting a MAC under another tenant, or (future) taking an agent
// down for a window.
//
// [Step] is deliberately an open interface, not a closed enum: a new
// operational step is one new type in this file, no executor changes.
// The current vocabulary is the minimal set the mac-reuse scenario
// needs plus [SleepStep]; grow it on demand rather than by
// speculation.
package scenariotest

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"regexp"
	"strings"
	"time"
)

const (
	// DefaultSweepTimeout bounds [AwaitSweepStep]. The agent-side
	// pipeline is reconcile notice (Kafka kick, or the 5-minute
	// periodic pass as the ceiling) → 60s ghost grace → 60s sweep
	// tick, so the default must comfortably cover the no-Kafka worst
	// case.
	DefaultSweepTimeout = 8 * time.Minute
	// DefaultPortSeriesTimeout bounds [PortSeriesStep]'s stabilize poll —
	// generously above one scrape interval so a drive's bytes have
	// drained before the row is declared failing.
	DefaultPortSeriesTimeout = 60 * time.Second
	// DefaultAgentReadyTimeout bounds [RestartAgentStep]'s wait for the
	// agent to answer /metrics and re-attach its taps after a restart.
	DefaultAgentReadyTimeout = 90 * time.Second
	// agentReadyPollInterval is the pause between readiness scrapes.
	agentReadyPollInterval = 2 * time.Second
	// configRestoreTimeout bounds the end-of-run sweep that puts back
	// agent configs a run left modified ([StepEnv.restoreDirtyConfigs]).
	// One restore is a file copy plus a unit restart, so this covers a
	// couple of nodes without letting a wedged host hang the exit.
	configRestoreTimeout = 3 * time.Minute
)

// sweepPollInterval is the pause between [AwaitSweepStep] polls. A var,
// not a const, so poll-loop tests can shrink it.
var sweepPollInterval = 5 * time.Second

// Step is one instruction in a scripted scenario. Run performs the
// step against env, appending any assertion rows to env.Report; it
// returns an error only for mechanical failures (a failed assertion is
// a false row, not an error — the run continues so the report shows
// every check). Kind is the short name used in logs and step-scoped
// error wrapping.
type Step interface {
	Kind() string
	Run(ctx context.Context, env *StepEnv) error
}

// metricRequirer is an optional Step extension: steps that depend on a
// specific /metrics family declare it, and `run` refuses up front when
// an agent does not expose it — failing before any topology exists
// beats timing out mid-scenario for the wrong reason.
type metricRequirer interface {
	requiredMetrics() []string
}

// StepEnv is the shared environment a scripted run threads through its
// steps: the realized run-state, the seams, the accumulating report,
// and the cross-step captures (counter snapshot, settled base, MACs of
// deleted VMs).
type StepEnv struct {
	Config     Config
	Scenario   *Scenario
	State      *RunState
	StatePath  string
	ReportPath string
	Cloud      Cloud
	Metrics    MetricsSource
	Exec       VMExec
	// AgentExec runs commands on the agent HOSTS (not the VMs) —
	// [RestartAgentStep]'s SSH transport, built from
	// [Config.AgentControl]. Nil unless a scenario restarts an agent.
	AgentExec VMExec
	Log       *slog.Logger
	SinkDelay time.Duration
	// MACLearnTimeout passes through to [DriveOptions.MACLearnTimeout];
	// zero uses the default, tests set a small value.
	MACLearnTimeout time.Duration

	// Report accumulates every step's assertion rows; `run` persists
	// it once the script completes.
	Report *AssertReport

	// captured is the per-tuple counter snapshot taken by the most
	// recent [CaptureStep]; capturedServers is the per-server family's
	// counterpart; settledBase is the summed settled-flows counter at
	// the same instant. Monotone/growth assertions and the sweep wait
	// diff against them.
	captured          map[tuple]float64
	capturedServers   map[serverTuple]float64
	capturedEpochs    map[string]float64
	settledBase       float64
	settledTuplesBase float64
	resolvedBase      float64
	evictionsBase     float64
	ghostsBase        float64
	// macs records each deleted VM's MAC ([DeleteVMStep] captures it
	// just before the delete) for a later BootVMStep's MACFrom.
	macs map[string]string
	// configDirty names the agent nodes whose on-host config a step has
	// modified and not yet put back, in the order they were modified.
	// [runSteps] restores whatever is still listed when the run ends,
	// however it ends — see [StepEnv.restoreDirtyConfigs].
	configDirty []string
}

// markConfigDirty records that node's on-host agent config has been
// modified and owes a restore. Idempotent: a node already owing one is
// not listed twice.
func (e *StepEnv) markConfigDirty(node string) {
	for _, n := range e.configDirty {
		if n == node {
			return
		}
	}
	e.configDirty = append(e.configDirty, node)
}

// clearConfigDirty drops node's outstanding restore — called when a
// scenario restores it explicitly, so the end-of-run sweep has nothing
// left to do.
func (e *StepEnv) clearConfigDirty(node string) {
	for i, n := range e.configDirty {
		if n == node {
			e.configDirty = append(e.configDirty[:i], e.configDirty[i+1:]...)
			return
		}
	}
}

// restoreDirtyConfigs puts back every agent config a step modified and
// did not restore. It is the safety net for the abort paths: a step
// error returns straight out of [runSteps], so a scenario's trailing
// restore step is never reached and the host would otherwise keep
// serving the scenario's temporary config — silently, into whatever
// runs next (lachesis#274).
//
// Deliberately best-effort and loud: a failure here is logged at error
// level naming the host, never returned, because it must not mask the
// original step error that caused the abort. Restores run newest-first
// and through the ordinary [RestartAgentStep] path, so the running
// agent ends up on the restored file rather than merely the file being
// right on disk.
//
// The context is detached from ctx (a cancelled run — Ctrl-C — is
// exactly when config gets stranded) but bounded, so a wedged host
// cannot hang the run's exit.
func (e *StepEnv) restoreDirtyConfigs(ctx context.Context) {
	if len(e.configDirty) == 0 {
		return
	}
	nodes := e.configDirty
	e.configDirty = nil

	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), configRestoreTimeout)
	defer cancel()
	for i := len(nodes) - 1; i >= 0; i-- {
		node := nodes[i]
		e.Log.Warn("restoring an agent config the run left modified", "node", node)
		if err := (RestartAgentStep{Node: node, RestoreConfig: true}).Run(rctx, e); err != nil {
			e.Log.Error("agent config NOT restored — the host is still on the scenario's config",
				"node", node, "err", err)
		}
	}
}

func (e *StepEnv) addRow(row AssertRow) {
	if !row.Pass {
		e.Report.OK = false
	}
	e.Report.Rows = append(e.Report.Rows, row)
}

// scrape samples all configured agents once.
func (e *StepEnv) scrape(ctx context.Context) (MetricsSnapshot, error) {
	return SampleAcross(ctx, e.Metrics, e.Config.Cluster.Agents)
}

// project resolves a DSL project name via the run-state.
func (e *StepEnv) project(dsl string) (ProjectRef, error) {
	ref, ok := e.State.Projects[dsl]
	if !ok {
		return ProjectRef{}, fmt.Errorf("run-state has no project %q", dsl)
	}
	return ref, nil
}

// tenantLabel resolves what a step's Tenant field matches against the
// metric's tenant_id label: a DSL project name resolves to its
// Keystone UUID; anything else (notably "unknown") is taken literally.
func (e *StepEnv) tenantLabel(tenant string) string {
	if ref, ok := e.State.Projects[tenant]; ok {
		return ref.ID
	}
	return tenant
}

// vmMAC returns a VM's MAC: recorded at deletion for VMs already gone,
// read live from its port otherwise.
func (e *StepEnv) vmMAC(ctx context.Context, vm string) (string, error) {
	if mac, ok := e.macs[vm]; ok {
		return mac, nil
	}
	portID := liveID(e.State.Ports, vm)
	if portID == "" {
		return "", fmt.Errorf("run-state has no port for VM %q", vm)
	}
	return e.Cloud.PortMAC(ctx, portID)
}

// --- the vocabulary ---

// DriveStep pushes Flows exactly like the standalone `drive`
// subcommand: attach recheck, fresh baseline into run-state, then the
// streams. A later [AssertStep] diffs against this step's baseline.
type DriveStep struct {
	Flows []Flow
	// KeepBaseline drives without resetting the run-state baseline, so a
	// following [AssertStep] measures the CUMULATIVE delta since an
	// earlier drive — the way router-regateway proves a second drive's
	// live bytes ADD to the settled total (settled + live) rather than
	// starting from zero.
	KeepBaseline bool
	// SkipMACLearn drives without the pre-drive MAC-learn gate — for the
	// unresolved-latebind scenario, where a VM's MAC is deliberately not
	// yet learned so its first bytes must park unknown. Leave false
	// everywhere else.
	SkipMACLearn bool
	// SkipAttachRecheck drives without re-confirming the up-time attach
	// gate — for a drive that follows a tap teardown (ghost-grace deletes
	// the peer, dropping a tap and racing a benign attach-failure).
	SkipAttachRecheck bool
}

func (DriveStep) Kind() string { return "drive" }

func (s DriveStep) Run(ctx context.Context, env *StepEnv) error {
	sc := *env.Scenario
	sc.Flows = s.Flows
	return Drive(ctx, DriveOptions{
		Config:            env.Config,
		Scenario:          &sc,
		State:             env.State,
		StatePath:         env.StatePath,
		Metrics:           env.Metrics,
		Exec:              env.Exec,
		Log:               env.Log,
		SinkDelay:         env.SinkDelay,
		MACLearnTimeout:   env.MACLearnTimeout,
		KeepBaseline:      s.KeepBaseline,
		SkipMACLearn:      s.SkipMACLearn,
		SkipAttachRecheck: s.SkipAttachRecheck,
	})
}

// IngressFlowStep streams Bytes INTO a VM from the harness itself —
// the "sender outside the cluster" no [Flow] can express, and the
// only way to drive the external/rx tuple through the FIP DNAT path
// (docs/architecture/edge-cases.md). It runs drive's usual gates
// (attach recheck, MAC-learn, fresh baseline — a later [AssertStep]
// diffs against it), then feeds the byte budget over SSH stdin into a
// `cat > /dev/null` on the VM: SSH because its port is the one
// inbound path the platform security group is guaranteed to pass (the
// harness already reaches every VM through it). The stream framing
// only adds bytes on the wire, so MinBytes = Bytes stays a safe lower
// bound.
type IngressFlowStep struct {
	// To is the DSL VM id receiving the stream, dialed at its FIP.
	To    string
	Bytes int64
}

func (IngressFlowStep) Kind() string { return "ingress-flow" }

func (s IngressFlowStep) Run(ctx context.Context, env *StepEnv) error {
	stdin, ok := env.Exec.(StdinExec)
	if !ok {
		return fmt.Errorf("ingress-flow: the exec transport cannot stream stdin (need [StdinExec])")
	}
	// Zero-flow drive: the same gates and baseline capture a DriveStep
	// gets, with the actual traffic pushed from the harness below.
	sc := *env.Scenario
	sc.Flows = nil
	if err := Drive(ctx, DriveOptions{
		Config:          env.Config,
		Scenario:        &sc,
		State:           env.State,
		StatePath:       env.StatePath,
		Metrics:         env.Metrics,
		Exec:            env.Exec,
		Log:             env.Log,
		SinkDelay:       env.SinkDelay,
		MACLearnTimeout: env.MACLearnTimeout,
	}); err != nil {
		return err
	}
	fip := ""
	for _, f := range env.State.FIPs {
		if f.VMID == s.To && f.Network == "" { // the provider SSH FIP
			fip = f.Address
		}
	}
	if fip == "" {
		return fmt.Errorf("ingress-flow: run-state has no SSH FIP for VM %q", s.To)
	}
	if err := awaitSSHReady(ctx, env, s.To, fip); err != nil {
		return fmt.Errorf("ingress-flow: %w", err)
	}
	if out, err := stdin.RunWithStdin(ctx, fip, "cat > /dev/null", io.LimitReader(zeroReader{}, s.Bytes)); err != nil {
		return fmt.Errorf("ingress-flow: stream %d bytes to %s: %w (output: %s)", s.Bytes, s.To, err, out)
	}
	env.Log.Info("ingress-flow: streamed", "to", s.To, "fip", fip, "bytes", s.Bytes)
	return nil
}

// zeroReader is an endless stream of zero bytes; [IngressFlowStep]
// bounds it with io.LimitReader.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// AssertStep evaluates Expect with the stabilize-polling `assert`
// semantics against the most recent DriveStep's baseline, folding the
// rows (tagged Note when they carry none) into the run's report.
type AssertStep struct {
	Expect []Expect
	Note   string
}

func (AssertStep) Kind() string { return "assert" }

func (s AssertStep) Run(ctx context.Context, env *StepEnv) error {
	sc := *env.Scenario
	sc.Expect = s.Expect
	rep, err := Assert(ctx, AssertOptions{
		Config:     env.Config,
		Scenario:   &sc,
		State:      env.State,
		ReportPath: env.ReportPath,
		Metrics:    env.Metrics,
		Log:        env.Log,
	})
	if err != nil {
		return err
	}
	for _, row := range rep.Rows {
		if row.Note == "" {
			row.Note = s.Note
		}
		env.addRow(row)
	}
	return nil
}

// CaptureStep snapshots every counter tuple plus the settled-flows
// base. Monotone and growth assertions, and the sweep wait, diff
// against the most recent capture.
type CaptureStep struct{}

func (CaptureStep) Kind() string { return "capture" }

func (CaptureStep) Run(ctx context.Context, env *StepEnv) error {
	snap, err := env.scrape(ctx)
	if err != nil {
		return err
	}
	env.captured = sumByTuple(snap.Bytes)
	env.capturedServers = sumByServerTuple(snap.Servers)
	env.capturedEpochs = snap.CountersResetEpochs
	env.settledBase = snap.SettledFlows
	env.settledTuplesBase = snap.SettledTuples
	env.resolvedBase = snap.UnresolvedResolved
	env.evictionsBase = snap.PressureReliefEvictions
	env.ghostsBase = snap.LingeringGhosts
	env.Log.Info("capture", "tuples", len(env.captured),
		"server_tuples", len(env.capturedServers), "settled_flows", env.settledBase,
		"settled_tuples", env.settledTuplesBase, "unresolved_resolved", env.resolvedBase,
		"pressure_relief_evictions", env.evictionsBase, "lingering_ghosts", env.ghostsBase)
	return nil
}

// DeleteVMStep tears down exactly one VM — FIP, then server (waiting
// until Nova forgets it, so the port unbinds), then port — recording
// its MAC first for a later [BootVMStep]. The FIP/server records stay
// (the final down re-deletes them as 404-tolerant no-ops); the port
// ref leaves the run-state so the MAC-learn gate never waits on a
// dead port.
type DeleteVMStep struct {
	VM string
}

func (DeleteVMStep) Kind() string { return "delete-vm" }

func (s DeleteVMStep) Run(ctx context.Context, env *StepEnv) error {
	mac, err := env.vmMAC(ctx, s.VM)
	if err != nil {
		return err
	}
	if env.macs == nil {
		env.macs = map[string]string{}
	}
	env.macs[s.VM] = mac

	for _, f := range env.State.FIPs {
		if f.VMID != s.VM {
			continue
		}
		if err := env.Cloud.DeleteFIP(ctx, f.ProjectID, f.ID); err != nil {
			return err
		}
	}
	for _, srv := range env.State.Servers {
		if srv.DSLID != s.VM {
			continue
		}
		if err := env.Cloud.DeleteServer(ctx, srv.ProjectID, srv.ID); err != nil {
			return err
		}
		if err := env.Cloud.WaitServerGone(ctx, srv.ProjectID, srv.ID); err != nil {
			return err
		}
	}
	// The deleted port's ref leaves the run-state: the MAC-learn gate
	// waits on every recorded (MAC, tenant) pair, and a dead port's
	// MAC may be reborn under ANOTHER tenant (mac-reuse) — a stale ref
	// would make the gate unsatisfiable. Truthful-inventory rule, same
	// as [DeleteFIPStep].
	kept := make([]ResourceRef, 0, len(env.State.Ports))
	for _, p := range env.State.Ports {
		if p.DSLID != s.VM {
			kept = append(kept, p)
			continue
		}
		if err := env.Cloud.DeletePort(ctx, p.ProjectID, p.ID); err != nil {
			return err
		}
	}
	env.State.Ports = kept
	if err := env.State.Save(env.StatePath); err != nil {
		return err
	}
	env.Log.Info("delete-vm: gone", "vm", s.VM, "mac", mac)
	return nil
}

// AwaitSweepStep blocks until the ghost sweep has processed a deleted
// VM/NIC. Prefer ForMACOf: it polls every agent's /debug/lookup for that
// entity's MAC and returns once the MAC no longer resolves in the
// userspace metadata map — which the sweep deletes LAST, after it has
// folded the MAC's GlobalState rows into settled (docs/architecture/data-structures.md#settled-bytes;
// sweep order: kernel delete → residual-flow evict → settle FOLD →
// userspace delete). So "MAC gone from /debug/lookup" is a precise,
// per-MAC signal that the fold (and therefore the per-server-series
// drop) has happened.
//
// With ForMACOf empty it falls back to waiting for the global
// lachesis_gc_settled_flows_total to rise — which is only trustworthy on
// a quiet single-tenant agent: on a shared agent other tenants' folds
// move that counter constantly, so the wait returns before THIS entity's
// grace elapses and any following assertion reads pre-fold state
// (lachesis#240). New scenarios should always set ForMACOf.
type AwaitSweepStep struct {
	// ForMACOf is the DSL id of the VM or NIC whose deleted MAC's fold to
	// wait for — recorded by the preceding [DeleteVMStep] / [DetachPortStep].
	ForMACOf string
	Timeout  time.Duration
}

func (AwaitSweepStep) Kind() string { return "await-sweep" }

func (s AwaitSweepStep) requiredMetrics() []string {
	if s.ForMACOf != "" {
		return nil // uses /debug/lookup, not a metric family
	}
	return []string{MetricSettledFlows}
}

func (s AwaitSweepStep) Run(ctx context.Context, env *StepEnv) error {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultSweepTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if s.ForMACOf != "" {
		return s.awaitMACSwept(ctx, env, timeout)
	}
	env.Log.Warn("await-sweep: waiting on the GLOBAL settled counter — unreliable on a shared agent (lachesis#240); set ForMACOf", "settled_flows_above", env.settledBase, "timeout", timeout)
	for {
		snap, err := env.scrape(ctx)
		if err != nil {
			return err
		}
		if snap.SettledFlows > env.settledBase {
			env.Log.Info("await-sweep: observed", "settled_flows_from", env.settledBase, "settled_flows_to", snap.SettledFlows)
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("ghost sweep not observed within %s (settled_flows still %.0f): %w",
				timeout, snap.SettledFlows, ctx.Err())
		case <-time.After(sweepPollInterval):
		}
	}
}

// awaitMACSwept polls every agent's /debug/lookup for the MAC recorded
// against ForMACOf and returns once it resolves on none of them — the
// userspace metadata delete that ends the ghost sweep, which happens
// after the fold.
func (s AwaitSweepStep) awaitMACSwept(ctx context.Context, env *StepEnv, timeout time.Duration) error {
	mac, err := env.vmMAC(ctx, s.ForMACOf)
	if err != nil {
		return fmt.Errorf("await-sweep: no MAC known for %q (delete or detach it first): %w", s.ForMACOf, err)
	}
	env.Log.Info("await-sweep: waiting for MAC to leave metadata", "for", s.ForMACOf, "mac", mac, "timeout", timeout)
	everFound := false // did the MAC resolve on any agent at any poll?
	var lastErr error  // most recent transient lookup failure, surfaced on timeout
	for {
		gone := true
		for _, u := range agentURLs(env.Config) {
			res, err := env.Metrics.LookupMAC(ctx, u, mac)
			if err != nil {
				// A momentarily-unreachable agent can't confirm the MAC is
				// gone there — keep waiting rather than abort, so one bad
				// scrape on a multi-node cluster doesn't fail the wait.
				lastErr = err
				gone = false
				continue
			}
			if res.Found {
				everFound = true
				gone = false
			}
		}
		if gone {
			if !everFound {
				// The MAC never resolved on any agent during the wait: it was
				// already swept before the first poll, or ForMACOf points at
				// an entity whose traffic was never driven/learned. Nothing to
				// wait for — return, but loudly, since a silent pass here would
				// mask a mis-targeted ForMACOf.
				env.Log.Warn("await-sweep: MAC never in metadata during the wait — nothing to await (already swept, or ForMACOf never learned)",
					"for", s.ForMACOf, "mac", mac)
				return nil
			}
			env.Log.Info("await-sweep: swept (MAC gone from metadata)", "for", s.ForMACOf, "mac", mac)
			return nil
		}
		select {
		case <-ctx.Done():
			if lastErr != nil {
				return fmt.Errorf("await-sweep: MAC %s (%s) not confirmed gone after %s (last lookup error: %v): %w", mac, s.ForMACOf, timeout, lastErr, ctx.Err())
			}
			return fmt.Errorf("await-sweep: MAC %s (%s) still in metadata after %s — ghost not swept: %w", mac, s.ForMACOf, timeout, ctx.Err())
		case <-time.After(sweepPollInterval):
		}
	}
}

// MonotoneStep asserts every captured tuple of Tenant is still at or
// above its captured value — the live form of the docs/architecture/contracts.md#required-contracts Contract 7
// series-monotonicity guarantee. One row per tuple.
type MonotoneStep struct {
	Tenant string
	Note   string
}

func (MonotoneStep) Kind() string { return "assert-monotone" }

func (s MonotoneStep) Run(ctx context.Context, env *StepEnv) error {
	ref, err := env.project(s.Tenant)
	if err != nil {
		return err
	}
	snap, err := env.scrape(ctx)
	if err != nil {
		return err
	}
	cur := sumByTuple(snap.Bytes)
	for k, base := range env.captured {
		if k.tenant != ref.ID {
			continue
		}
		env.addRow(AssertRow{
			Tenant: s.Tenant, TenantID: k.tenant,
			Zone: k.zone, Direction: k.direction,
			Baseline: base, Current: cur[k], Delta: cur[k] - base,
			Pass: cur[k] >= base, Note: s.Note,
		})
	}
	return nil
}

// MaxGrowthStep asserts a (tenant, zone) pair's tx and rx tuples have
// grown by less than Budget since the most recent capture. It is the
// negative-space check: "the deleted VM's bytes did not re-bucket to
// unknown" and "the reborn MAC brought no history" are both bounded-
// growth claims, differing only in target. Budget separates background
// chatter (KiBs) from a mis-attributed flow (MiBs).
type MaxGrowthStep struct {
	Tenant string // DSL project name, or a literal label like "unknown"
	Zone   string
	Budget int64
	Note   string
}

func (MaxGrowthStep) Kind() string { return "assert-max-growth" }

func (s MaxGrowthStep) Run(ctx context.Context, env *StepEnv) error {
	label := env.tenantLabel(s.Tenant)
	snap, err := env.scrape(ctx)
	if err != nil {
		return err
	}
	cur := sumByTuple(snap.Bytes)
	for _, dir := range []string{"tx", "rx"} {
		k := tuple{label, s.Zone, dir}
		env.addRow(AssertRow{
			Tenant: s.Tenant, TenantID: label,
			Zone: s.Zone, Direction: dir,
			Baseline: env.captured[k], Current: cur[k], Delta: cur[k] - env.captured[k],
			Pass: cur[k]-env.captured[k] < float64(s.Budget),
			Note: s.Note,
		})
	}
	return nil
}

// BootVMStep realizes one of the scenario's Deferred VMs mid-run: its
// port (optionally pinning a deleted VM's MAC via MACFrom), server,
// FIP, and a +1 attach gate — everything `up` would have done, at the
// moment the script wants it. The VM's project, network, subnet, and
// fixed IP all come from its declaration in the scenario's Builder.
type BootVMStep struct {
	VM string
	// MACFrom names a VM whose MAC this port pins — recorded at its
	// DeleteVMStep, or read live if it still exists. Empty lets
	// Neutron assign a MAC.
	MACFrom string
}

func (BootVMStep) Kind() string { return "boot-vm" }

func (s BootVMStep) Run(ctx context.Context, env *StepEnv) error {
	snap := env.Scenario.Builder.Build()
	var project, network, subnet, ip string
	for _, p := range snap.Ports {
		if p.ID == s.VM && len(p.FixedIPs) > 0 {
			project, network = p.ProjectID, p.NetworkID
			subnet, ip = p.FixedIPs[0].SubnetID, p.FixedIPs[0].IPAddress
			break
		}
	}
	if project == "" {
		return fmt.Errorf("scenario declares no VM %q", s.VM)
	}
	proj, err := env.project(project)
	if err != nil {
		return err
	}
	netID := liveID(env.State.Networks, network)
	subnetID := liveID(env.State.Subnets, subnet)
	if netID == "" || subnetID == "" {
		return fmt.Errorf("run-state has no live ids for %s/%s", network, subnet)
	}

	mac := ""
	if s.MACFrom != "" {
		if mac, err = env.vmMAC(ctx, s.MACFrom); err != nil {
			return err
		}
	}
	p := env.Config.Prerequisites
	flavorID, err := env.Cloud.FindFlavor(ctx, flavorFor(env.Config, env.Scenario))
	if err != nil {
		return err
	}
	imageID, err := env.Cloud.FindImage(ctx, p.ImageName)
	if err != nil {
		return err
	}
	secGroupID, err := env.Cloud.FindSecGroup(ctx, p.SecGroupName)
	if err != nil {
		return err
	}
	extNetID, err := env.Cloud.FindExternalNetwork(ctx, p.ExternalNetworkName)
	if err != nil {
		return err
	}

	baseline, err := env.scrape(ctx)
	if err != nil {
		return fmt.Errorf("attach baseline scrape: %w", err)
	}

	name := Mangle(env.Config.Naming.Prefix, env.State.RunID, s.VM)
	portID, err := env.Cloud.CreatePort(ctx, proj.ID, PortSpec{
		Name:       name,
		NetworkID:  netID,
		SubnetID:   subnetID,
		FixedIP:    ip,
		SecGroupID: secGroupID,
		MACAddress: mac,
	})
	if err != nil {
		return err
	}
	portMAC := mac
	if portMAC == "" {
		if portMAC, err = env.Cloud.PortMAC(ctx, portID); err != nil {
			return err
		}
	}
	env.State.Ports = append(env.State.Ports, ResourceRef{DSLID: s.VM, ID: portID, Name: name, ProjectID: proj.ID, MAC: portMAC})
	if err := env.State.Save(env.StatePath); err != nil {
		return err
	}

	// Deferred VMs honor Scenario.Placement like up-time boots do,
	// reusing realize's recorded resolution; run-states predating
	// placement persistence resolve fresh.
	placement := env.State.Placement
	if placement == nil {
		var perr error
		if placement, perr = resolvePlacement(env.Scenario.Placement, env.Config.Cluster.Agents); perr != nil {
			return perr
		}
	}
	serverID, err := env.Cloud.CreateServer(ctx, proj.ID, ServerSpec{
		Name:             name,
		FlavorID:         flavorID,
		ImageID:          imageID,
		PortID:           portID,
		KeypairName:      p.KeypairName,
		AvailabilityZone: placementAZ(placement, s.VM),
	})
	if err != nil {
		return err
	}
	env.State.Servers = append(env.State.Servers, ResourceRef{DSLID: s.VM, ID: serverID, Name: name, ProjectID: proj.ID})
	if err := env.State.Save(env.StatePath); err != nil {
		return err
	}
	activeCtx, cancel := context.WithTimeout(ctx, serverActiveTimeout)
	defer cancel()
	if err := env.Cloud.WaitServerActive(activeCtx, proj.ID, serverID); err != nil {
		return err
	}

	fipID, addr, err := env.Cloud.CreateFIP(ctx, proj.ID, FIPCreateSpec{
		ExternalNetworkID: extNetID,
		PortID:            portID,
		FixedIP:           ip,
	})
	if err != nil {
		return err
	}
	env.State.FIPs = append(env.State.FIPs, FIPRef{VMID: s.VM, ID: fipID, Address: addr, ProjectID: proj.ID})
	if err := env.State.Save(env.StatePath); err != nil {
		return err
	}
	env.Log.Info("boot-vm: up", "vm", s.VM, "port", portID, "mac", mac, "server", serverID, "fip", addr)

	return s.attachGate(ctx, env, baseline)
}

// attachGate waits for the booted VM's tap with the same summed gauge
// + no-new-failures rule as realize, then refreshes the run-state's
// attach record so a later DriveStep's recheck expects the new count.
func (s BootVMStep) attachGate(ctx context.Context, env *StepEnv, baseline MetricsSnapshot) error {
	return awaitAttachRise(ctx, env, baseline, "boot-vm")
}

// awaitAttachRise blocks until the agents' summed attached-interfaces
// gauge rises one above baseline with no new attach failures, then
// refreshes the run-state's attach record so a later DriveStep's
// recheck expects the new count. Shared by every step that plugs one
// new tap in ([BootVMStep], [AttachPortStep], [ReattachPortStep]).
func awaitAttachRise(ctx context.Context, env *StepEnv, baseline MetricsSnapshot, kind string) error {
	target := baseline.AttachedInterfaces + 1
	ctx, cancel := context.WithTimeout(ctx, DefaultAttachTimeout)
	defer cancel()
	for {
		snap, err := env.scrape(ctx)
		if err != nil {
			return fmt.Errorf("attach gate scrape: %w", err)
		}
		if snap.AttachFailures > baseline.AttachFailures {
			return fmt.Errorf("attach gate: %.0f new TC attach failure(s)", snap.AttachFailures-baseline.AttachFailures)
		}
		if snap.AttachedInterfaces >= target {
			env.Log.Info(kind+": attach gate green", "attached", snap.AttachedInterfaces, "target", target)
			env.State.Attach = AttachRecord{Target: target, Failures: snap.AttachFailures}
			return env.State.Save(env.StatePath)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("attach gate: attached_interfaces %.0f < %.0f before timeout: %w",
				snap.AttachedInterfaces, target, ctx.Err())
		case <-time.After(attachPollInterval):
		}
	}
}

// AssociateFIPStep allocates one extra floating IP for a live VM from
// a specific DSL external network (created or provider-bound) and
// binds it to the VM's port — the second-external-path move of the
// multi-external-path scenario. The FIP is recorded in the run-state
// (down deletes it like any other) tagged with the DSL network id so
// a later [DeleteFIPStep] can target exactly it.
type AssociateFIPStep struct {
	VM      string
	Network string
}

func (AssociateFIPStep) Kind() string { return "associate-fip" }

func (s AssociateFIPStep) Run(ctx context.Context, env *StepEnv) error {
	snap := env.Scenario.Builder.Build()
	var project, ip string
	for _, p := range snap.Ports {
		if p.ID == s.VM && len(p.FixedIPs) > 0 {
			project, ip = p.ProjectID, p.FixedIPs[0].IPAddress
			break
		}
	}
	if project == "" {
		return fmt.Errorf("scenario declares no VM %q", s.VM)
	}
	proj, err := env.project(project)
	if err != nil {
		return err
	}
	portID := liveID(env.State.Ports, s.VM)
	if portID == "" {
		return fmt.Errorf("run-state has no live port for %q", s.VM)
	}
	netID := liveID(env.State.Networks, s.Network)
	if netID == "" {
		// Provider-bound external marker (not a CreateExternalNets net in
		// run-state) resolves to the config's external network, the same
		// mapping realize applies — so a FIP can be re-established on the
		// provider net after a round trip freed it.
		for _, n := range snap.Networks {
			if n.ID == s.Network && n.IsExternal {
				if netID, err = env.Cloud.FindExternalNetwork(ctx, env.Config.Prerequisites.ExternalNetworkName); err != nil {
					return fmt.Errorf("associate-fip: resolve provider external net: %w", err)
				}
				break
			}
		}
	}
	if netID == "" {
		return fmt.Errorf("associate-fip: no live network for %q (not a created external net nor a provider-bound marker)", s.Network)
	}
	fipID, addr, err := env.Cloud.CreateFIP(ctx, proj.ID, FIPCreateSpec{
		ExternalNetworkID: netID,
		PortID:            portID,
		FixedIP:           ip,
	})
	if err != nil {
		return err
	}
	env.State.FIPs = append(env.State.FIPs, FIPRef{
		VMID: s.VM, ID: fipID, Address: addr, ProjectID: proj.ID, Network: s.Network,
	})
	if err := env.State.Save(env.StatePath); err != nil {
		return err
	}
	env.Log.Info("associate-fip", "vm", s.VM, "addr", addr, "network", s.Network)
	return nil
}

// routerRef finds a router's run-state entry (live id + project) by
// its DSL id — shared by the Neutron-mutation steps.
func routerRef(env *StepEnv, dsl string) (ResourceRef, error) {
	for _, r := range env.State.Routers {
		if r.DSLID == dsl {
			return r, nil
		}
	}
	return ResourceRef{}, fmt.Errorf("run-state has no router %q", dsl)
}

// SetRouterRoutesStep replaces a router's static (extra) routes mid-run
// via the Neutron API — the live route change behind the
// extraroute-mutation scenario. The agent's next reconcile rebuilds the
// trie insert-then-delete (docs/architecture/trie-construction.md), so
// new traffic reclassifies with no MISS window. Routes wholly replaces
// the router's route set (an empty slice clears them).
type SetRouterRoutesStep struct {
	Router string
	Routes []RouteSpec
}

func (SetRouterRoutesStep) Kind() string { return "set-router-routes" }

func (s SetRouterRoutesStep) Run(ctx context.Context, env *StepEnv) error {
	ref, err := routerRef(env, s.Router)
	if err != nil {
		return err
	}
	if err := env.Cloud.SetRouterRoutes(ctx, ref.ProjectID, ref.ID, s.Routes); err != nil {
		return err
	}
	env.Log.Info("set-router-routes", "router", s.Router, "routes", len(s.Routes))
	return nil
}

// SetRouterGatewayStep re-points a router's external gateway to another
// DSL external network mid-run — the re-gateway mutation. The agent's
// reconcile rebuilds the router-interface-MAC → external-network map;
// every flow riding a changed router MAC folds under its OLD label
// first (reconcile/routers.go [state.SettleRebase]), keeping the
// external_network series monotone across the move. ExternalNet is a
// DSL external-network id resolved to its live network via the
// run-state (a [Scenario.CreateExternalNets] marker).
type SetRouterGatewayStep struct {
	Router      string
	ExternalNet string
}

func (SetRouterGatewayStep) Kind() string { return "set-router-gateway" }

func (s SetRouterGatewayStep) Run(ctx context.Context, env *StepEnv) error {
	ref, err := routerRef(env, s.Router)
	if err != nil {
		return err
	}
	netID := liveID(env.State.Networks, s.ExternalNet)
	if netID == "" {
		// Not a created (CreateExternalNets) network in run-state — a
		// provider-bound external marker resolves to the config's external
		// network, the same mapping realize applies (so re-gatewaying BACK
		// to the provider net works on the round trip).
		for _, n := range env.Scenario.Builder.Build().Networks {
			if n.ID == s.ExternalNet && n.IsExternal {
				if netID, err = env.Cloud.FindExternalNetwork(ctx, env.Config.Prerequisites.ExternalNetworkName); err != nil {
					return fmt.Errorf("set-router-gateway: resolve provider external net: %w", err)
				}
				break
			}
		}
	}
	if netID == "" {
		return fmt.Errorf("set-router-gateway: no live network for %q (not a created external net nor a provider-bound marker)", s.ExternalNet)
	}
	if err := env.Cloud.SetRouterGateway(ctx, ref.ProjectID, ref.ID, netID); err != nil {
		return err
	}
	env.Log.Info("set-router-gateway", "router", s.Router, "external_net", s.ExternalNet)
	return nil
}

// SettledTuplesGrewStep asserts the settled-accumulator tuple count —
// the SUM of the four-layer per-tier gauges (state_{tenant,server,total}
// _settled_tuples) — rose by at least Min since the most recent
// [CaptureStep] — the live proof that a fold actually fired.
// It polls (folds land a reconcile pass after the mutation, not
// instantly) until the floor is met or Timeout (default
// [DefaultSweepTimeout]) records a failing row. Unlike the GC-only
// settled_flows counter, this gauge also moves on a reconcile-driven
// [state.SettleRebase], so it discriminates "the attribution change
// folded the port's flows" from "nothing happened".
type SettledTuplesGrewStep struct {
	Min     int64
	Timeout time.Duration
	Note    string
}

func (SettledTuplesGrewStep) Kind() string { return "assert-settled-tuples-grew" }

func (SettledTuplesGrewStep) requiredMetrics() []string { return []string{MetricTenantSettledTuples} }

func (s SettledTuplesGrewStep) Run(ctx context.Context, env *StepEnv) error {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultSweepTimeout
	}
	deadline := time.Now().Add(timeout)
	var delta float64
	for {
		snap, err := env.scrape(ctx)
		if err != nil {
			return err
		}
		delta = snap.SettledTuples - env.settledTuplesBase
		if delta >= float64(s.Min) || time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(sweepPollInterval):
		}
	}
	env.addRow(AssertRow{
		Tenant: "settled-tuples", Zone: "-", Direction: "-",
		Baseline: env.settledTuplesBase, Current: env.settledTuplesBase + delta, Delta: delta,
		MinBytes: s.Min, Pass: delta >= float64(s.Min), Note: s.Note,
	})
	return nil
}

// AddRouteStep adds an in-guest static route on a VM (`sudo ip route
// add CIDR via Via`) — how a scenario steers traffic through a
// specific router when the VM's default route points elsewhere (the
// second-router drive of the multi-external-path scenario). The
// platform cannot see in-guest routes, which is exactly the point:
// the per-flow router-MAC attribution must still label the traffic by
// the router that carried it. Assumes the VM is SSH-reachable (a
// prior DriveStep's readiness gate, in practice).
type AddRouteStep struct {
	VM   string
	CIDR string
	Via  string
}

func (AddRouteStep) Kind() string { return "add-route" }

func (s AddRouteStep) Run(ctx context.Context, env *StepEnv) error {
	fip := ""
	for _, f := range env.State.FIPs {
		if f.VMID == s.VM && f.Network == "" { // the provider SSH FIP
			fip = f.Address
		}
	}
	if fip == "" {
		return fmt.Errorf("run-state has no SSH FIP for VM %q", s.VM)
	}
	if err := awaitSSHReady(ctx, env, s.VM, fip); err != nil {
		return fmt.Errorf("add-route: %w", err)
	}
	// Absolute path: cirros sudo's PATH lacks /sbin ("sudo: ip: command
	// not found"); the busybox `route` spelling is the fallback for
	// images without iproute2 at that path.
	cmd := fmt.Sprintf("sudo /sbin/ip route add %s via %s 2>/dev/null || sudo route add -net %s gw %s",
		s.CIDR, s.Via, s.CIDR, s.Via)
	if out, err := env.Exec.Run(ctx, fip, cmd); err != nil {
		return fmt.Errorf("add-route %s via %s on %s: %w (output: %s)", s.CIDR, s.Via, s.VM, err, out)
	}
	env.Log.Info("add-route", "cidr", s.CIDR, "via", s.Via, "vm", s.VM)
	return nil
}

// EnableForwardingStep turns a VM into a router, which takes two
// sysctls, not one:
//
//   - `net.ipv4.ip_forward=1` so packets addressed through the VM are
//     forwarded rather than dropped.
//   - `rp_filter=0` (all + default) so they survive reverse-path
//     filtering. This one is easy to miss and fails silently: a packet
//     arriving on the transit NIC carries the ORIGINAL sender's source
//     address, and the appliance has no route back to that subnet via
//     the NIC it arrived on (its only default route is via its boot
//     NIC), so with rp_filter on, Linux discards it before forwarding
//     — no counter moves anywhere, which reads exactly like "the
//     platform never delivered the traffic".
//
// Together they are what makes a VM usable as an extraroute nexthop
// (`device_owner compute:*`) — the resolver's Step B case
// (docs/architecture/trie-construction.md#the-static-route-resolver),
// exercised live by the vm-appliance-nexthop scenario.
//
// The forwarded packet keeps the ORIGINAL source IP, so the port it
// leaves by must ALSO have port security disabled
// ([PortSpec.PortSecurityOff] / [AttachPortStep.PortSecurityOff]) or
// OVN anti-spoofing drops it on the way out. Same absolute-path +
// SSH-FIP spelling as [AddRouteStep].
type EnableForwardingStep struct {
	VM string
}

func (EnableForwardingStep) Kind() string { return "enable-forwarding" }

func (s EnableForwardingStep) Run(ctx context.Context, env *StepEnv) error {
	fip := ""
	for _, f := range env.State.FIPs {
		if f.VMID == s.VM && f.Network == "" { // the provider SSH FIP
			fip = f.Address
		}
	}
	if fip == "" {
		return fmt.Errorf("run-state has no SSH FIP for VM %q", s.VM)
	}
	if err := awaitSSHReady(ctx, env, s.VM, fip); err != nil {
		return fmt.Errorf("enable-forwarding: %w", err)
	}
	// Written straight to /proc: cirros has no /sbin/sysctl in sudo's
	// PATH, and tee-ing the pseudo-files is the portable spelling. Both
	// values are read back so a silently-ignored write fails HERE rather
	// than as a mystifying zero-delta at the appliance's tap.
	// Every conf/*/rp_filter, not just conf/all: the kernel takes
	// max(conf.all, conf.<dev>), so a per-device 1 left over from
	// interface creation would still drop the forwarded packet. The
	// read-back collapses them with sort -u, so any surviving 1 shows up.
	const cmd = "echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward >/dev/null; " +
		"for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 | sudo tee $f >/dev/null; done; " +
		"cat /proc/sys/net/ipv4/ip_forward; " +
		"cat /proc/sys/net/ipv4/conf/*/rp_filter | sort -u"
	out, err := env.Exec.Run(ctx, fip, cmd)
	if err != nil {
		return fmt.Errorf("enable-forwarding on %s: %w (output: %s)", s.VM, err, out)
	}
	got := strings.Fields(strings.TrimSpace(out))
	if len(got) != 2 || got[0] != "1" || got[1] != "0" {
		return fmt.Errorf("enable-forwarding on %s: ip_forward/rp_filter read %v, want [1 0]", s.VM, got)
	}
	env.Log.Info("enable-forwarding", "vm", s.VM, "ip_forward", 1, "rp_filter", 0)
	return nil
}

// AssertFlowPeerStep proves WHICH interface carried driven bytes: it
// resolves the named router's interface port on the given attach IP
// (declared by the DSL, MAC recorded in the run-state), queries every
// agent's /debug/flows for rows carrying that MAC, and asserts the
// summed bytes in Zone meet MinBytes. This is the flow-granular gate
// that a label assertion alone cannot provide — the external_network
// label of a fallback-tier flow equals the default route's label, so
// only the peer MAC on the flow key distinguishes "rode the intended
// router" from "accidentally rode the default route".
type AssertFlowPeerStep struct {
	Router   string // DSL router id
	Via      string // the Attach IP naming which interface of the router
	Zone     string
	MinBytes int64
	Note     string
}

func (AssertFlowPeerStep) Kind() string { return "assert-flow-peer" }

func (s AssertFlowPeerStep) Run(ctx context.Context, env *StepEnv) error {
	// The DSL declares the interface port; the run-state ref carries
	// the Neutron-assigned MAC realize recorded.
	snap := env.Scenario.Builder.Build()
	dslPort := ""
	for _, p := range snap.Ports {
		if p.DeviceOwner == "network:router_interface" && p.DeviceID == s.Router &&
			len(p.FixedIPs) > 0 && p.FixedIPs[0].IPAddress == s.Via {
			dslPort = p.ID
		}
	}
	if dslPort == "" {
		return fmt.Errorf("scenario declares no %s interface at %s", s.Router, s.Via)
	}
	mac := ""
	for _, ref := range env.State.Ports {
		if ref.DSLID == dslPort {
			mac = ref.MAC
		}
	}
	if mac == "" {
		return fmt.Errorf("run-state has no MAC for %s (port %s)", s.Router, dslPort)
	}

	var total float64
	for _, u := range agentURLs(env.Config) {
		rows, err := env.Metrics.LookupFlows(ctx, u, mac)
		if err != nil {
			return fmt.Errorf("assert-flow-peer: %w", err)
		}
		for _, r := range rows {
			if r.Zone == s.Zone {
				total += r.Bytes
			}
		}
	}
	env.addRow(AssertRow{
		Tenant: "flow-peer", Zone: s.Zone, Direction: "-",
		Current: total, Delta: total, MinBytes: s.MinBytes,
		Pass: total >= float64(s.MinBytes),
		Note: s.Note,
	})
	env.Log.Info("assert-flow-peer", "router", s.Router, "via", s.Via, "mac", mac, "zone", s.Zone, "bytes", total, "min", s.MinBytes)
	return nil
}

// DeleteFIPStep removes the floating IP(s) a prior [AssociateFIPStep]
// bound to VM from the named DSL network. Provider-net FIPs (Network
// "" in the run-state — the SSH path) are never touched — unless
// Provider is set, which targets EXACTLY that SSH FIP: the
// router-regateway scenario frees it so Neutron will let the router's
// external gateway change (RouterExternalGatewayInUseByFloatingIp
// otherwise). Deleting it sacrifices SSH, so only steps that drive
// nothing afterward use Provider.
type DeleteFIPStep struct {
	VM       string
	Network  string
	Provider bool
}

func (DeleteFIPStep) Kind() string { return "delete-fip" }

func (s DeleteFIPStep) Run(ctx context.Context, env *StepEnv) error {
	deleted := 0
	kept := make([]FIPRef, 0, len(env.State.FIPs))
	for _, f := range env.State.FIPs {
		// Without Provider, the SSH FIP (Network "") is never a target —
		// only Provider opts into it, so a stray empty Network can't
		// silently sacrifice SSH.
		match := f.VMID == s.VM && f.Network == s.Network && f.Network != ""
		if s.Provider {
			match = f.VMID == s.VM && f.Network == "" // the provider SSH FIP
		}
		if !match {
			kept = append(kept, f)
			continue
		}
		if err := env.Cloud.DeleteFIP(ctx, f.ProjectID, f.ID); err != nil {
			return err
		}
		deleted++
		env.Log.Info("delete-fip: gone", "addr", f.Address, "network", f.Network, "provider", s.Provider)
	}
	if deleted == 0 {
		return fmt.Errorf("run-state has no matching FIP for VM %q (network %q, provider %v)", s.VM, s.Network, s.Provider)
	}
	// Drop the deleted refs so `down` doesn't re-delete them — the
	// run-state stays a truthful inventory of what is still live.
	env.State.FIPs = kept
	return env.State.Save(env.StatePath)
}

const (
	// DefaultAnomalyTimeout bounds [AssertAnomalyStep]'s poll. The
	// gauge updates when a reconcile pass commits — Kafka-kicked
	// within seconds of the triggering resource event, with the
	// 5-minute periodic pass as the no-Kafka ceiling.
	DefaultAnomalyTimeout = 8 * time.Minute
	// anomalyPollInterval is the pause between AssertAnomalyStep
	// scrapes.
	anomalyPollInterval = 5 * time.Second
)

// AssertAnomalyStep polls the agents' summed
// lachesis_neutron_anomalies{class=Class} until Min ≤ value ≤ Max
// (both inclusive) or Timeout (default [DefaultAnomalyTimeout])
// fires, then records one report row either way. Polling — rather
// than a one-shot read — because the gauge only updates when a
// reconcile pass commits the topology change the step just made.
type AssertAnomalyStep struct {
	Class   string
	Min     int64
	Max     int64
	Timeout time.Duration
	Note    string
}

func (AssertAnomalyStep) Kind() string { return "assert-anomaly" }

func (AssertAnomalyStep) requiredMetrics() []string { return []string{MetricNeutronAnomalies} }

func (s AssertAnomalyStep) Run(ctx context.Context, env *StepEnv) error {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultAnomalyTimeout
	}
	env.Log.Info("assert-anomaly", "class", s.Class, "min", s.Min, "max", s.Max, "timeout", timeout)
	deadline := time.Now().Add(timeout)
	var last float64
	for {
		snap, err := env.scrape(ctx)
		if err != nil {
			return err
		}
		last = snap.Anomalies[s.Class]
		if last >= float64(s.Min) && last <= float64(s.Max) {
			break
		}
		if time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(anomalyPollInterval):
		}
	}
	env.addRow(AssertRow{
		Tenant: "anomaly", Zone: s.Class, Direction: "-",
		Current: last, Delta: last, MinBytes: s.Min,
		Pass: last >= float64(s.Min) && last <= float64(s.Max),
		Note: s.Note,
	})
	return nil
}

// Migration timing: live migrations on the target clusters complete
// in well under a minute; five bounds a stuck migration without
// hanging an unattended run.
const (
	DefaultMigrateTimeout = 5 * time.Minute
	migratePollInterval   = 3 * time.Second
)

// MigrateStep live-migrates a realized VM and waits until Nova
// reports it ACTIVE on a different host. Target optionally names the
// destination — a placement slot ("node:<i>") or a literal configured
// agent host, the [Scenario.Placement] vocabulary — empty lets the
// scheduler choose. The completed move is appended to the run-state's
// Migrations (source and destination hosts), the evidence per-node
// assertions across the migration are judged against. Node identity
// in those assertions follows the OBSERVING agent: bytes driven after
// this step surface on the destination's series.
type MigrateStep struct {
	VM     string
	Target string
	// Timeout bounds the wait for the migration to land; zero uses
	// [DefaultMigrateTimeout]. Tests set a small value.
	Timeout time.Duration
}

func (MigrateStep) Kind() string { return "migrate" }

func (s MigrateStep) Run(ctx context.Context, env *StepEnv) error {
	var ref ResourceRef
	for _, r := range env.State.Servers {
		if r.DSLID == s.VM {
			ref = r
			break
		}
	}
	if ref.ID == "" {
		return fmt.Errorf("migrate: run-state has no server for VM %q", s.VM)
	}
	target := ""
	if s.Target != "" {
		host, err := resolveNode(s.Target, env.Config.Cluster.Agents)
		if err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
		target = host
	}
	from, err := env.Cloud.ServerHost(ctx, ref.ProjectID, ref.ID)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	if target != "" && target == from {
		return fmt.Errorf("migrate: VM %q already on %s — a migration that moves nothing proves nothing", s.VM, from)
	}
	env.Log.Info("migrate: requested", "vm", s.VM, "server", ref.ID, "from", from, "target", dashEmpty(target))
	if err := env.Cloud.LiveMigrateServer(ctx, ref.ProjectID, ref.ID, target); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultMigrateTimeout
	}
	deadline := time.Now().Add(timeout)
	for {
		host, err := env.Cloud.ServerHost(ctx, ref.ProjectID, ref.ID)
		if err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
		if host != from && (target == "" || host == target) {
			if err := env.Cloud.WaitServerActive(ctx, ref.ProjectID, ref.ID); err != nil {
				return fmt.Errorf("migrate: %w", err)
			}
			env.State.Migrations = append(env.State.Migrations, MigrationRecord{VM: s.VM, From: from, To: host})
			// Re-baseline the attach record: migration legitimately
			// re-plumbs taps, and the source agent racing its dying tap
			// increments the failure counter (benign — the link is
			// gone). Without a fresh baseline the next drive's recheck
			// reads that noise as taps lost since up.
			if snap, err := SampleAcross(ctx, env.Metrics, env.Config.Cluster.Agents); err == nil {
				env.State.Attach.Failures = snap.AttachFailures
			} else {
				return fmt.Errorf("migrate: attach re-baseline scrape: %w", err)
			}
			if err := env.State.Save(env.StatePath); err != nil {
				return err
			}
			env.Log.Info("migrate: landed", "vm", s.VM, "from", from, "to", host)
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("migrate: VM %q still on %s after %s (target %s)", s.VM, host, timeout, dashEmpty(target))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(migratePollInterval):
		}
	}
}

// dashEmpty renders an optional value for logs.
func dashEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// removeStateCmd builds the state-removal command for a cold restart:
// the WAL (and .bak) always; the bpffs pins when RemovePins asks for a
// full host-reboot simulation. Paths come from agent_control so
// scenarios stay cluster-portable.
func (s RestartAgentStep) removeStateCmd(ac AgentControlConfig) (string, error) {
	if !s.RemoveWAL {
		return "", fmt.Errorf("RemovePins without RemoveWAL is not a modeled failure shape — pins cannot vanish while the WAL survives a running host")
	}
	if ac.WALPath == "" {
		return "", fmt.Errorf("RemoveWAL set but agent_control.wal_path is empty")
	}
	if err := shellSafe("agent_control.wal_path", ac.WALPath); err != nil {
		return "", err
	}
	cmd := fmt.Sprintf("sudo rm -f %s %s.bak", ac.WALPath, ac.WALPath)
	if s.RemovePins {
		if ac.PinPath == "" {
			return "", fmt.Errorf("RemovePins set but agent_control.pin_path is empty")
		}
		if err := shellSafe("agent_control.pin_path", ac.PinPath); err != nil {
			return "", err
		}
		cmd += fmt.Sprintf(" && sudo rm -rf %s", ac.PinPath)
	}
	return cmd, nil
}

// EpochStep asserts the counters-reset epoch's behaviour across the
// most recent [CaptureStep]: Changed false pins the warm-restart
// contract (the stored epoch carries forward — the gauge keeps naming
// the last TRUE state restart), Changed true pins the cold-boot one
// (an empty-WAL start stamps a fresh, later epoch, scrapable as soon
// as /metrics answers — the readiness gate inside [RestartAgentStep]
// already proved that timing before this step runs).
type EpochStep struct {
	// Node selects the agent, as in [RestartAgentStep]. Empty = the
	// sole agent.
	Node string
	// Changed is the expectation: true = a fresh epoch was stamped
	// (strictly later than the captured one), false = the captured
	// epoch carried through unchanged.
	Changed bool
	Note    string
}

func (EpochStep) Kind() string { return "assert-epoch" }

func (EpochStep) requiredMetrics() []string {
	return []string{MetricCountersReset}
}

func (s EpochStep) Run(ctx context.Context, env *StepEnv) error {
	agent, err := agentForNode(env.Config, s.Node)
	if err != nil {
		return fmt.Errorf("assert-epoch: %w", err)
	}
	base, ok := env.capturedEpochs[agent.Host]
	if !ok {
		return fmt.Errorf("assert-epoch: no captured epoch for %s — add a CaptureStep before the restart", agent.Host)
	}
	res, err := env.Metrics.Scrape(ctx, agent.MetricsURL)
	if err != nil {
		return fmt.Errorf("assert-epoch: scrape %s: %w", agent.MetricsURL, err)
	}
	cur := res.CountersResetEpoch
	pass := cur == base && cur != 0
	if s.Changed {
		pass = cur > base
	}
	env.addRow(AssertRow{
		Tenant:   agent.Host,
		Zone:     "epoch",
		Baseline: base, Current: cur, Delta: cur - base,
		Pass: pass, Note: s.Note,
	})
	return nil
}

// SleepStep pauses the script — the timing primitive for scenarios
// that must outwait an external cadence no metric signals (agent
// restart windows, scrape-interval boundaries).
type SleepStep struct {
	Duration time.Duration
}

func (SleepStep) Kind() string { return "sleep" }

func (s SleepStep) Run(ctx context.Context, env *StepEnv) error {
	env.Log.Info("sleep", "duration", s.Duration)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(s.Duration):
		return nil
	}
}

// RestartAgentStep restarts the telemetry agent on one compute host
// over SSH and waits for it to come back on /metrics with its taps
// re-attached — the prerequisite behind WAL-restart continuity,
// zombie-hunter verification, pressure-GC, and fault-injection
// scenarios. It restarts the agent; the billing-continuity assertions
// (monotone, no reset) are the scenario's own steps after it.
//
// With SetConfig the step derives a modified config from the one the
// node already runs before restarting, bringing the agent back under
// different tunables; the original is backed up to
// <config>.scenariotest.bak on the host. Restoring it is the scenario's
// concern (a later RestartAgentStep with RestoreConfig) — deliberately
// not automatic, since a step has no post-hook.
type RestartAgentStep struct {
	// Node selects the agent: a placement slot ("node:0") or a literal
	// agent host. Empty means the sole agent (errors if more than one).
	Node string
	// SetConfig overrides individual keys in the node's OWN agent config
	// before the restart — dotted YAML path to value, e.g.
	// {"gc.pressure_high_watermark": "0.0001"}. Values are decoded as
	// YAML scalars, so they land with their natural type (float, bool,
	// duration string). Everything not named is preserved, and the
	// original is backed up to <config_path>.scenariotest.bak, so a later
	// RestoreConfig undoes it.
	//
	// This is the cluster-portable way to run an agent under different
	// tunables: nothing has to be pre-staged, and the derived config
	// keeps the node's own broker list, WAL path and credentials.
	// Mutually exclusive with RestoreConfig.
	SetConfig map[string]string
	// RestoreConfig restores the config an earlier SetConfig backed up
	// (<config_path>.scenariotest.bak) before the restart — how a
	// scenario ends a modified-config phase and leaves the node as found.
	RestoreConfig bool
	// RemoveWAL deletes the agent's WAL and its .bak (agent_control.wal_path)
	// between stop and start — the WAL-destroyed cold boot of the
	// counters-reset-epoch design (docs/architecture/boot-and-recovery.md#counters-reset-epoch).
	// With pinned maps still in place the restart is the ADOPTED shape:
	// the kernel counters carry on and only the WAL-held state is lost.
	RemoveWAL bool
	// RemovePins additionally removes the agent's bpffs pin directory
	// (agent_control.pin_path) — combined with RemoveWAL this simulates
	// a host reboot: the true restart-from-zero shape.
	RemovePins bool
	// Timeout overrides [AgentControlConfig.ReadyTimeout] for the
	// post-restart readiness wait.
	Timeout time.Duration
}

func (RestartAgentStep) Kind() string { return "restart-agent" }

// requiredMetrics declares both families the readiness gate checks
// ([requiredMetrics]), so the pre-create step-metric gate refuses up
// front on an agent missing either — not just the one this step reads
// for the tap baseline.
func (RestartAgentStep) requiredMetrics() []string {
	return []string{MetricBytesTotal, MetricAttachedInterfaces}
}

func (s RestartAgentStep) Run(ctx context.Context, env *StepEnv) error {
	if env.AgentExec == nil {
		return fmt.Errorf("restart-agent: no agent-host SSH transport — set agent_control in the config")
	}
	ac := env.Config.AgentControl
	if ac.KeyPath == "" || ac.User == "" {
		return fmt.Errorf("restart-agent: agent_control.user and agent_control.key_path are required")
	}
	agent, err := agentForNode(env.Config, s.Node)
	if err != nil {
		return fmt.Errorf("restart-agent: %w", err)
	}
	unit := ac.Unit
	if unit == "" {
		unit = "lachesis-agent"
	}
	// The unit and any config paths are interpolated into an SSH command
	// line; reject shell-unsafe values (operator/scenario-controlled, but
	// a stray metacharacter would misexecute as root).
	if err := shellSafe("agent_control.unit", unit); err != nil {
		return fmt.Errorf("restart-agent: %w", err)
	}
	// Validate the config-source combination BEFORE touching the host: a
	// check that fired after the config swap would abort the scenario with
	// the node already modified and its restore step never reached.
	if len(s.SetConfig) > 0 && s.RestoreConfig {
		return fmt.Errorf("restart-agent: SetConfig and RestoreConfig are mutually exclusive")
	}
	if len(s.SetConfig) > 0 || s.RestoreConfig {
		if ac.ConfigPath == "" {
			return fmt.Errorf("restart-agent: config changes need agent_control.config_path")
		}
		if err := shellSafe("agent_control.config_path", ac.ConfigPath); err != nil {
			return fmt.Errorf("restart-agent: %w", err)
		}
	}

	// Baseline THIS agent's tap count so readiness can wait for the
	// re-attach (the boot zombie-hunt drops filters, then re-attaches).
	base, err := env.Metrics.Scrape(ctx, agent.MetricsURL)
	if err != nil {
		return fmt.Errorf("restart-agent: baseline scrape %s: %w", agent.MetricsURL, err)
	}

	host := agent.sshHost()
	// Restart evidence: the unit's MainPID before the restart. Readiness
	// then requires a DIFFERENT, running PID — proof the process actually
	// cycled, not that a level happens to match on the old one. Best
	// effort: if the agent is down (or the read fails) oldPID is empty
	// and any running new PID counts as evidence.
	oldPID, _ := agentMainPID(ctx, env, host, unit)

	if s.RestoreConfig {
		// Copy the backup an earlier SetConfig took back over the live
		// config. No backup-first here: the source IS the backup, so
		// backing up would clobber it (a self-destroying restore).
		restore := fmt.Sprintf("sudo cp -f %s.scenariotest.bak %s", ac.ConfigPath, ac.ConfigPath)
		if out, err := env.AgentExec.Run(ctx, host, restore); err != nil {
			return fmt.Errorf("restart-agent: restore config on %s: %w (output: %s)", host, err, out)
		}
		// The node no longer owes a restore, so the end-of-run sweep has
		// nothing to redo (lachesis#274).
		env.clearConfigDirty(s.Node)
		env.Log.Info("restart-agent: config restored", "host", host, "path", ac.ConfigPath)
	}

	if len(s.SetConfig) > 0 {
		// Combination and path already validated above, before any host
		// mutation could have happened.
		if err := applySetConfig(ctx, env.AgentExec, host, ac.ConfigPath, s.SetConfig, true); err != nil {
			return fmt.Errorf("restart-agent: %w", err)
		}
		// This step took the backup, so it owns the debt: if the run ends
		// before a restore step runs, the sweep uses it (lachesis#274).
		env.markConfigDirty(s.Node)
		env.Log.Info("restart-agent: config overrides applied",
			"host", host, "path", ac.ConfigPath, "keys", len(s.SetConfig))
	}

	cycle := "sudo systemctl restart " + unit
	if s.RemoveWAL || s.RemovePins {
		rm, err := s.removeStateCmd(ac)
		if err != nil {
			return fmt.Errorf("restart-agent: %w", err)
		}
		// Stop first so the final flush cannot re-create the WAL after
		// the removal; the gap is the cold boot under test.
		cycle = "sudo systemctl stop " + unit + " && " + rm + " && sudo systemctl start " + unit
	}
	if out, err := env.AgentExec.Run(ctx, host, cycle); err != nil {
		return fmt.Errorf("restart-agent: cycle %s on %s: %w (output: %s)", unit, host, err, out)
	}
	env.Log.Info("restart-agent: restart issued", "host", host, "unit", unit,
		"old_pid", oldPID, "remove_wal", s.RemoveWAL, "remove_pins", s.RemovePins)

	return s.awaitReady(ctx, env, agent, host, unit, oldPID, base.AttachedInterfaces)
}

// ResolvedGrewStep asserts the UnresolvedBuffer late-binding counter
// (lachesis_unresolved_resolved_total) rose by at least Min since the
// most recent [CaptureStep] — the proof that a flow's bytes were parked
// unknown and then re-attributed to the right tenant WITHIN the TTL (not
// expired to unknown). Polls until the floor is met or Timeout (default
// [DefaultSweepTimeout]) records a failing row, because resolution lands
// a reconcile-plus-scrape after the MAC becomes known.
type ResolvedGrewStep struct {
	Min     int64
	Timeout time.Duration
	Note    string
}

func (ResolvedGrewStep) Kind() string { return "assert-resolved-grew" }

func (ResolvedGrewStep) requiredMetrics() []string { return []string{MetricUnresolvedResolved} }

func (s ResolvedGrewStep) Run(ctx context.Context, env *StepEnv) error {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultSweepTimeout
	}
	deadline := time.Now().Add(timeout)
	var delta float64
	for {
		snap, err := env.scrape(ctx)
		if err != nil {
			return err
		}
		delta = snap.UnresolvedResolved - env.resolvedBase
		if delta >= float64(s.Min) || time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(sweepPollInterval):
		}
	}
	env.addRow(AssertRow{
		Tenant: "unresolved-resolved", Zone: "-", Direction: "-",
		Baseline: env.resolvedBase, Current: env.resolvedBase + delta, Delta: delta,
		MinBytes: s.Min, Pass: delta >= float64(s.Min), Note: s.Note,
	})
	return nil
}

// EvictionsGrewStep asserts the pressure-relief eviction counter
// (lachesis_gc_evictions_total{reason="pressure_relief"}) rose by at
// least Min since the most recent [CaptureStep] — the proof that the
// telemetry_map fill crossed the high watermark and the GC evicted the
// oldest flows, rather than the map quietly staying under the trigger
// (docs/architecture/data-structures.md#kernel-side-bpf-maps).
//
// It reads the pressure_relief reason ALONE, never the whole family: the
// same family carries the ghost sweep's ttl and ghost_residual_flow
// reasons, and conflating them would let an unrelated ghost expiry pass
// as pressure relief.
//
// The step only shows that eviction happened. Its value comes from
// pairing with the byte assertions around it: bytes evicted from the
// kernel map must already have been flushed into GlobalState, so the
// tenant's exposed total keeps growing across the eviction ("flush
// before evict"). Polls until the floor is met or Timeout (default
// [DefaultSweepTimeout]), because relief runs on the scrape tick.
type EvictionsGrewStep struct {
	Min     int64
	Timeout time.Duration
	Note    string
}

func (EvictionsGrewStep) Kind() string { return "assert-evictions-grew" }

func (EvictionsGrewStep) requiredMetrics() []string { return []string{MetricGCEvictions} }

func (s EvictionsGrewStep) Run(ctx context.Context, env *StepEnv) error {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultSweepTimeout
	}
	deadline := time.Now().Add(timeout)
	var delta float64
	for {
		snap, err := env.scrape(ctx)
		if err != nil {
			return err
		}
		delta = snap.PressureReliefEvictions - env.evictionsBase
		if delta >= float64(s.Min) || time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(sweepPollInterval):
		}
	}
	env.addRow(AssertRow{
		Tenant: "gc-pressure-relief", Zone: "-", Direction: "-",
		Baseline: env.evictionsBase, Current: env.evictionsBase + delta, Delta: delta,
		MinBytes: s.Min, Pass: delta >= float64(s.Min), Note: s.Note,
	})
	return nil
}

// ReloadAgentStep installs an alternate config on an agent host and
// sends SIGHUP — a HOT reload, not a restart: the process does not
// cycle, so in-memory state (crucially the UnresolvedBuffer) survives.
// It is how the unresolved-latebind scenario "resumes the metadata
// feed" — swap in a config with a short reconcile interval and SIGHUP,
// and the running agent's next periodic reconcile learns the newly
// booted VM and late-binds its buffered bytes. Only hot-reloadable
// fields take effect (docs/operations/runtime.md); a restart would
// discard the buffer this scenario depends on.
//
// PRECONDITION when SetConfig is set: unlike [RestartAgentStep], this
// deliberately does NOT back up the current config (a reload chains
// after a restart's config change, and a second backup would clobber
// that restart's original-config backup). So it is only safe after a
// RestartAgentStep has already backed up the real config, and the
// scenario must restore it explicitly (its final RestartAgentStep with
// RestoreConfig). Used standalone, it would modify the config with no
// way back.
type ReloadAgentStep struct {
	// Node selects the agent (a placement slot or literal host); empty
	// means the sole agent.
	Node string
	// SetConfig overrides individual keys in the config the node is
	// currently running, before the SIGHUP — dotted YAML path to value,
	// like [RestartAgentStep.SetConfig]. Because it patches the CURRENT
	// config, overrides an earlier restart applied stay in force and this
	// step only names what changes.
	//
	// NO backup is taken (see the PRECONDITION on the type): the earlier
	// restart's backup is the scenario's way home.
	SetConfig map[string]string
}

func (ReloadAgentStep) Kind() string { return "reload-agent" }

func (s ReloadAgentStep) Run(ctx context.Context, env *StepEnv) error {
	if env.AgentExec == nil {
		return fmt.Errorf("reload-agent: no agent-host SSH transport — set agent_control in the config")
	}
	ac := env.Config.AgentControl
	if ac.KeyPath == "" || ac.User == "" {
		return fmt.Errorf("reload-agent: agent_control.user and agent_control.key_path are required")
	}
	agent, err := agentForNode(env.Config, s.Node)
	if err != nil {
		return fmt.Errorf("reload-agent: %w", err)
	}
	unit := ac.Unit
	if unit == "" {
		unit = "lachesis-agent"
	}
	if err := shellSafe("agent_control.unit", unit); err != nil {
		return fmt.Errorf("reload-agent: %w", err)
	}
	// Validate before mutating the host — see the same note on
	// [RestartAgentStep.Run].
	if len(s.SetConfig) > 0 {
		if ac.ConfigPath == "" {
			return fmt.Errorf("reload-agent: SetConfig set but agent_control.config_path is empty")
		}
		if err := shellSafe("agent_control.config_path", ac.ConfigPath); err != nil {
			return fmt.Errorf("reload-agent: %w", err)
		}
	}
	host := agent.sshHost()
	if len(s.SetConfig) > 0 {
		// backup=false, per the PRECONDITION on the type: the earlier
		// restart's backup holds the real config and must survive.
		if err := applySetConfig(ctx, env.AgentExec, host, ac.ConfigPath, s.SetConfig, false); err != nil {
			return fmt.Errorf("reload-agent: %w", err)
		}
		// Idempotent with the restart that took the backup (the documented
		// precondition), so the normal chained case records one debt, not
		// two. Used standalone — where no backup exists — this turns a
		// silently-modified host into a loud end-of-run failure instead
		// (lachesis#274).
		env.markConfigDirty(s.Node)
		env.Log.Info("reload-agent: config overrides applied",
			"host", host, "path", ac.ConfigPath, "keys", len(s.SetConfig))
	}

	// SIGHUP the unit's main process (no ExecReload on the unit — send the
	// signal directly). The agent re-reads its YAML and applies the
	// hot-reloadable fields; the process keeps running.
	if out, err := env.AgentExec.Run(ctx, host, "sudo systemctl kill -s HUP "+unit); err != nil {
		return fmt.Errorf("reload-agent: SIGHUP %s on %s: %w (output: %s)", unit, host, err, out)
	}
	env.Log.Info("reload-agent: SIGHUP sent", "host", host, "unit", unit)
	return nil
}

// awaitReady blocks until the restart is confirmed AND the agent is
// serving again: the unit reports a running MainPID different from
// oldPID (the process cycled), and /metrics answers with the required
// families and a tap count back at the pre-restart baseline (re-attach
// complete). Fires an error on timeout.
func (s RestartAgentStep) awaitReady(ctx context.Context, env *StepEnv, agent AgentConfig, host, unit, oldPID string, baseTaps float64) error {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = env.Config.AgentControl.ReadyTimeout
	}
	if timeout <= 0 {
		timeout = DefaultAgentReadyTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	restarted := false
	for {
		// First confirm the process cycled: a running MainPID (not 0/empty)
		// that differs from the pre-restart one.
		if !restarted {
			pid, err := agentMainPID(ctx, env, host, unit)
			if err == nil && pid != "" && pid != "0" && pid != oldPID {
				restarted = true
				env.Log.Info("restart-agent: process cycled", "host", host, "old_pid", oldPID, "new_pid", pid)
			}
		}
		if restarted {
			res, err := env.Metrics.Scrape(ctx, agent.MetricsURL)
			if err == nil && requiredMetrics(res) == nil && res.AttachedInterfaces >= baseTaps {
				env.Log.Info("restart-agent: ready", "host", host,
					"attached", res.AttachedInterfaces, "baseline", baseTaps)
				return nil
			}
		}
		select {
		case <-ctx.Done():
			if !restarted {
				return fmt.Errorf("restart-agent: %s MainPID never changed from %q within %s — restart not confirmed: %w", unit, oldPID, timeout, ctx.Err())
			}
			return fmt.Errorf("restart-agent: %s not ready within %s: %w", agent.MetricsURL, timeout, ctx.Err())
		case <-time.After(agentReadyPollInterval):
		}
	}
}

// agentMainPID reads the systemd MainPID of unit on host — the restart
// evidence [RestartAgentStep] gates on. Returns the bare PID string
// ("0" when the unit is stopped).
func agentMainPID(ctx context.Context, env *StepEnv, host, unit string) (string, error) {
	out, err := env.AgentExec.Run(ctx, host, "systemctl show -p MainPID "+unit)
	if err != nil {
		return "", err
	}
	// Output is "MainPID=<n>" (possibly with surrounding whitespace).
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(out), "MainPID=")), nil
}

// shellSafe rejects a value with characters outside a conservative set
// (alphanumerics and common path/unit punctuation), so config- and
// scenario-supplied tokens interpolated into an SSH command line cannot
// inject shell syntax. Real unit names and file paths use only these.
func shellSafe(field, v string) error {
	if v == "" || !shellSafeToken.MatchString(v) {
		return fmt.Errorf("%s %q contains characters unsafe for a shell command", field, v)
	}
	return nil
}

// awaitSSHReady polls a trivial command until the VM answers SSH — the
// step-side twin of drive's waitReady (lachesis#253): Nova ACTIVE races
// cloud-init by tens of seconds, so any step that execs in the guest
// right after `up` (ConfigureNICStep, AddRouteStep) must gate on
// readiness or fail spuriously with "Connection refused" on clusters
// where realize outpaces the boot. Same timeout + poll cadence as
// drive's gate.
func awaitSSHReady(ctx context.Context, env *StepEnv, vmID, addr string) error {
	ctx, cancel := context.WithTimeout(ctx, defaultReadyTimeout)
	defer cancel()
	env.Log.Info("waiting for ssh-ready", "vm", vmID, "addr", addr, "timeout", defaultReadyTimeout)
	for {
		if _, err := env.Exec.Run(ctx, addr, "true"); err == nil {
			env.Log.Info("vm ssh-ready", "vm", vmID, "addr", addr)
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("vm %s (%s) not ssh-ready before deadline: %w", vmID, addr, ctx.Err())
		case <-time.After(readyPollInterval):
		}
	}
}

// PortSeriesStep asserts the per-port leaf family attributes traffic to
// the RIGHT port: the lachesis_port_bytes_total series carrying Port's
// live Neutron id must sum to at least MinBytes across all agents. This
// is the port-identity check the coarser tiers cannot express — e.g.
// after a same-MAC port rebirth, traffic mislabeled under the dead
// port's port_id leaves the new id's series empty (stale-attribution
// reconcile miss). Data-dependent family, so no metric preflight — a
// missing family simply fails the row with sum 0.
type PortSeriesStep struct {
	VM       string // DSL VM the port belongs to (for the report row)
	Port     string // the [AttachPortStep.ID] run-state handle
	MinBytes float64
	// Timeout bounds the stabilize poll (default
	// [DefaultPortSeriesTimeout]): a drive returns when the traffic is
	// SENT, but the bytes surface only at the agent's next kernel drain
	// (the scrape interval), so a single immediate scrape races the
	// tick. Poll until the sum reaches MinBytes; a timeout is the
	// failing row (traffic never attributed to this port).
	Timeout time.Duration
	Note    string
}

func (PortSeriesStep) Kind() string { return "assert-port-series" }

func (s PortSeriesStep) Run(ctx context.Context, env *StepEnv) error {
	portID := liveID(env.State.Ports, s.Port)
	if portID == "" {
		return fmt.Errorf("assert-port-series: run-state has no live port for %q", s.Port)
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultPortSeriesTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var sum float64
	for {
		snap, err := env.scrape(ctx)
		if err != nil {
			return err
		}
		sum = 0
		for _, p := range snap.PortBytes {
			if p.PortID == portID {
				sum += p.Value
			}
		}
		if sum >= s.MinBytes {
			break
		}
		select {
		case <-ctx.Done():
			env.Log.Warn("assert-port-series: timeout — traffic never attributed to the port",
				"port", s.Port, "id", portID, "sum", sum, "min", s.MinBytes)
			env.addRow(AssertRow{
				Tenant: s.VM, VM: s.VM, Zone: "-", Direction: "-",
				Baseline: s.MinBytes, Current: sum, Delta: sum - s.MinBytes,
				Pass: false, Note: s.Note,
			})
			return nil
		case <-time.After(sweepPollInterval):
		}
	}
	env.addRow(AssertRow{
		Tenant: s.VM, VM: s.VM, Zone: "-", Direction: "-",
		Baseline: s.MinBytes, Current: sum, Delta: sum - s.MinBytes,
		Pass: true, Note: s.Note,
	})
	return nil
}

// AwaitPortBindingStep polls every agent's /debug/lookup until the MAC
// of Port (its run-state ref) is bound to Port's CURRENT Neutron id —
// the reconcile has processed a same-MAC port rebirth. On a healthy
// agent this resolves within one reconcile interval; an agent whose
// change detection misses the port_id change never rebinds, so the
// timeout is recorded as a FAILING ROW (the defect itself), not a
// mechanical error. Timeout defaults to [DefaultSweepTimeout].
type AwaitPortBindingStep struct {
	VM      string
	Port    string // the [AttachPortStep.ID] whose live id must be bound
	Timeout time.Duration
	Note    string
}

func (AwaitPortBindingStep) Kind() string { return "await-port-binding" }

func (s AwaitPortBindingStep) Run(ctx context.Context, env *StepEnv) error {
	var ref ResourceRef
	for _, p := range env.State.Ports {
		if p.DSLID == s.Port {
			ref = p
		}
	}
	if ref.ID == "" || ref.MAC == "" {
		return fmt.Errorf("await-port-binding: run-state has no port/MAC for %q", s.Port)
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultSweepTimeout
	}
	env.Log.Info("await-port-binding: waiting for MAC to rebind", "port", s.Port, "id", ref.ID, "mac", ref.MAC, "timeout", timeout)
	deadline := time.Now().Add(timeout)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	var last string
	for {
		bound := true
		for _, u := range agentURLs(env.Config) {
			res, err := env.Metrics.LookupMAC(ctx, u, ref.MAC)
			if err != nil || !res.Found || res.PortID != ref.ID {
				bound = false
				if err == nil {
					last = res.PortID
				}
			}
		}
		if bound {
			env.Log.Info("await-port-binding: rebound", "port", s.Port, "id", ref.ID)
			env.addRow(AssertRow{
				Tenant: s.VM, VM: s.VM, Zone: "-", Direction: "-",
				Baseline: 1, Current: 1, Delta: 0, Pass: true, Note: s.Note,
			})
			return nil
		}
		select {
		case <-ctx.Done():
			// The defect, as a row: the agents still bind the MAC to a
			// stale (dead) port id — the port tier is mislabeling.
			env.Log.Warn("await-port-binding: timeout — MAC still bound to a stale port",
				"port", s.Port, "want", ref.ID, "stale", last)
			env.addRow(AssertRow{
				Tenant: s.VM, VM: s.VM, Zone: "-", Direction: "-",
				Baseline: 1, Current: 0, Delta: -1, Pass: false, Note: s.Note,
			})
			return nil
		case <-time.After(sweepPollInterval):
		}
	}
}

// AttachPortStep hot-plugs a second NIC onto a live VM: it creates a
// fresh port on a DSL network (the NIC is deliberately NOT a DSL VM —
// the DSL models one port per VM, and the whole point of a hot-plugged
// NIC is that it shares the VM's server_id) and attaches it via Nova
// os-interface. The port is recorded in the run-state under ID (with
// its MAC, so the MAC-learn gate covers it) and gated on the same
// attached-interfaces rise as a boot. Pair with [ConfigureNICStep] —
// the guest does not configure a hot-plugged NIC by itself.
type AttachPortStep struct {
	VM string // DSL VM to plug into
	// ID names the NIC's run-state ref (e.g. "vm-a-nic2") — the handle
	// a later [DetachPortStep]/[ReattachPortStep] targets.
	ID      string
	Network string // DSL network the port lands on
	Subnet  string // DSL subnet for the fixed IP
	IP      string // fixed IP (must be free in the subnet)
	// MACFrom, when set, pins the new port to the MAC recorded for a
	// previously deleted VM/NIC ([DeleteVMStep]/[DetachPortStep] record
	// it) — the MAC-reuse shapes: same MAC, new port identity.
	MACFrom string
	// PortSecurityOff creates the NIC's port with anti-spoofing off (and
	// no security group — Neutron couples the two), so the guest can
	// source frames from a forged MAC ([SetNICMACStep]).
	PortSecurityOff bool
	// AllowedPairs declares allowed_address_pairs on the NIC's port —
	// the VRRP-style grants that admit specific (IP, MAC) sources with
	// port security still on.
	AllowedPairs []AddressPair
}

func (AttachPortStep) Kind() string { return "attach-port" }

func (s AttachPortStep) Run(ctx context.Context, env *StepEnv) error {
	snap := env.Scenario.Builder.Build()
	project := ""
	for _, p := range snap.Ports {
		if p.ID == s.VM {
			project = p.ProjectID
			break
		}
	}
	if project == "" {
		return fmt.Errorf("scenario declares no VM %q", s.VM)
	}
	proj, err := env.project(project)
	if err != nil {
		return err
	}
	serverID, ok := serverIDFor(env.State, s.VM)
	if !ok {
		return fmt.Errorf("run-state has no server for VM %q", s.VM)
	}
	netID := liveID(env.State.Networks, s.Network)
	subnetID := liveID(env.State.Subnets, s.Subnet)
	if netID == "" || subnetID == "" {
		return fmt.Errorf("run-state has no live ids for %s/%s", s.Network, s.Subnet)
	}
	secGroupID, err := env.Cloud.FindSecGroup(ctx, env.Config.Prerequisites.SecGroupName)
	if err != nil {
		return err
	}

	baseline, err := env.scrape(ctx)
	if err != nil {
		return fmt.Errorf("attach baseline scrape: %w", err)
	}

	pinnedMAC := ""
	if s.MACFrom != "" {
		pinnedMAC = env.macs[s.MACFrom]
		if pinnedMAC == "" {
			return fmt.Errorf("attach-port: no MAC recorded for %q (delete or detach it first)", s.MACFrom)
		}
	}
	name := Mangle(env.Config.Naming.Prefix, env.State.RunID, s.ID)
	portID, err := env.Cloud.CreatePort(ctx, proj.ID, PortSpec{
		Name:            name,
		NetworkID:       netID,
		SubnetID:        subnetID,
		FixedIP:         s.IP,
		MACAddress:      pinnedMAC,
		SecGroupID:      secGroupID,
		PortSecurityOff: s.PortSecurityOff,
		AllowedPairs:    s.AllowedPairs,
	})
	if err != nil {
		return err
	}
	mac, err := env.Cloud.PortMAC(ctx, portID)
	if err != nil {
		return err
	}
	env.State.Ports = append(env.State.Ports, ResourceRef{DSLID: s.ID, ID: portID, Name: name, ProjectID: proj.ID, MAC: mac})
	if err := env.State.Save(env.StatePath); err != nil {
		return err
	}
	if err := env.Cloud.AttachInterface(ctx, proj.ID, serverID, portID); err != nil {
		return err
	}
	env.Log.Info("attach-port: plugged", "vm", s.VM, "nic", s.ID, "port", portID, "mac", mac, "ip", s.IP)
	return awaitAttachRise(ctx, env, baseline, "attach-port")
}

// ReattachPortStep plugs a previously-detached NIC (its port kept
// alive by [DetachPortStep] with Delete false) back into its VM — the
// same Neutron port, same MAC, new tap. Gated like any attach.
type ReattachPortStep struct {
	VM   string
	Port string // the [AttachPortStep.ID] of the detached NIC
}

func (ReattachPortStep) Kind() string { return "reattach-port" }

func (s ReattachPortStep) Run(ctx context.Context, env *StepEnv) error {
	var ref ResourceRef
	for _, p := range env.State.Ports {
		if p.DSLID == s.Port {
			ref = p
			break
		}
	}
	if ref.ID == "" {
		return fmt.Errorf("run-state has no port %q", s.Port)
	}
	serverID, ok := serverIDFor(env.State, s.VM)
	if !ok {
		return fmt.Errorf("run-state has no server for VM %q", s.VM)
	}
	baseline, err := env.scrape(ctx)
	if err != nil {
		return fmt.Errorf("attach baseline scrape: %w", err)
	}
	if err := env.Cloud.AttachInterface(ctx, ref.ProjectID, serverID, ref.ID); err != nil {
		return err
	}
	env.Log.Info("reattach-port: plugged", "vm", s.VM, "nic", s.Port, "port", ref.ID, "mac", ref.MAC)
	return awaitAttachRise(ctx, env, baseline, "reattach-port")
}

// DetachPortStep unplugs a hot-plugged NIC (Nova os-interface detach)
// and re-baselines the run-state's attach record — the tap
// legitimately disappears, and the source agent racing its dying tap
// may increment the failure counter (benign, same race as a live
// migration's). With Delete set the port is then deleted outright:
// the MAC leaves Neutron, the agent's ghost lifecycle takes over, and
// the ref leaves the run-state (truthful-inventory rule, as
// [DeleteVMStep]). Without Delete the port survives unbound for a
// later [ReattachPortStep] — but reattach it before the next
// DriveStep: after the ghost sweep its MAC is gone from the agents'
// maps and the MAC-learn gate would wait on it forever.
type DetachPortStep struct {
	VM     string
	Port   string // the [AttachPortStep.ID] of the NIC
	Delete bool
}

func (DetachPortStep) Kind() string { return "detach-port" }

func (s DetachPortStep) Run(ctx context.Context, env *StepEnv) error {
	var ref ResourceRef
	for _, p := range env.State.Ports {
		if p.DSLID == s.Port {
			ref = p
			break
		}
	}
	if ref.ID == "" {
		return fmt.Errorf("run-state has no port %q", s.Port)
	}
	// Record the MAC so a following [AwaitSweepStep]{ForMACOf: s.Port} can
	// wait for THIS NIC's ghost fold — even after Delete drops the ref.
	if env.macs == nil {
		env.macs = map[string]string{}
	}
	env.macs[s.Port] = ref.MAC
	serverID, ok := serverIDFor(env.State, s.VM)
	if !ok {
		return fmt.Errorf("run-state has no server for VM %q", s.VM)
	}
	baseline, err := env.scrape(ctx)
	if err != nil {
		return fmt.Errorf("detach baseline scrape: %w", err)
	}
	if err := env.Cloud.DetachInterface(ctx, ref.ProjectID, serverID, ref.ID); err != nil {
		return err
	}

	// Wait for the tap to actually drop, then re-baseline: the next
	// drive's recheck must expect one tap fewer and must not read the
	// dying-tap failure blip as taps lost since up.
	waitCtx, cancel := context.WithTimeout(ctx, DefaultAttachTimeout)
	defer cancel()
	for {
		snap, err := env.scrape(waitCtx)
		if err != nil {
			return fmt.Errorf("detach gate scrape: %w", err)
		}
		if snap.AttachedInterfaces <= baseline.AttachedInterfaces-1 {
			env.State.Attach = AttachRecord{Target: snap.AttachedInterfaces, Failures: snap.AttachFailures}
			if err := env.State.Save(env.StatePath); err != nil {
				return err
			}
			env.Log.Info("detach-port: unplugged", "vm", s.VM, "nic", s.Port, "attached", snap.AttachedInterfaces)
			break
		}
		select {
		case <-waitCtx.Done():
			return fmt.Errorf("detach gate: attached_interfaces still %.0f (want ≤ %.0f): %w",
				snap.AttachedInterfaces, baseline.AttachedInterfaces-1, waitCtx.Err())
		case <-time.After(attachPollInterval):
		}
	}

	if !s.Delete {
		return nil
	}
	if err := env.Cloud.DeletePort(ctx, ref.ProjectID, ref.ID); err != nil {
		return err
	}
	kept := make([]ResourceRef, 0, len(env.State.Ports))
	for _, p := range env.State.Ports {
		if p.DSLID != s.Port {
			kept = append(kept, p)
		}
	}
	env.State.Ports = kept
	if err := env.State.Save(env.StatePath); err != nil {
		return err
	}
	env.Log.Info("detach-port: port deleted", "nic", s.Port, "mac", ref.MAC)
	return nil
}

// ConfigureNICStep brings a hot-plugged NIC up inside the guest — the
// platform attaches the port, but nothing configures the interface in
// a cirros image. Same absolute-path + busybox-fallback spelling as
// [AddRouteStep], over the VM's provider SSH FIP.
type ConfigureNICStep struct {
	VM   string
	Dev  string // guest device, e.g. "eth1"
	CIDR string // address to assign, e.g. "10.0.22.9/24"
}

func (ConfigureNICStep) Kind() string { return "configure-nic" }

func (s ConfigureNICStep) Run(ctx context.Context, env *StepEnv) error {
	fip := ""
	for _, f := range env.State.FIPs {
		if f.VMID == s.VM && f.Network == "" { // the provider SSH FIP
			fip = f.Address
		}
	}
	if fip == "" {
		return fmt.Errorf("run-state has no SSH FIP for VM %q", s.VM)
	}
	// Dev is interpolated unquoted into the SSH command; reject a
	// stray metacharacter. CIDR needs no such guard — net.ParseCIDR
	// below rejects anything that isn't digits/dots/slash.
	if err := shellSafe("configure-nic.dev", s.Dev); err != nil {
		return err
	}
	if err := awaitSSHReady(ctx, env, s.VM, fip); err != nil {
		return fmt.Errorf("configure-nic: %w", err)
	}
	ip, ipnet, err := net.ParseCIDR(s.CIDR)
	if err != nil {
		return fmt.Errorf("configure-nic %s: %w", s.CIDR, err)
	}
	mask := net.IP(ipnet.Mask).String()
	cmd := fmt.Sprintf(
		"sudo /sbin/ip addr add %s dev %s 2>/dev/null || sudo ifconfig %s %s netmask %s; sudo /sbin/ip link set %s up 2>/dev/null || sudo ifconfig %s up",
		s.CIDR, s.Dev, s.Dev, ip, mask, s.Dev, s.Dev)
	if out, err := env.Exec.Run(ctx, fip, cmd); err != nil {
		return fmt.Errorf("configure-nic %s on %s: %w (output: %s)", s.Dev, s.VM, err, out)
	}
	env.Log.Info("configure-nic", "vm", s.VM, "dev", s.Dev, "cidr", s.CIDR)
	return nil
}

// SetNICMACStep rewrites a guest interface's MAC address — the forge
// behind the spoofed-MAC and VRRP-vMAC scenarios. Runs over the VM's
// provider SSH FIP (so never against the interface the session rides),
// with the same absolute-path + busybox-fallback spelling as
// [ConfigureNICStep]. The Neutron port's MAC is untouched: only the
// wire frames change, which is exactly the point — the agent's maps
// still know the REAL port MAC, so the forged source must land
// unresolved.
type SetNICMACStep struct {
	VM  string
	Dev string // guest device, e.g. "eth1"
	MAC string // the forged source MAC, e.g. "02:de:ad:be:ef:01"
}

func (SetNICMACStep) Kind() string { return "set-nic-mac" }

func (s SetNICMACStep) Run(ctx context.Context, env *StepEnv) error {
	fip := ""
	for _, f := range env.State.FIPs {
		if f.VMID == s.VM && f.Network == "" { // the provider SSH FIP
			fip = f.Address
		}
	}
	if fip == "" {
		return fmt.Errorf("set-nic-mac: run-state has no SSH FIP for VM %q", s.VM)
	}
	if err := shellSafe("set-nic-mac.dev", s.Dev); err != nil {
		return err
	}
	if err := shellSafe("set-nic-mac.mac", s.MAC); err != nil {
		return err
	}
	if err := awaitSSHReady(ctx, env, s.VM, fip); err != nil {
		return fmt.Errorf("set-nic-mac: %w", err)
	}
	cmd := fmt.Sprintf(
		"sudo /sbin/ip link set %s down 2>/dev/null || sudo ifconfig %s down; "+
			"sudo /sbin/ip link set %s address %s 2>/dev/null || sudo ifconfig %s hw ether %s; "+
			"sudo /sbin/ip link set %s up 2>/dev/null || sudo ifconfig %s up",
		s.Dev, s.Dev, s.Dev, s.MAC, s.Dev, s.MAC, s.Dev, s.Dev)
	if out, err := env.Exec.Run(ctx, fip, cmd); err != nil {
		return fmt.Errorf("set-nic-mac %s=%s on %s: %w (output: %s)", s.Dev, s.MAC, s.VM, err, out)
	}
	env.Log.Info("set-nic-mac", "vm", s.VM, "dev", s.Dev, "mac", s.MAC)
	return nil
}

// zoneGrowthSettle is how long a pure upper-bound [ZoneGrowthStep]
// (MinBytes 0) waits for the drive to drain before its single read —
// bytes surface a kernel drain (scrape interval) after traffic, so a
// too-early read could let a late-arriving mis-attribution slip under
// the ceiling. A var, not a const, so tests shrink it to zero.
var zoneGrowthSettle = 15 * time.Second

// ZoneGrowthStep asserts one (tenant, zone, DIRECTION) tuple's growth
// since the most recent [CaptureStep] sits inside [MinBytes, MaxBytes].
// It refines [MaxGrowthStep] two ways the forged-MAC scenarios need:
// a single direction (a forged sender pollutes tx while the peer's
// legitimate replies own the same zone's other tuples), and a LOWER
// bound with stabilize polling — bytes surface only at the agents'
// next kernel drain, so with MinBytes set the step polls until the
// floor is met or Timeout (default [DefaultPortSeriesTimeout]) records
// the failing row. MaxBytes 0 means unbounded above.
//
// A pure upper-bound check (MinBytes 0) has no floor to poll toward, so
// it waits [zoneGrowthSettle] for the drive to drain before its single
// read — otherwise it would depend on a preceding MinBytes step having
// polled long enough to drain the traffic first.
type ZoneGrowthStep struct {
	Tenant    string // DSL project name, or a literal label like "unknown"
	Zone      string
	Direction string // "tx" or "rx"
	MinBytes  int64
	MaxBytes  int64
	Timeout   time.Duration
	Note      string
}

func (ZoneGrowthStep) Kind() string { return "assert-zone-growth" }

func (s ZoneGrowthStep) Run(ctx context.Context, env *StepEnv) error {
	label := env.tenantLabel(s.Tenant)
	k := tuple{label, s.Zone, s.Direction}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultPortSeriesTimeout
	}
	// Pure upper bound: no floor to poll toward, so settle first so the
	// drive has drained before the single read (see [zoneGrowthSettle]).
	if s.MinBytes == 0 && zoneGrowthSettle > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(zoneGrowthSettle):
		}
	}
	deadline := time.Now().Add(timeout)
	var delta float64
	for {
		snap, err := env.scrape(ctx)
		if err != nil {
			return err
		}
		delta = sumByTuple(snap.Bytes)[k] - env.captured[k]
		if delta >= float64(s.MinBytes) || time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(sweepPollInterval):
		}
	}
	pass := delta >= float64(s.MinBytes) && (s.MaxBytes <= 0 || delta <= float64(s.MaxBytes))
	env.addRow(AssertRow{
		Tenant: s.Tenant, TenantID: label,
		Zone: s.Zone, Direction: s.Direction,
		Baseline: env.captured[k], Current: env.captured[k] + delta, Delta: delta,
		MinBytes: s.MinBytes,
		Pass:     pass, Note: s.Note,
	})
	return nil
}

// ServerMonotoneStep asserts every captured per-server tuple of VM is
// still at or above its captured value — [MonotoneStep]'s counterpart
// on the mortal lachesis_server_bytes_total family, and the live form
// of the mortal-series monotonicity invariant (lachesis#226/#227): a
// fold must never make a server's series observable below an earlier
// observation. One row per tuple.
type ServerMonotoneStep struct {
	VM   string
	Note string
}

func (ServerMonotoneStep) Kind() string { return "assert-server-monotone" }

// requiredMetrics deliberately returns nil: the mortal per-server family
// (lachesis_server_bytes_total) is data-dependent — a fresh, quiet agent
// exposes it only once a server flow has bytes, which THIS scenario's own
// DriveStep produces before the assertion runs. A preflight gate on it
// can't tell "agent too old" from "no traffic yet" and falsely blocks the
// run on a freshly-started agent (observed live on c36). If the family is
// genuinely never produced, [ServerMonotoneStep.Run] fails with a clear
// "no captured server tuples" error instead.
func (ServerMonotoneStep) requiredMetrics() []string { return nil }

func (s ServerMonotoneStep) Run(ctx context.Context, env *StepEnv) error {
	serverID, ok := serverIDFor(env.State, s.VM)
	if !ok {
		return fmt.Errorf("run-state has no server for VM %q", s.VM)
	}
	snap, err := env.scrape(ctx)
	if err != nil {
		return err
	}
	cur := sumByServerTuple(snap.Servers)
	rows := 0
	for k, base := range env.capturedServers {
		if k.server != serverID {
			continue
		}
		rows++
		env.addRow(AssertRow{
			Tenant: s.VM, VM: s.VM, ServerID: serverID,
			Zone: k.zone, ExternalNetwork: k.ext, Direction: k.direction,
			Baseline: base, Current: cur[k], Delta: cur[k] - base,
			Pass: cur[k] >= base, Note: s.Note,
		})
	}
	if rows == 0 {
		return fmt.Errorf("assert-server-monotone: no captured server tuples for VM %q — capture after its traffic was driven", s.VM)
	}
	return nil
}

var shellSafeToken = regexp.MustCompile(`^[A-Za-z0-9@%.:_/+-]+$`)

// agentForNode resolves a RestartAgentStep's Node to its AgentConfig: a
// placement slot or literal host, or the sole agent when Node is empty.
func agentForNode(cfg Config, node string) (AgentConfig, error) {
	if node == "" {
		if len(cfg.Cluster.Agents) != 1 {
			return AgentConfig{}, fmt.Errorf("node is required when the cluster has %d agents", len(cfg.Cluster.Agents))
		}
		return cfg.Cluster.Agents[0], nil
	}
	host, err := resolveNode(node, cfg.Cluster.Agents)
	if err != nil {
		return AgentConfig{}, err
	}
	for _, a := range cfg.Cluster.Agents {
		if a.Host == host {
			return a, nil
		}
	}
	// resolveNode only returns a configured host, so this is a safety
	// net, not a reachable path.
	return AgentConfig{}, fmt.Errorf("resolved host %q has no agent entry", host)
}

// MaxSettledStep asserts the ghost-fold counter (settled_flows) grew by
// at most Budget rows since the most recent [CaptureStep]. CAUTION: a
// fold only registers after the 60s ghost grace + a sweep tick, so this
// is meaningful ONLY when the check runs after that window has elapsed
// (e.g. following an [AwaitSweepStep]). For "did this operation mark a
// ghost at all" — where you want an immediate answer within seconds —
// use [MaxGhostsStep], which reads the mark-time gauge and is not blinded
// by the grace (lachesis#243).
type MaxSettledStep struct {
	Budget int64
	Note   string
}

func (MaxSettledStep) Kind() string { return "assert-max-settled" }

func (MaxSettledStep) requiredMetrics() []string { return []string{MetricSettledFlows} }

func (s MaxSettledStep) Run(ctx context.Context, env *StepEnv) error {
	snap, err := env.scrape(ctx)
	if err != nil {
		return err
	}
	delta := snap.SettledFlows - env.settledBase
	env.addRow(AssertRow{
		Tenant: "settled-flows", Zone: "-", Direction: "-",
		Baseline: env.settledBase, Current: snap.SettledFlows, Delta: delta,
		Pass: delta <= float64(s.Budget), Note: s.Note,
	})
	return nil
}

// MaxGhostsStep asserts the live lingering-ghost gauge grew by at most
// Budget since the most recent [CaptureStep] — the immediate,
// discriminating "nothing was marked for deletion" check. Unlike
// [MaxSettledStep], the gauge rises the instant a MAC is MarkDelete'd
// (before any grace), so Budget 0 across a live migration genuinely
// proves the migration ghosted nothing — a migration keeps the port in
// the Neutron snapshot, so a mark is a defect, not a timing artifact
// (lachesis#235/#243). Delta from capture, so a pre-existing ghost on a
// shared agent doesn't false-fail it.
type MaxGhostsStep struct {
	Budget int64
	Note   string
}

func (MaxGhostsStep) Kind() string { return "assert-max-ghosts" }

func (MaxGhostsStep) requiredMetrics() []string { return []string{MetricLingeringGhosts} }

func (s MaxGhostsStep) Run(ctx context.Context, env *StepEnv) error {
	snap, err := env.scrape(ctx)
	if err != nil {
		return err
	}
	delta := snap.LingeringGhosts - env.ghostsBase
	env.addRow(AssertRow{
		Tenant: "lingering-ghosts", Zone: "-", Direction: "-",
		Baseline: env.ghostsBase, Current: snap.LingeringGhosts, Delta: delta,
		Pass: delta <= float64(s.Budget), Note: s.Note,
	})
	return nil
}

// liveID resolves a DSL id to the live resource id recorded by
// realize; empty when absent.
func liveID(refs []ResourceRef, dslID string) string {
	for _, r := range refs {
		if r.DSLID == dslID {
			return r.ID
		}
	}
	return ""
}

// defaultSteps is the classic linear loop as a script: drive every
// declared flow, assert every declared expectation.
func defaultSteps(sc *Scenario) []Step {
	return []Step{
		DriveStep{Flows: sc.Flows},
		AssertStep{Expect: sc.Expect},
	}
}

// requiredStepMetrics collects the /metrics families the scenario's
// steps declare through [metricRequirer], deduplicated.
func requiredStepMetrics(steps []Step) []string {
	seen := map[string]bool{}
	var out []string
	for _, st := range steps {
		r, ok := st.(metricRequirer)
		if !ok {
			continue
		}
		for _, m := range r.requiredMetrics() {
			if !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	return out
}
