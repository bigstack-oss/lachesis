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
	"log/slog"
	"time"
)

const (
	// DefaultSweepTimeout bounds [AwaitSweepStep]. The agent-side
	// pipeline is reconcile notice (Kafka kick, or the 5-minute
	// periodic pass as the ceiling) → 60s ghost grace → 60s sweep
	// tick, so the default must comfortably cover the no-Kafka worst
	// case.
	DefaultSweepTimeout = 8 * time.Minute
	// sweepPollInterval is the pause between [AwaitSweepStep] scrapes.
	sweepPollInterval = 5 * time.Second
)

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
	Log        *slog.Logger
	SinkDelay  time.Duration
	// MACLearnTimeout passes through to [DriveOptions.MACLearnTimeout];
	// zero uses the default, tests set a small value.
	MACLearnTimeout time.Duration

	// Report accumulates every step's assertion rows; `run` persists
	// it once the script completes.
	Report *AssertReport

	// captured is the per-tuple counter snapshot taken by the most
	// recent [CaptureStep]; settledBase is the summed settled-flows
	// counter at the same instant. Monotone/growth assertions and the
	// sweep wait diff against them.
	captured    map[tuple]float64
	settledBase float64
	// macs records each deleted VM's MAC ([DeleteVMStep] captures it
	// just before the delete) for a later BootVMStep's MACFrom.
	macs map[string]string
}

func (e *StepEnv) addRow(row AssertRow) {
	if !row.Pass {
		e.Report.OK = false
	}
	e.Report.Rows = append(e.Report.Rows, row)
}

// scrape samples all configured agents once.
func (e *StepEnv) scrape(ctx context.Context) (MetricsSnapshot, error) {
	return sampleAcross(ctx, e.Metrics, e.Config.Cluster.Agents)
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
}

func (DriveStep) Kind() string { return "drive" }

func (s DriveStep) Run(ctx context.Context, env *StepEnv) error {
	sc := *env.Scenario
	sc.Flows = s.Flows
	return Drive(ctx, DriveOptions{
		Config:          env.Config,
		Scenario:        &sc,
		State:           env.State,
		StatePath:       env.StatePath,
		Metrics:         env.Metrics,
		Exec:            env.Exec,
		Log:             env.Log,
		SinkDelay:       env.SinkDelay,
		MACLearnTimeout: env.MACLearnTimeout,
	})
}

// AssertStep evaluates Expect with the settle-polling `assert`
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
	env.settledBase = snap.SettledFlows
	env.Log.Info("capture", "tuples", len(env.captured), "settled_flows", env.settledBase)
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

// AwaitSweepStep blocks until the agents' summed
// lachesis_gc_settled_flows_total rises above the value the most recent
// [CaptureStep] recorded — the ghost sweep has folded something — or
// Timeout (default [DefaultSweepTimeout]) fires.
type AwaitSweepStep struct {
	Timeout time.Duration
}

func (AwaitSweepStep) Kind() string { return "await-sweep" }

func (AwaitSweepStep) requiredMetrics() []string { return []string{metricSettledFlows} }

func (s AwaitSweepStep) Run(ctx context.Context, env *StepEnv) error {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultSweepTimeout
	}
	env.Log.Info("await-sweep: waiting", "settled_flows_above", env.settledBase, "timeout", timeout)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
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

// MonotoneStep asserts every captured tuple of Tenant is still at or
// above its captured value — the live form of the §13.1 Contract 7
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
			env.Log.Info("boot-vm: attach gate green", "attached", snap.AttachedInterfaces, "target", target)
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
	netID := liveID(env.State.Networks, s.Network)
	if portID == "" || netID == "" {
		return fmt.Errorf("run-state has no live ids for %s/%s", s.VM, s.Network)
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
// "" in the run-state — the SSH path) are never touched.
type DeleteFIPStep struct {
	VM      string
	Network string
}

func (DeleteFIPStep) Kind() string { return "delete-fip" }

func (s DeleteFIPStep) Run(ctx context.Context, env *StepEnv) error {
	deleted := 0
	kept := make([]FIPRef, 0, len(env.State.FIPs))
	for _, f := range env.State.FIPs {
		if f.VMID != s.VM || f.Network != s.Network || f.Network == "" {
			kept = append(kept, f)
			continue
		}
		if err := env.Cloud.DeleteFIP(ctx, f.ProjectID, f.ID); err != nil {
			return err
		}
		deleted++
		env.Log.Info("delete-fip: gone", "addr", f.Address, "network", s.Network)
	}
	if deleted == 0 {
		return fmt.Errorf("run-state has no FIP for VM %q from network %q", s.VM, s.Network)
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

func (AssertAnomalyStep) requiredMetrics() []string { return []string{metricNeutronAnomalies} }

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
