// Package steps is the step vocabulary a scripted scenario is written
// in: an ordered program the run executes between up and down, able to
// express the mid-run lifecycle events the classic drive-all/assert-all
// loop cannot — deleting a VM, waiting out the agent's ghost sweep,
// rebooting a MAC under another tenant, restarting an agent cold.
//
// A step is one type implementing [scenariotest.Step], grouped into
// files by what it acts on: traffic.go drives and captures, lifecycle.go
// boots/deletes/migrates servers, port.go hot-plugs NICs, network.go
// mutates Neutron, agent.go drives the agent host, and the two assert_*
// files hold the assertions — billing-facing and agent-internal.
// Adding a step is one new type in the right file; the executor never
// changes.
package steps

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/agentctl"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/assert"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/drive"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/gate"
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
	// agentReadyPollInterval is the pause between readiness scrapes.
	agentReadyPollInterval = 2 * time.Second
	// configRestoreTimeout bounds the end-of-run sweep that puts back
	// agent configs a run left modified ([scenariotest.StepEnv.restoreDirtyConfigs]).
	// One restore is a file copy plus a unit restart, so this covers a
	// couple of nodes without letting a wedged host hang the exit.
	configRestoreTimeout = 3 * time.Minute
)

// sweepPollInterval is the pause between [AwaitSweepStep] polls. A var,
// not a const, so poll-loop tests can shrink it.
var sweepPollInterval = 5 * time.Second

// --- the vocabulary ---

// DriveStep pushes Flows exactly like the standalone `drive`
// subcommand: attach recheck, fresh baseline into run-state, then the
// streams. A later [AssertStep] diffs against this step's baseline.
type DriveStep struct {
	Flows []scenariotest.Flow
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

func (s DriveStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	sc := *env.Scenario
	sc.Flows = s.Flows
	return drive.Run(ctx, drive.Options{
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
// the "sender outside the cluster" no [scenariotest.Flow] can express, and the
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

func (s IngressFlowStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	stdin, ok := env.Exec.(scenariotest.StdinExec)
	if !ok {
		return fmt.Errorf("ingress-flow: the exec transport cannot stream stdin (need [scenariotest.StdinExec])")
	}
	// Zero-flow drive: the same gates and baseline capture a DriveStep
	// gets, with the actual traffic pushed from the harness below.
	sc := *env.Scenario
	sc.Flows = nil
	if err := drive.Run(ctx, drive.Options{
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
	if err := gate.SSHReady(ctx, env, s.To, fip); err != nil {
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

// AssertStep evaluates scenariotest.Expect with the stabilize-polling `assert`
// semantics against the most recent DriveStep's baseline, folding the
// rows (tagged Note when they carry none) into the run's report.
type AssertStep struct {
	Expect []scenariotest.Expect
	Note   string
}

func (AssertStep) Kind() string { return "assert" }

func (s AssertStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	sc := *env.Scenario
	sc.Expect = s.Expect
	rep, err := assert.Run(ctx, assert.Options{
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
		env.AddRow(row)
	}
	return nil
}

// CaptureStep snapshots every counter tuple plus the settled-flows
// base. Monotone and growth assertions, and the sweep wait, diff
// against the most recent capture.
type CaptureStep struct{}

func (CaptureStep) Kind() string { return "capture" }

func (CaptureStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	return env.TakeCapture(ctx)
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

func (s DeleteVMStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	mac, err := env.VMMAC(ctx, s.VM)
	if err != nil {
		return err
	}
	env.RecordMAC(s.VM, mac)

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
	kept := make([]scenariotest.ResourceRef, 0, len(env.State.Ports))
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

func (s AwaitSweepStep) RequiredMetrics() []string {
	if s.ForMACOf != "" {
		return nil // uses /debug/lookup, not a metric family
	}
	return []string{scenariotest.MetricSettledFlows}
}

func (s AwaitSweepStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultSweepTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if s.ForMACOf != "" {
		return s.awaitMACSwept(ctx, env, timeout)
	}
	env.Log.Warn("await-sweep: waiting on the GLOBAL settled counter — unreliable on a shared agent (lachesis#240); set ForMACOf", "settled_flows_above", env.Captured.SettledFlows, "timeout", timeout)
	for {
		snap, err := env.Scrape(ctx)
		if err != nil {
			return err
		}
		if snap.SettledFlows > env.Captured.SettledFlows {
			env.Log.Info("await-sweep: observed", "settled_flows_from", env.Captured.SettledFlows, "settled_flows_to", snap.SettledFlows)
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
func (s AwaitSweepStep) awaitMACSwept(ctx context.Context, env *scenariotest.StepEnv, timeout time.Duration) error {
	mac, err := env.VMMAC(ctx, s.ForMACOf)
	if err != nil {
		return fmt.Errorf("await-sweep: no MAC known for %q (delete or detach it first): %w", s.ForMACOf, err)
	}
	env.Log.Info("await-sweep: waiting for MAC to leave metadata", "for", s.ForMACOf, "mac", mac, "timeout", timeout)
	everFound := false // did the MAC resolve on any agent at any poll?
	var lastErr error  // most recent transient lookup failure, surfaced on timeout
	for {
		gone := true
		for _, u := range scenariotest.AgentURLs(env.Config) {
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

func (s MonotoneStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	ref, err := env.Project(s.Tenant)
	if err != nil {
		return err
	}
	snap, err := env.Scrape(ctx)
	if err != nil {
		return err
	}
	cur := scenariotest.SumByTuple(snap.Bytes)
	for k, base := range env.Captured.Tuples {
		if k.Tenant != ref.ID {
			continue
		}
		env.AddRow(scenariotest.AssertRow{
			Tenant: s.Tenant, TenantID: k.Tenant,
			Zone: k.Zone, Direction: k.Direction,
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

func (s MaxGrowthStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	label := env.TenantLabel(s.Tenant)
	snap, err := env.Scrape(ctx)
	if err != nil {
		return err
	}
	cur := scenariotest.SumByTuple(snap.Bytes)
	for _, dir := range []string{"tx", "rx"} {
		k := scenariotest.Tuple{Tenant: label, Zone: s.Zone, Direction: dir}
		env.AddRow(scenariotest.AssertRow{
			Tenant: s.Tenant, TenantID: label,
			Zone: s.Zone, Direction: dir,
			Baseline: env.Captured.Tuples[k], Current: cur[k], Delta: cur[k] - env.Captured.Tuples[k],
			Pass: cur[k]-env.Captured.Tuples[k] < float64(s.Budget),
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

func (s BootVMStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
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
	proj, err := env.Project(project)
	if err != nil {
		return err
	}
	netID := scenariotest.LiveID(env.State.Networks, network)
	subnetID := scenariotest.LiveID(env.State.Subnets, subnet)
	if netID == "" || subnetID == "" {
		return fmt.Errorf("run-state has no live ids for %s/%s", network, subnet)
	}

	mac := ""
	if s.MACFrom != "" {
		if mac, err = env.VMMAC(ctx, s.MACFrom); err != nil {
			return err
		}
	}
	p := env.Config.Prerequisites
	flavorID, err := env.Cloud.FindFlavor(ctx, scenariotest.FlavorFor(env.Config, env.Scenario))
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

	baseline, err := env.Scrape(ctx)
	if err != nil {
		return fmt.Errorf("attach baseline scrape: %w", err)
	}

	name := scenariotest.Mangle(env.Config.Naming.Prefix, env.State.RunID, s.VM)
	portID, err := env.Cloud.CreatePort(ctx, proj.ID, scenariotest.PortSpec{
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
	env.State.Ports = append(env.State.Ports, scenariotest.ResourceRef{DSLID: s.VM, ID: portID, Name: name, ProjectID: proj.ID, MAC: portMAC})
	if err := env.State.Save(env.StatePath); err != nil {
		return err
	}

	// Deferred VMs honor scenariotest.Scenario.Placement like up-time boots do,
	// reusing realize's recorded resolution; run-states predating
	// placement persistence resolve fresh.
	placement := env.State.Placement
	if placement == nil {
		var perr error
		if placement, perr = scenariotest.ResolvePlacement(env.Scenario.Placement, env.Config.Cluster.Agents); perr != nil {
			return perr
		}
	}
	serverID, err := env.Cloud.CreateServer(ctx, proj.ID, scenariotest.ServerSpec{
		Name:             name,
		FlavorID:         flavorID,
		ImageID:          imageID,
		PortID:           portID,
		KeypairName:      p.KeypairName,
		AvailabilityZone: scenariotest.PlacementAZ(placement, s.VM),
	})
	if err != nil {
		return err
	}
	env.State.Servers = append(env.State.Servers, scenariotest.ResourceRef{DSLID: s.VM, ID: serverID, Name: name, ProjectID: proj.ID})
	if err := env.State.Save(env.StatePath); err != nil {
		return err
	}
	activeCtx, cancel := context.WithTimeout(ctx, scenariotest.ServerActiveTimeout)
	defer cancel()
	if err := env.Cloud.WaitServerActive(activeCtx, proj.ID, serverID); err != nil {
		return err
	}

	fipID, addr, err := env.Cloud.CreateFIP(ctx, proj.ID, scenariotest.FIPCreateSpec{
		ExternalNetworkID: extNetID,
		PortID:            portID,
		FixedIP:           ip,
	})
	if err != nil {
		return err
	}
	env.State.FIPs = append(env.State.FIPs, scenariotest.FIPRef{VMID: s.VM, ID: fipID, Address: addr, ProjectID: proj.ID})
	if err := env.State.Save(env.StatePath); err != nil {
		return err
	}
	env.Log.Info("boot-vm: up", "vm", s.VM, "port", portID, "mac", mac, "server", serverID, "fip", addr)

	return s.attachGate(ctx, env, baseline)
}

// attachGate waits for the booted VM's tap with the same summed gauge
// + no-new-failures rule as realize, then refreshes the run-state's
// attach record so a later DriveStep's recheck expects the new count.
func (s BootVMStep) attachGate(ctx context.Context, env *scenariotest.StepEnv, baseline scenariotest.MetricsSnapshot) error {
	return gate.AttachRise(ctx, env, baseline, "boot-vm")
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

func (s AssociateFIPStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
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
	proj, err := env.Project(project)
	if err != nil {
		return err
	}
	portID := scenariotest.LiveID(env.State.Ports, s.VM)
	if portID == "" {
		return fmt.Errorf("run-state has no live port for %q", s.VM)
	}
	netID := scenariotest.LiveID(env.State.Networks, s.Network)
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
	fipID, addr, err := env.Cloud.CreateFIP(ctx, proj.ID, scenariotest.FIPCreateSpec{
		ExternalNetworkID: netID,
		PortID:            portID,
		FixedIP:           ip,
	})
	if err != nil {
		return err
	}
	env.State.FIPs = append(env.State.FIPs, scenariotest.FIPRef{
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
func routerRef(env *scenariotest.StepEnv, dsl string) (scenariotest.ResourceRef, error) {
	for _, r := range env.State.Routers {
		if r.DSLID == dsl {
			return r, nil
		}
	}
	return scenariotest.ResourceRef{}, fmt.Errorf("run-state has no router %q", dsl)
}

// SetRouterRoutesStep replaces a router's static (extra) routes mid-run
// via the Neutron API — the live route change behind the
// extraroute-mutation scenario. The agent's next reconcile rebuilds the
// trie insert-then-delete (docs/architecture/trie-construction.md), so
// new traffic reclassifies with no MISS window. Routes wholly replaces
// the router's route set (an empty slice clears them).
type SetRouterRoutesStep struct {
	Router string
	Routes []scenariotest.RouteSpec
}

func (SetRouterRoutesStep) Kind() string { return "set-router-routes" }

func (s SetRouterRoutesStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
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
// run-state (a [scenariotest.Scenario.CreateExternalNets] marker).
type SetRouterGatewayStep struct {
	Router      string
	ExternalNet string
}

func (SetRouterGatewayStep) Kind() string { return "set-router-gateway" }

func (s SetRouterGatewayStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	ref, err := routerRef(env, s.Router)
	if err != nil {
		return err
	}
	netID := scenariotest.LiveID(env.State.Networks, s.ExternalNet)
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

func (SettledTuplesGrewStep) RequiredMetrics() []string {
	return []string{scenariotest.MetricTenantSettledTuples}
}

func (s SettledTuplesGrewStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultSweepTimeout
	}
	deadline := time.Now().Add(timeout)
	var delta float64
	for {
		snap, err := env.Scrape(ctx)
		if err != nil {
			return err
		}
		delta = snap.SettledTuples - env.Captured.SettledTuples
		if delta >= float64(s.Min) || time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(sweepPollInterval):
		}
	}
	env.AddRow(scenariotest.AssertRow{
		Tenant: "settled-tuples", Zone: "-", Direction: "-",
		Baseline: env.Captured.SettledTuples, Current: env.Captured.SettledTuples + delta, Delta: delta,
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

func (s AddRouteStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	fip := ""
	for _, f := range env.State.FIPs {
		if f.VMID == s.VM && f.Network == "" { // the provider SSH FIP
			fip = f.Address
		}
	}
	if fip == "" {
		return fmt.Errorf("run-state has no SSH FIP for VM %q", s.VM)
	}
	if err := gate.SSHReady(ctx, env, s.VM, fip); err != nil {
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
// (`device_owner compute:*`) — the resolver's scenariotest.Step B case
// (docs/architecture/trie-construction.md#the-static-route-resolver),
// exercised live by the vm-appliance-nexthop scenario.
//
// The forwarded packet keeps the ORIGINAL source IP, so the port it
// leaves by must ALSO have port security disabled
// ([scenariotest.PortSpec.PortSecurityOff] / [AttachPortStep.PortSecurityOff]) or
// OVN anti-spoofing drops it on the way out. Same absolute-path +
// SSH-FIP spelling as [AddRouteStep].
type EnableForwardingStep struct {
	VM string
}

func (EnableForwardingStep) Kind() string { return "enable-forwarding" }

func (s EnableForwardingStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	fip := ""
	for _, f := range env.State.FIPs {
		if f.VMID == s.VM && f.Network == "" { // the provider SSH FIP
			fip = f.Address
		}
	}
	if fip == "" {
		return fmt.Errorf("run-state has no SSH FIP for VM %q", s.VM)
	}
	if err := gate.SSHReady(ctx, env, s.VM, fip); err != nil {
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

func (s AssertFlowPeerStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
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
	for _, u := range scenariotest.AgentURLs(env.Config) {
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
	env.AddRow(scenariotest.AssertRow{
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

func (s DeleteFIPStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	deleted := 0
	kept := make([]scenariotest.FIPRef, 0, len(env.State.FIPs))
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

func (AssertAnomalyStep) RequiredMetrics() []string {
	return []string{scenariotest.MetricNeutronAnomalies}
}

func (s AssertAnomalyStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultAnomalyTimeout
	}
	env.Log.Info("assert-anomaly", "class", s.Class, "min", s.Min, "max", s.Max, "timeout", timeout)
	deadline := time.Now().Add(timeout)
	var last float64
	for {
		snap, err := env.Scrape(ctx)
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
	env.AddRow(scenariotest.AssertRow{
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

// dashEmpty renders an optional value for logs.
func dashEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// MigrateStep live-migrates a realized VM and waits until Nova
// reports it ACTIVE on a different host. Target optionally names the
// destination — a placement slot ("node:<i>") or a literal configured
// agent host, the [scenariotest.Scenario.Placement] vocabulary — empty lets the
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

func (s MigrateStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	var ref scenariotest.ResourceRef
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
		host, err := scenariotest.ResolveNode(s.Target, env.Config.Cluster.Agents)
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
			env.State.Migrations = append(env.State.Migrations, scenariotest.MigrationRecord{VM: s.VM, From: from, To: host})
			// Re-baseline the attach record: migration legitimately
			// re-plumbs taps, and the source agent racing its dying tap
			// increments the failure counter (benign — the link is
			// gone). Without a fresh baseline the next drive's recheck
			// reads that noise as taps lost since up.
			if snap, err := scenariotest.SampleAcross(ctx, env.Metrics, env.Config.Cluster.Agents); err == nil {
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

func (EpochStep) RequiredMetrics() []string {
	return []string{scenariotest.MetricCountersReset}
}

func (s EpochStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	agent, err := scenariotest.AgentForNode(env.Config, s.Node)
	if err != nil {
		return fmt.Errorf("assert-epoch: %w", err)
	}
	base, ok := env.Captured.Epochs[agent.Host]
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
	env.AddRow(scenariotest.AssertRow{
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

func (s SleepStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
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
	// Timeout overrides [scenariotest.AgentControlConfig.ReadyTimeout] for the
	// post-restart readiness wait.
	Timeout time.Duration
}

func (RestartAgentStep) Kind() string { return "restart-agent" }

// HostNeeds declares the agent_control keys this step reads, so a
// cluster that has not staged them SKIPs rather than failing mid-run.
func (s RestartAgentStep) HostNeeds() scenariotest.HostNeeds {
	return scenariotest.HostNeeds{AgentSSH: true, WALPath: s.RemoveWAL, PinPath: s.RemovePins}
}

// requiredMetrics declares both families the readiness gate checks
// ([requiredMetrics]), so the pre-create step-metric gate refuses up
// front on an agent missing either — not just the one this step reads
// for the tap baseline.
func (RestartAgentStep) RequiredMetrics() []string {
	return []string{scenariotest.MetricBytesTotal, scenariotest.MetricAttachedInterfaces}
}

func (s RestartAgentStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	ctl, err := agentctl.For(env, s.Node)
	if err != nil {
		return fmt.Errorf("restart-agent: %w", err)
	}
	// Baseline THIS agent's tap count so readiness can wait for the
	// re-attach (the boot zombie-hunt drops filters, then re-attaches).
	base, err := ctl.Baseline(ctx)
	if err != nil {
		return fmt.Errorf("restart-agent: %w", err)
	}
	// Backup on Set: this step owns the restore debt, so a run that dies
	// before the scenario's restore step still finds its way home
	// (lachesis#274).
	dirty, restored, err := ctl.ApplyConfig(ctx, agentctl.Change{
		Set: s.SetConfig, Restore: s.RestoreConfig, Backup: true,
	})
	if err != nil {
		return fmt.Errorf("restart-agent: %w", err)
	}
	switch {
	case dirty:
		env.MarkConfigDirty(s.Node)
	case restored:
		env.ClearConfigDirty(s.Node)
	}
	oldPID, err := ctl.Restart(ctx, agentctl.Cycle{RemoveWAL: s.RemoveWAL, RemovePins: s.RemovePins})
	if err != nil {
		return fmt.Errorf("restart-agent: %w", err)
	}
	if err := ctl.AwaitReady(ctx, oldPID, base.AttachedInterfaces, s.Timeout); err != nil {
		return fmt.Errorf("restart-agent: %w", err)
	}
	return nil
}

func (s ReloadAgentStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	ctl, err := agentctl.For(env, s.Node)
	if err != nil {
		return fmt.Errorf("reload-agent: %w", err)
	}
	// Backup false, per the PRECONDITION on the type: the earlier
	// restart's backup holds the real config and must survive.
	dirty, _, err := ctl.ApplyConfig(ctx, agentctl.Change{Set: s.SetConfig, Backup: false})
	if err != nil {
		return fmt.Errorf("reload-agent: %w", err)
	}
	if dirty {
		// Idempotent with the restart that took the backup (the documented
		// precondition), so the normal chained case records one debt, not
		// two. Used standalone — where no backup exists — this turns a
		// silently-modified host into a loud end-of-run failure instead
		// (lachesis#274).
		env.MarkConfigDirty(s.Node)
	}
	if err := ctl.Reload(ctx); err != nil {
		return fmt.Errorf("reload-agent: %w", err)
	}
	return nil
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

func (ResolvedGrewStep) RequiredMetrics() []string {
	return []string{scenariotest.MetricUnresolvedResolved}
}

func (s ResolvedGrewStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultSweepTimeout
	}
	deadline := time.Now().Add(timeout)
	var delta float64
	for {
		snap, err := env.Scrape(ctx)
		if err != nil {
			return err
		}
		delta = snap.UnresolvedResolved - env.Captured.Resolved
		if delta >= float64(s.Min) || time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(sweepPollInterval):
		}
	}
	env.AddRow(scenariotest.AssertRow{
		Tenant: "unresolved-resolved", Zone: "-", Direction: "-",
		Baseline: env.Captured.Resolved, Current: env.Captured.Resolved + delta, Delta: delta,
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

func (EvictionsGrewStep) RequiredMetrics() []string { return []string{scenariotest.MetricGCEvictions} }

func (s EvictionsGrewStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultSweepTimeout
	}
	deadline := time.Now().Add(timeout)
	var delta float64
	for {
		snap, err := env.Scrape(ctx)
		if err != nil {
			return err
		}
		delta = snap.PressureReliefEvictions - env.Captured.Evictions
		if delta >= float64(s.Min) || time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(sweepPollInterval):
		}
	}
	env.AddRow(scenariotest.AssertRow{
		Tenant: "gc-pressure-relief", Zone: "-", Direction: "-",
		Baseline: env.Captured.Evictions, Current: env.Captured.Evictions + delta, Delta: delta,
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

func (s PortSeriesStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	portID := scenariotest.LiveID(env.State.Ports, s.Port)
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
		snap, err := env.Scrape(ctx)
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
			env.AddRow(scenariotest.AssertRow{
				Tenant: s.VM, VM: s.VM, Zone: "-", Direction: "-",
				Baseline: s.MinBytes, Current: sum, Delta: sum - s.MinBytes,
				Pass: false, Note: s.Note,
			})
			return nil
		case <-time.After(sweepPollInterval):
		}
	}
	env.AddRow(scenariotest.AssertRow{
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

func (s AwaitPortBindingStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	var ref scenariotest.ResourceRef
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
		for _, u := range scenariotest.AgentURLs(env.Config) {
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
			env.AddRow(scenariotest.AssertRow{
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
			env.AddRow(scenariotest.AssertRow{
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
	AllowedPairs []scenariotest.AddressPair
}

func (AttachPortStep) Kind() string { return "attach-port" }

func (s AttachPortStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
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
	proj, err := env.Project(project)
	if err != nil {
		return err
	}
	serverID, ok := scenariotest.ServerIDFor(env.State, s.VM)
	if !ok {
		return fmt.Errorf("run-state has no server for VM %q", s.VM)
	}
	netID := scenariotest.LiveID(env.State.Networks, s.Network)
	subnetID := scenariotest.LiveID(env.State.Subnets, s.Subnet)
	if netID == "" || subnetID == "" {
		return fmt.Errorf("run-state has no live ids for %s/%s", s.Network, s.Subnet)
	}
	secGroupID, err := env.Cloud.FindSecGroup(ctx, env.Config.Prerequisites.SecGroupName)
	if err != nil {
		return err
	}

	baseline, err := env.Scrape(ctx)
	if err != nil {
		return fmt.Errorf("attach baseline scrape: %w", err)
	}

	pinnedMAC := ""
	if s.MACFrom != "" {
		pinnedMAC = env.RecordedMAC(s.MACFrom)
		if pinnedMAC == "" {
			return fmt.Errorf("attach-port: no MAC recorded for %q (delete or detach it first)", s.MACFrom)
		}
	}
	name := scenariotest.Mangle(env.Config.Naming.Prefix, env.State.RunID, s.ID)
	portID, err := env.Cloud.CreatePort(ctx, proj.ID, scenariotest.PortSpec{
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
	env.State.Ports = append(env.State.Ports, scenariotest.ResourceRef{DSLID: s.ID, ID: portID, Name: name, ProjectID: proj.ID, MAC: mac})
	if err := env.State.Save(env.StatePath); err != nil {
		return err
	}
	if err := env.Cloud.AttachInterface(ctx, proj.ID, serverID, portID); err != nil {
		return err
	}
	env.Log.Info("attach-port: plugged", "vm", s.VM, "nic", s.ID, "port", portID, "mac", mac, "ip", s.IP)
	return gate.AttachRise(ctx, env, baseline, "attach-port")
}

// ReattachPortStep plugs a previously-detached NIC (its port kept
// alive by [DetachPortStep] with Delete false) back into its VM — the
// same Neutron port, same MAC, new tap. Gated like any attach.
type ReattachPortStep struct {
	VM   string
	Port string // the [AttachPortStep.ID] of the detached NIC
}

func (ReattachPortStep) Kind() string { return "reattach-port" }

func (s ReattachPortStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	var ref scenariotest.ResourceRef
	for _, p := range env.State.Ports {
		if p.DSLID == s.Port {
			ref = p
			break
		}
	}
	if ref.ID == "" {
		return fmt.Errorf("run-state has no port %q", s.Port)
	}
	serverID, ok := scenariotest.ServerIDFor(env.State, s.VM)
	if !ok {
		return fmt.Errorf("run-state has no server for VM %q", s.VM)
	}
	baseline, err := env.Scrape(ctx)
	if err != nil {
		return fmt.Errorf("attach baseline scrape: %w", err)
	}
	if err := env.Cloud.AttachInterface(ctx, ref.ProjectID, serverID, ref.ID); err != nil {
		return err
	}
	env.Log.Info("reattach-port: plugged", "vm", s.VM, "nic", s.Port, "port", ref.ID, "mac", ref.MAC)
	return gate.AttachRise(ctx, env, baseline, "reattach-port")
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

func (s DetachPortStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	var ref scenariotest.ResourceRef
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
	env.RecordMAC(s.Port, ref.MAC)
	serverID, ok := scenariotest.ServerIDFor(env.State, s.VM)
	if !ok {
		return fmt.Errorf("run-state has no server for VM %q", s.VM)
	}
	baseline, err := env.Scrape(ctx)
	if err != nil {
		return fmt.Errorf("detach baseline scrape: %w", err)
	}
	if err := env.Cloud.DetachInterface(ctx, ref.ProjectID, serverID, ref.ID); err != nil {
		return err
	}

	// Wait for the tap to actually drop, then re-baseline: the next
	// drive's recheck must expect one tap fewer and must not read the
	// dying-tap failure blip as taps lost since up.
	waitCtx, cancel := context.WithTimeout(ctx, scenariotest.DefaultAttachTimeout)
	defer cancel()
	for {
		snap, err := env.Scrape(waitCtx)
		if err != nil {
			return fmt.Errorf("detach gate scrape: %w", err)
		}
		if snap.AttachedInterfaces <= baseline.AttachedInterfaces-1 {
			env.State.Attach = scenariotest.AttachRecord{Target: snap.AttachedInterfaces, Failures: snap.AttachFailures}
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
		case <-time.After(scenariotest.AttachPollInterval):
		}
	}

	if !s.Delete {
		return nil
	}
	if err := env.Cloud.DeletePort(ctx, ref.ProjectID, ref.ID); err != nil {
		return err
	}
	kept := make([]scenariotest.ResourceRef, 0, len(env.State.Ports))
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

func (s ConfigureNICStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
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
	if err := scenariotest.ShellSafe("configure-nic.dev", s.Dev); err != nil {
		return err
	}
	if err := gate.SSHReady(ctx, env, s.VM, fip); err != nil {
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

func (s SetNICMACStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	fip := ""
	for _, f := range env.State.FIPs {
		if f.VMID == s.VM && f.Network == "" { // the provider SSH FIP
			fip = f.Address
		}
	}
	if fip == "" {
		return fmt.Errorf("set-nic-mac: run-state has no SSH FIP for VM %q", s.VM)
	}
	if err := scenariotest.ShellSafe("set-nic-mac.dev", s.Dev); err != nil {
		return err
	}
	if err := scenariotest.ShellSafe("set-nic-mac.mac", s.MAC); err != nil {
		return err
	}
	if err := gate.SSHReady(ctx, env, s.VM, fip); err != nil {
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

func (s ZoneGrowthStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	label := env.TenantLabel(s.Tenant)
	k := scenariotest.Tuple{Tenant: label, Zone: s.Zone, Direction: s.Direction}
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
		snap, err := env.Scrape(ctx)
		if err != nil {
			return err
		}
		delta = scenariotest.SumByTuple(snap.Bytes)[k] - env.Captured.Tuples[k]
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
	env.AddRow(scenariotest.AssertRow{
		Tenant: s.Tenant, TenantID: label,
		Zone: s.Zone, Direction: s.Direction,
		Baseline: env.Captured.Tuples[k], Current: env.Captured.Tuples[k] + delta, Delta: delta,
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
func (ServerMonotoneStep) RequiredMetrics() []string { return nil }

func (s ServerMonotoneStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	serverID, ok := scenariotest.ServerIDFor(env.State, s.VM)
	if !ok {
		return fmt.Errorf("run-state has no server for VM %q", s.VM)
	}
	snap, err := env.Scrape(ctx)
	if err != nil {
		return err
	}
	cur := scenariotest.SumByServerTuple(snap.Servers)
	rows := 0
	for k, base := range env.Captured.Servers {
		if k.Server != serverID {
			continue
		}
		rows++
		env.AddRow(scenariotest.AssertRow{
			Tenant: s.VM, VM: s.VM, ServerID: serverID,
			Zone: k.Zone, ExternalNetwork: k.Ext, Direction: k.Direction,
			Baseline: base, Current: cur[k], Delta: cur[k] - base,
			Pass: cur[k] >= base, Note: s.Note,
		})
	}
	if rows == 0 {
		return fmt.Errorf("assert-server-monotone: no captured server tuples for VM %q — capture after its traffic was driven", s.VM)
	}
	return nil
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

func (MaxSettledStep) RequiredMetrics() []string { return []string{scenariotest.MetricSettledFlows} }

func (s MaxSettledStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	snap, err := env.Scrape(ctx)
	if err != nil {
		return err
	}
	delta := snap.SettledFlows - env.Captured.SettledFlows
	env.AddRow(scenariotest.AssertRow{
		Tenant: "settled-flows", Zone: "-", Direction: "-",
		Baseline: env.Captured.SettledFlows, Current: snap.SettledFlows, Delta: delta,
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

func (MaxGhostsStep) RequiredMetrics() []string { return []string{scenariotest.MetricLingeringGhosts} }

func (s MaxGhostsStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	snap, err := env.Scrape(ctx)
	if err != nil {
		return err
	}
	delta := snap.LingeringGhosts - env.Captured.Ghosts
	env.AddRow(scenariotest.AssertRow{
		Tenant: "lingering-ghosts", Zone: "-", Direction: "-",
		Baseline: env.Captured.Ghosts, Current: snap.LingeringGhosts, Delta: delta,
		Pass: delta <= float64(s.Budget), Note: s.Note,
	})
	return nil
}

// RestoreDirtyConfigs puts back every agent config a step modified and
// did not restore. It is the safety net for the abort paths: a step
// error returns straight out of the executor, so a scenario's trailing
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
func RestoreDirtyConfigs(ctx context.Context, env *scenariotest.StepEnv) {
	nodes := env.TakeConfigDirty()
	if len(nodes) == 0 {
		return
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), configRestoreTimeout)
	defer cancel()
	for i := len(nodes) - 1; i >= 0; i-- {
		node := nodes[i]
		env.Log.Warn("restoring an agent config the run left modified", "node", node)
		if err := (RestartAgentStep{Node: node, RestoreConfig: true}).Run(rctx, env); err != nil {
			env.Log.Error("agent config NOT restored — the host is still on the scenario's config",
				"node", node, "err", err)
		}
	}
}

// Default is the classic linear loop as a script: drive every declared
// flow, assert every declared expectation. A scenario that declares no
// Steps of its own runs this.
func Default(sc *scenariotest.Scenario) []scenariotest.Step {
	return []scenariotest.Step{
		DriveStep{Flows: sc.Flows},
		AssertStep{Expect: sc.Expect},
	}
}

// RequiredMetrics collects the /metrics families a script's steps
// declare through [scenariotest.MetricRequirer], deduplicated. `run`
// checks them against every agent before creating anything, so a
// scenario fails on an under-featured agent before any topology exists.
func RequiredMetrics(steps []scenariotest.Step) []string {
	seen := map[string]bool{}
	var out []string
	for _, st := range steps {
		r, ok := st.(scenariotest.MetricRequirer)
		if !ok {
			continue
		}
		for _, m := range r.RequiredMetrics() {
			if !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	return out
}
