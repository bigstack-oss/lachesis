// Server-lifecycle steps: booting a VM mid-run, deleting one,
// live-migrating it, and waiting.

package steps

import (
	"context"
	"fmt"
	"time"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/gate"
)

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
