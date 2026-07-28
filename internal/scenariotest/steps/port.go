// Port steps: NIC hot-plug and the in-guest configuration that makes a
// hot-plugged port carry traffic.

package steps

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/gate"
)

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
