package scenariotest

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/neutron"
)

// RealizeOptions bundles everything `up` needs to stand a scenario up.
type RealizeOptions struct {
	Config    Config
	Scenario  *Scenario
	RunID     string
	StatePath string
	Cloud     Cloud
	Metrics   MetricsSource
	Log       io.Writer

	// AttachTimeout bounds the attach-ready gate. Zero uses
	// [DefaultAttachTimeout].
	AttachTimeout time.Duration
}

const (
	// DefaultAttachTimeout bounds how long `up` waits for the agents
	// to attach to the new VM taps before giving up.
	DefaultAttachTimeout = 90 * time.Second
	// attachPollInterval is how often the attach gate re-scrapes.
	attachPollInterval = 2 * time.Second
	// serverActiveTimeout bounds each server's boot wait. Without it a
	// server stuck in BUILD would hang `up` forever — the only other
	// cancellation is the operator's SIGINT.
	serverActiveTimeout = 5 * time.Minute
)

// Realize stands the scenario's topology up on the live cluster and
// blocks until the agents have attached to the new taps. It writes
// run-state to opts.StatePath after every created resource, so a
// partial failure still leaves a record `down` can clean up. It never
// deletes a project. The returned RunState is the realized topology.
func Realize(ctx context.Context, opts RealizeOptions) (*RunState, error) {
	if opts.Log == nil {
		opts.Log = io.Discard
	}
	r := &realizer{
		ctx:           ctx,
		opts:          opts,
		rs:            NewRunState(opts.RunID, opts.Scenario.Name, opts.Config.Naming.Prefix),
		netLive:       map[string]string{},
		netExternal:   map[string]bool{},
		subnetLive:    map[string]string{},
		subnetGateway: map[string]string{},
		routerLive:    map[string]string{},
		vmPort:        map[string]string{},
		vmProject:     map[string]string{},
		vmInternalIP:  map[string]string{},
	}
	if err := r.run(); err != nil {
		return r.rs, err
	}
	return r.rs, nil
}

type realizer struct {
	ctx  context.Context
	opts RealizeOptions
	rs   *RunState

	// resolved prerequisites (live IDs)
	extNetID   string
	flavorID   string
	imageID    string
	secGroupID string

	// DSL id → live id maps
	netLive       map[string]string // external DSL nets map to the real external net
	netExternal   map[string]bool
	subnetLive    map[string]string
	subnetGateway map[string]string // DSL subnet id → its DSL gateway IP
	routerLive    map[string]string

	vmPort       map[string]string // VM DSL id → live port id
	vmProject    map[string]string // VM DSL id → project id
	vmInternalIP map[string]string
	vmOrder      []string // VM DSL ids in creation order
}

func (r *realizer) run() error {
	snap := r.opts.Scenario.Builder.Build()

	if err := r.resolvePrereqs(); err != nil {
		return err
	}
	if err := r.networks(snap); err != nil {
		return err
	}
	if err := r.subnets(snap); err != nil {
		return err
	}
	if err := r.routers(snap); err != nil {
		return err
	}
	if err := r.routerInterfaces(snap); err != nil {
		return err
	}
	// Static routes go on after interfaces: a route's nexthop must sit
	// on an already-attached (transit) subnet or Neutron rejects it.
	if err := r.routerRoutes(snap); err != nil {
		return err
	}
	if err := r.vmPorts(snap); err != nil {
		return err
	}

	// Capture the attach baseline now: VM ports exist but are unbound,
	// so no taps yet. Booting binds them and taps appear.
	baseline, err := sampleAcross(r.ctx, r.opts.Metrics, agentURLs(r.opts.Config))
	if err != nil {
		return fmt.Errorf("attach baseline scrape: %w", err)
	}

	if err := r.bootServers(); err != nil {
		return err
	}
	if err := r.waitActive(); err != nil {
		return err
	}
	if err := r.allocateFIPs(); err != nil {
		return err
	}
	if err := r.attachGate(baseline, len(r.vmOrder)); err != nil {
		return err
	}
	r.logf("up complete: %d VM(s), run-state at %s", len(r.vmOrder), r.opts.StatePath)
	return nil
}

func (r *realizer) resolvePrereqs() error {
	p := r.opts.Config.Prerequisites
	var err error
	if r.extNetID, err = r.opts.Cloud.FindExternalNetwork(r.ctx, p.ExternalNetworkName); err != nil {
		return err
	}
	if r.flavorID, err = r.opts.Cloud.FindFlavor(r.ctx, flavorFor(r.opts.Config, r.opts.Scenario)); err != nil {
		return err
	}
	if r.imageID, err = r.opts.Cloud.FindImage(r.ctx, p.ImageName); err != nil {
		return err
	}
	if r.secGroupID, err = r.opts.Cloud.FindSecGroup(r.ctx, p.SecGroupName); err != nil {
		return err
	}
	return nil
}

func (r *realizer) networks(snap neutron.Snapshot) error {
	for _, n := range snap.Networks {
		// External networks are never created — the router gateways to
		// the real provider external network, and so do the VMs' FIPs.
		if n.IsExternal {
			r.netLive[n.ID] = r.extNetID
			r.netExternal[n.ID] = true
			continue
		}
		proj, err := r.projectID(n.ProjectID)
		if err != nil {
			return err
		}
		name := Mangle(r.prefix(), r.opts.RunID, n.ID)
		id, err := r.opts.Cloud.CreateNetwork(r.ctx, proj, NetworkSpec{Name: name, Shared: n.Shared})
		if err != nil {
			return err
		}
		r.netLive[n.ID] = id
		r.rs.Networks = append(r.rs.Networks, ResourceRef{DSLID: n.ID, ID: id, Name: name, ProjectID: proj})
		if err := r.save(); err != nil {
			return err
		}
		r.logf("network %s -> %s", n.ID, id)
	}
	return nil
}

func (r *realizer) subnets(snap neutron.Snapshot) error {
	for _, s := range snap.Subnets {
		r.subnetGateway[s.ID] = s.GatewayIP
		// Subnets on external networks belong to the real provider net.
		if r.netExternal[s.NetworkID] {
			continue
		}
		proj, err := r.projectID(s.ProjectID)
		if err != nil {
			return err
		}
		name := Mangle(r.prefix(), r.opts.RunID, s.ID)
		id, err := r.opts.Cloud.CreateSubnet(r.ctx, proj, SubnetSpec{
			Name:      name,
			NetworkID: r.netLive[s.NetworkID],
			CIDR:      s.CIDR,
			GatewayIP: s.GatewayIP,
		})
		if err != nil {
			return err
		}
		r.subnetLive[s.ID] = id
		r.rs.Subnets = append(r.rs.Subnets, ResourceRef{DSLID: s.ID, ID: id, Name: name, ProjectID: proj})
		if err := r.save(); err != nil {
			return err
		}
		r.logf("subnet %s -> %s", s.ID, id)
	}
	return nil
}

func (r *realizer) routers(snap neutron.Snapshot) error {
	for _, rt := range snap.Routers {
		proj, err := r.projectID(rt.ProjectID)
		if err != nil {
			return err
		}
		extID := ""
		if rt.ExternalNetworkID != "" {
			extID = r.netLive[rt.ExternalNetworkID] // external DSL net → real ext net
			if extID == "" {
				extID = r.extNetID
			}
		}
		name := Mangle(r.prefix(), r.opts.RunID, rt.ID)
		id, err := r.opts.Cloud.CreateRouter(r.ctx, proj, RouterSpec{Name: name, ExternalNetworkID: extID})
		if err != nil {
			return err
		}
		r.routerLive[rt.ID] = id
		r.rs.Routers = append(r.rs.Routers, ResourceRef{DSLID: rt.ID, ID: id, Name: name, ProjectID: proj})
		if err := r.save(); err != nil {
			return err
		}
		r.logf("router %s -> %s", rt.ID, id)
	}
	return nil
}

// routerRoutes applies each router's static (extra) routes. Run after
// routerInterfaces so every nexthop sits on an attached subnet.
func (r *realizer) routerRoutes(snap neutron.Snapshot) error {
	for _, rt := range snap.Routers {
		if len(rt.Routes) == 0 {
			continue
		}
		proj, err := r.projectID(rt.ProjectID)
		if err != nil {
			return err
		}
		routes := make([]RouteSpec, len(rt.Routes))
		for i, rr := range rt.Routes {
			routes[i] = RouteSpec{Destination: rr.Destination, Nexthop: rr.Nexthop}
		}
		if err := r.opts.Cloud.SetRouterRoutes(r.ctx, proj, r.routerLive[rt.ID], routes); err != nil {
			return err
		}
		r.logf("router %s: %d static route(s)", rt.ID, len(routes))
	}
	return nil
}

// routerInterfaces attaches each network:router_interface port from
// the snapshot to its router. When the interface sits on the subnet's
// gateway IP we attach by subnet (Neutron assigns the gateway);
// otherwise (e.g. two routers on a transit subnet) we pre-create a
// port at the requested IP and attach by port.
func (r *realizer) routerInterfaces(snap neutron.Snapshot) error {
	for _, p := range snap.Ports {
		if p.DeviceOwner != "network:router_interface" {
			continue
		}
		routerID := r.routerLive[p.DeviceID]
		if routerID == "" {
			return fmt.Errorf("router interface %s references unknown router %q", p.ID, p.DeviceID)
		}
		proj, err := r.projectID(p.ProjectID)
		if err != nil {
			return err
		}
		fip := p.FixedIPs[0]
		subnetID := r.subnetLive[fip.SubnetID]
		if subnetID == "" {
			return fmt.Errorf("router interface %s references unknown subnet %q", p.ID, fip.SubnetID)
		}

		if fip.IPAddress != "" && fip.IPAddress == r.subnetGateway[fip.SubnetID] {
			if err := r.opts.Cloud.AddRouterInterface(r.ctx, proj, routerID, subnetID, ""); err != nil {
				return err
			}
			r.logf("router interface %s: router %s ↔ subnet %s (gateway)", p.ID, p.DeviceID, fip.SubnetID)
			continue
		}

		name := Mangle(r.prefix(), r.opts.RunID, p.ID)
		portID, err := r.opts.Cloud.CreatePort(r.ctx, proj, PortSpec{
			Name:      name,
			NetworkID: r.netLive[p.NetworkID],
			SubnetID:  subnetID,
			FixedIP:   fip.IPAddress,
		})
		if err != nil {
			return err
		}
		r.rs.Ports = append(r.rs.Ports, ResourceRef{DSLID: p.ID, ID: portID, Name: name, ProjectID: proj})
		if err := r.save(); err != nil {
			return err
		}
		if err := r.opts.Cloud.AddRouterInterface(r.ctx, proj, routerID, "", portID); err != nil {
			return err
		}
		r.logf("router interface %s: router %s ↔ port %s @ %s", p.ID, p.DeviceID, portID, fip.IPAddress)
	}
	return nil
}

func (r *realizer) vmPorts(snap neutron.Snapshot) error {
	deferred := make(map[string]bool, len(r.opts.Scenario.Deferred))
	for _, id := range r.opts.Scenario.Deferred {
		deferred[id] = true
	}
	for _, p := range snap.Ports {
		if !strings.HasPrefix(p.DeviceOwner, "compute:") {
			continue
		}
		// Deferred VMs are declared but not realized: no port, no
		// server, no FIP, no attach-gate slot. A [BootVMStep] creates
		// them mid-script.
		if deferred[p.ID] {
			r.logf("vm %s deferred (booted by a later step)", p.ID)
			continue
		}
		proj, err := r.projectID(p.ProjectID)
		if err != nil {
			return err
		}
		fip := p.FixedIPs[0]
		name := Mangle(r.prefix(), r.opts.RunID, p.ID)
		portID, err := r.opts.Cloud.CreatePort(r.ctx, proj, PortSpec{
			Name:       name,
			NetworkID:  r.netLive[p.NetworkID],
			SubnetID:   r.subnetLive[fip.SubnetID],
			FixedIP:    fip.IPAddress,
			SecGroupID: r.secGroupID,
		})
		if err != nil {
			return err
		}
		r.vmPort[p.ID] = portID
		r.vmProject[p.ID] = proj
		r.vmInternalIP[p.ID] = fip.IPAddress
		r.vmOrder = append(r.vmOrder, p.ID)
		r.rs.Ports = append(r.rs.Ports, ResourceRef{DSLID: p.ID, ID: portID, Name: name, ProjectID: proj})
		if err := r.save(); err != nil {
			return err
		}
		r.logf("vm port %s -> %s @ %s", p.ID, portID, fip.IPAddress)
	}
	return nil
}

func (r *realizer) bootServers() error {
	for _, vmID := range r.vmOrder {
		proj := r.vmProject[vmID]
		az := ""
		if host := r.opts.Scenario.Placement[vmID]; host != "" {
			az = "nova:" + host
		}
		name := Mangle(r.prefix(), r.opts.RunID, vmID)
		// No security group here: the VM boots on a pre-created port
		// that already carries it, and Nova ignores boot-time secgroups
		// for pre-existing ports anyway.
		id, err := r.opts.Cloud.CreateServer(r.ctx, proj, ServerSpec{
			Name:             name,
			FlavorID:         r.flavorID,
			ImageID:          r.imageID,
			PortID:           r.vmPort[vmID],
			KeypairName:      r.opts.Config.Prerequisites.KeypairName,
			AvailabilityZone: az,
		})
		if err != nil {
			return err
		}
		r.rs.Servers = append(r.rs.Servers, ResourceRef{DSLID: vmID, ID: id, Name: name, ProjectID: proj})
		if err := r.save(); err != nil {
			return err
		}
		r.logf("server %s -> %s booting", vmID, id)
	}
	return nil
}

func (r *realizer) waitActive() error {
	for _, s := range r.rs.Servers {
		if err := r.waitOneActive(s); err != nil {
			return err
		}
		r.logf("server %s ACTIVE", s.DSLID)
	}
	return nil
}

// waitOneActive bounds a single server's boot wait with
// [serverActiveTimeout] so a server stuck in BUILD fails the run
// instead of hanging it.
func (r *realizer) waitOneActive(s ResourceRef) error {
	ctx, cancel := context.WithTimeout(r.ctx, serverActiveTimeout)
	defer cancel()
	return r.opts.Cloud.WaitServerActive(ctx, s.ProjectID, s.ID)
}

func (r *realizer) allocateFIPs() error {
	for _, vmID := range r.vmOrder {
		proj := r.vmProject[vmID]
		spec := r.opts.Scenario.FIPs[vmID]
		extNetID := r.extNetID
		if spec.ExternalNet != "" {
			id, err := r.opts.Cloud.FindExternalNetwork(r.ctx, spec.ExternalNet)
			if err != nil {
				return err
			}
			extNetID = id
		}
		id, addr, err := r.opts.Cloud.CreateFIP(r.ctx, proj, FIPCreateSpec{
			ExternalNetworkID: extNetID,
			PortID:            r.vmPort[vmID],
			FixedIP:           r.vmInternalIP[vmID],
			FloatingIP:        spec.FixedIP,
		})
		if err != nil {
			return err
		}
		r.rs.FIPs = append(r.rs.FIPs, FIPRef{VMID: vmID, ID: id, Address: addr, ProjectID: proj})
		if err := r.save(); err != nil {
			return err
		}
		r.logf("fip %s -> %s for vm %s", id, addr, vmID)
	}
	return nil
}

// attachGate blocks until the agents' summed attached-interface gauge
// has risen by expectedTaps over the baseline (one tap per new VM
// port) with no new attach failures, or the timeout fires. This is
// the only HTTP-visible attach signal — there is no per-interface
// surface — so it can be fooled by background tenant churn moving the
// count; that limitation is inherent and documented.
func (r *realizer) attachGate(baseline MetricsSnapshot, expectedTaps int) error {
	if expectedTaps == 0 {
		return nil
	}
	timeout := r.opts.AttachTimeout
	if timeout <= 0 {
		timeout = DefaultAttachTimeout
	}
	target := baseline.AttachedInterfaces + float64(expectedTaps)
	r.logf("attach gate: waiting for attached_interfaces ≥ %.0f (baseline %.0f + %d taps)", target, baseline.AttachedInterfaces, expectedTaps)

	ctx, cancel := context.WithTimeout(r.ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(attachPollInterval)
	defer ticker.Stop()
	for {
		snap, err := sampleAcross(ctx, r.opts.Metrics, agentURLs(r.opts.Config))
		if err != nil {
			return fmt.Errorf("attach gate scrape: %w", err)
		}
		if snap.AttachFailures > baseline.AttachFailures {
			return fmt.Errorf("attach gate: %0.f new TC attach failure(s) since baseline", snap.AttachFailures-baseline.AttachFailures)
		}
		if snap.AttachedInterfaces >= target {
			r.logf("attach gate: green (attached_interfaces %.0f ≥ %.0f)", snap.AttachedInterfaces, target)
			// Record the green state so a standalone `drive` can
			// re-confirm the taps are still attached before traffic.
			r.rs.Attach = AttachRecord{Target: target, Failures: snap.AttachFailures}
			return r.save()
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("attach gate: attached_interfaces %.0f < %.0f before timeout: %w", snap.AttachedInterfaces, target, ctx.Err())
		case <-ticker.C:
		}
	}
}

// --- helpers ---

func (r *realizer) prefix() string { return r.opts.Config.Naming.Prefix }

func (r *realizer) save() error {
	return r.rs.Save(r.opts.StatePath)
}

func (r *realizer) logf(format string, args ...any) {
	fmt.Fprintf(r.opts.Log, format+"\n", args...)
}

// projectID resolves a DSL project name to its live Keystone ID,
// reusing or creating per policy and caching the result in run-state.
// The admin user is granted the admin role on the project in both
// paths — creation grants its creator nothing, and re-granting on
// reuse is idempotent in Keystone, so a run that crashed between
// create and grant heals on the next attempt instead of failing
// token scoping with an opaque auth error.
func (r *realizer) projectID(dslName string) (string, error) {
	if ref, ok := r.rs.Projects[dslName]; ok {
		return ref.ID, nil
	}
	mangled := MangleProject(r.prefix(), dslName)
	id, found, err := r.opts.Cloud.FindProject(r.ctx, mangled)
	if err != nil {
		return "", err
	}
	policy := r.opts.Scenario.Projects[dslName]
	if found && policy == ForceFresh {
		return "", fmt.Errorf("project %q exists but scenario policy is ForceFresh", mangled)
	}
	created := false
	if !found {
		if id, err = r.opts.Cloud.CreateProject(r.ctx, mangled); err != nil {
			return "", err
		}
		created = true
	}
	if err := r.opts.Cloud.GrantAdminRole(r.ctx, id); err != nil {
		return "", err
	}
	r.rs.Projects[dslName] = ProjectRef{Name: mangled, ID: id, Created: created}
	if err := r.save(); err != nil {
		return "", err
	}
	r.logf("project %s -> %s (created=%v)", dslName, id, created)
	return id, nil
}
