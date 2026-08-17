// Package realize stands a scenario's declared topology up on the live
// cluster and blocks until the agents have attached to the new taps.
// It writes run-state after every created resource, so a partial
// failure still leaves a record [down] can clean up.
package realize

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/bigstack-oss/lachesis/internal/neutron"
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// Options bundles everything `up` needs to stand a scenario up.
type Options struct {
	Config    scenariotest.Config
	Scenario  *scenariotest.Scenario
	RunID     string
	StatePath string
	Cloud     scenariotest.Cloud
	Metrics   scenariotest.MetricsSource
	Log       *slog.Logger

	// AttachTimeout bounds the attach-ready gate. Zero uses
	// [scenariotest.DefaultAttachTimeout].
	AttachTimeout time.Duration
}

// Run stands the scenario's topology up on the live cluster and
// blocks until the agents have attached to the new taps. It writes
// run-state to opts.StatePath after every created resource, so a
// partial failure still leaves a record `down` can clean up. It never
// deletes a project. The returned scenariotest.RunState is the realized topology.
func Run(ctx context.Context, opts Options) (*scenariotest.RunState, error) {
	if opts.Log == nil {
		opts.Log = slog.New(slog.DiscardHandler)
	}
	r := &realizer{
		ctx:           ctx,
		opts:          opts,
		rs:            scenariotest.NewRunState(opts.RunID, opts.Scenario.Name, opts.Config.Naming.Prefix),
		netLive:       map[string]string{},
		netExternal:   map[string]bool{},
		subnetLive:    map[string]string{},
		subnetGateway: map[string]string{},
		routerLive:    map[string]string{},
		vmPort:        map[string]string{},
		lbVIP:         map[string]string{},
		vmExtraPorts:  map[string][]string{},
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
	opts Options
	rs   *scenariotest.RunState

	// resolved prerequisites (live IDs)
	extNetID   string
	flavorID   string
	imageID    string
	secGroupID string
	// lbFlavorID is the resolved Octavia flavor, empty unless the
	// scenario declares a load balancer needing a non-default topology.
	lbFlavorID string

	// DSL id → live id maps
	netLive       map[string]string // external DSL nets map to the real external net
	netExternal   map[string]bool
	subnetLive    map[string]string
	subnetGateway map[string]string // DSL subnet id → its DSL gateway IP
	routerLive    map[string]string

	vmPort       map[string]string   // VM DSL id → primary live port id (eth0, FIP-fronted)
	vmExtraPorts map[string][]string // VM DSL id → additional NIC live port ids (eth1…)
	vmProject    map[string]string   // VM DSL id → project id
	vmInternalIP map[string]string
	vmOrder      []string // VM DSL ids (one per server) in creation order
	taps         int      // total VM ports created — one tap each, the attach-gate target

	// lbVIP maps a load balancer's DSL id to the VIP Octavia assigned —
	// the address a VIPTarget flow resolves to.
	lbVIP map[string]string

	// placement is scenariotest.Scenario.Placement with "node:<i>" slots resolved
	// to configured agent hosts; set before any resource is created.
	placement scenariotest.Placement
}

func (r *realizer) run() error {
	snap := r.opts.Scenario.Builder.Build()
	r.opts.Log.Info("realizing topology",
		"networks", len(snap.Networks), "subnets", len(snap.Subnets),
		"routers", len(snap.Routers), "ports", len(snap.Ports))

	// Resolve placement slots first: a scenario asking for more nodes
	// than the config lists must fail with nothing created yet.
	placement, err := scenariotest.ResolvePlacement(r.opts.Scenario.Placement, r.opts.Config.Cluster.Agents)
	if err != nil {
		return err
	}
	r.placement = placement
	// Recorded in the run-state (saved with the first create) so the
	// file stands alone as placement evidence and deferred boots reuse
	// the resolution.
	r.rs.Placement = placement

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

	// scenariotest.Capture the attach baseline now: VM ports exist but are unbound,
	// so no taps yet. Booting binds them and taps appear.
	baseline, err := scenariotest.SampleAcross(r.ctx, r.opts.Metrics, r.opts.Config.Cluster.Agents)
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
	if err := r.loadBalancers(snap); err != nil {
		return err
	}
	if err := r.attachGate(baseline, r.taps); err != nil {
		return err
	}
	r.opts.Log.Info("up complete", "vms", len(r.vmOrder), "taps", r.taps, "state", r.opts.StatePath)
	return nil
}

func (r *realizer) resolvePrereqs() error {
	p := r.opts.Config.Prerequisites
	var err error
	// The Octavia flavor is resolved only when a declared load balancer
	// needs a non-default topology: the Amphora count comes from the
	// flavor's loadbalancer_topology, not from any per-LB argument. A
	// cluster with none staged never reaches here — SkipReason turns
	// that into a SKIPPED scenario.
	if scenariotest.NeedsLBFlavor(r.opts.Scenario) {
		if r.lbFlavorID, err = r.opts.Cloud.FindLBFlavor(r.ctx, p.LBFlavorName); err != nil {
			return fmt.Errorf("resolve lb flavor %q: %w", p.LBFlavorName, err)
		}
	}
	if r.extNetID, err = r.opts.Cloud.FindExternalNetwork(r.ctx, p.ExternalNetworkName); err != nil {
		return err
	}
	if r.flavorID, err = r.opts.Cloud.FindFlavor(r.ctx, scenariotest.FlavorFor(r.opts.Config, r.opts.Scenario)); err != nil {
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
	created := make(map[string]bool, len(r.opts.Scenario.CreateExternalNets))
	for _, id := range r.opts.Scenario.CreateExternalNets {
		created[id] = true
	}
	for _, n := range snap.Networks {
		// External networks are normally never created — the router
		// gateways to the real provider external network, and so do
		// the VMs' FIPs. [scenariotest.Scenario.CreateExternalNets] opts a marker
		// out: it is created as a segmentless `router:external`
		// network (FIP-allocatable, no wire traffic) and its subnets
		// realize like any tenant subnet.
		if n.IsExternal && !created[n.ID] {
			r.netLive[n.ID] = r.extNetID
			r.netExternal[n.ID] = true
			continue
		}
		proj, err := r.projectID(n.ProjectID)
		if err != nil {
			return err
		}
		name := scenariotest.Mangle(r.prefix(), r.opts.RunID, n.ID)
		id, err := r.opts.Cloud.CreateNetwork(r.ctx, proj, scenariotest.NetworkSpec{Name: name, Shared: n.Shared, External: n.IsExternal})
		if err != nil {
			return err
		}
		r.netLive[n.ID] = id
		r.rs.Networks = append(r.rs.Networks, scenariotest.ResourceRef{DSLID: n.ID, ID: id, Name: name, ProjectID: proj})
		if err := r.save(); err != nil {
			return err
		}
		r.opts.Log.Debug("network ready", "dsl", n.ID, "id", id)
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
		name := scenariotest.Mangle(r.prefix(), r.opts.RunID, s.ID)
		id, err := r.opts.Cloud.CreateSubnet(r.ctx, proj, scenariotest.SubnetSpec{
			Name:      name,
			NetworkID: r.netLive[s.NetworkID],
			CIDR:      s.CIDR,
			GatewayIP: s.GatewayIP,
		})
		if err != nil {
			return err
		}
		r.subnetLive[s.ID] = id
		r.rs.Subnets = append(r.rs.Subnets, scenariotest.ResourceRef{DSLID: s.ID, ID: id, Name: name, ProjectID: proj})
		if err := r.save(); err != nil {
			return err
		}
		r.opts.Log.Debug("subnet ready", "dsl", s.ID, "id", id)
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
		name := scenariotest.Mangle(r.prefix(), r.opts.RunID, rt.ID)
		id, err := r.opts.Cloud.CreateRouter(r.ctx, proj, scenariotest.RouterSpec{Name: name, ExternalNetworkID: extID})
		if err != nil {
			return err
		}
		r.routerLive[rt.ID] = id
		r.rs.Routers = append(r.rs.Routers, scenariotest.ResourceRef{DSLID: rt.ID, ID: id, Name: name, ProjectID: proj})
		if err := r.save(); err != nil {
			return err
		}
		r.opts.Log.Debug("router ready", "dsl", rt.ID, "id", id)
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
		routes := make([]scenariotest.RouteSpec, len(rt.Routes))
		for i, rr := range rt.Routes {
			routes[i] = scenariotest.RouteSpec{Destination: rr.Destination, Nexthop: rr.Nexthop}
		}
		if err := r.opts.Cloud.SetRouterRoutes(r.ctx, proj, r.routerLive[rt.ID], routes); err != nil {
			return err
		}
		r.opts.Log.Debug("router routes set", "dsl", rt.ID, "routes", len(routes))
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
			r.opts.Log.Debug("router interface ready", "dsl", p.ID, "router", p.DeviceID, "subnet", fip.SubnetID, "via", "gateway")
			continue
		}

		name := scenariotest.Mangle(r.prefix(), r.opts.RunID, p.ID)
		portID, err := r.opts.Cloud.CreatePort(r.ctx, proj, scenariotest.PortSpec{
			Name:      name,
			NetworkID: r.netLive[p.NetworkID],
			SubnetID:  subnetID,
			FixedIP:   fip.IPAddress,
		})
		if err != nil {
			return err
		}
		mac, err := r.opts.Cloud.PortMAC(r.ctx, portID)
		if err != nil {
			return err
		}
		r.rs.Ports = append(r.rs.Ports, scenariotest.ResourceRef{DSLID: p.ID, ID: portID, Name: name, ProjectID: proj, MAC: mac, RouterInterface: true})
		if err := r.save(); err != nil {
			return err
		}
		if err := r.opts.Cloud.AddRouterInterface(r.ctx, proj, routerID, "", portID); err != nil {
			return err
		}
		r.opts.Log.Debug("router interface ready", "dsl", p.ID, "router", p.DeviceID, "port", portID, "ip", fip.IPAddress)
	}
	return nil
}

// vmPorts creates a Neutron port for every non-deferred compute port
// and groups them by server identity (the shared DeviceID) so a
// multi-homed VM — one [scenario.Builder.NIC] call per extra NIC — becomes ONE
// server carrying several ports. The primary port (DSL id == the VM
// id, i.e. DeviceID without its "-instance" suffix) is eth0, the one
// [allocateFIPs] fronts; the rest are extras. Single-NIC VMs (the
// common case) take the primary path exactly as before.
func (r *realizer) vmPorts(snap neutron.Snapshot) error {
	deferred := make(map[string]bool, len(r.opts.Scenario.Deferred))
	for _, id := range r.opts.Scenario.Deferred {
		deferred[id] = true
	}
	amphora := amphoraComputes(snap)
	for _, p := range snap.Ports {
		if !strings.HasPrefix(p.DeviceOwner, "compute:") {
			continue
		}
		// An Amphora's ports are declared by the DSL so the unit tier
		// sees the real shape, but live they are Octavia's to create —
		// it boots the VM and plugs every NIC itself. Creating them here
		// would collide with the ones Octavia makes.
		if amphora[p.DeviceID] {
			continue
		}
		vmID := strings.TrimSuffix(p.DeviceID, "-instance")
		// A deferred VM with extra NICs is unsupported: BootVMStep boots
		// only the primary port, so the extras would vanish silently.
		// Fail loudly at realize instead (docs: deferred VMs are
		// single-NIC).
		if deferred[vmID] && p.ID != vmID {
			return fmt.Errorf("vm %q is Deferred but declares an extra NIC (%s); deferred VMs are single-NIC (BootVMStep boots only the primary port)", vmID, p.ID)
		}
		// Deferred VMs are declared but not realized: no port, no
		// server, no FIP, no attach-gate slot. A a BootVMStep creates
		// them mid-script. Keyed by the VM id, so a NIC on a deferred VM
		// is deferred with it.
		if deferred[vmID] {
			r.opts.Log.Debug("vm deferred (booted by a later step)", "vm", vmID, "port", p.ID)
			continue
		}
		proj, err := r.projectID(p.ProjectID)
		if err != nil {
			return err
		}
		fip := p.FixedIPs[0]
		name := scenariotest.Mangle(r.prefix(), r.opts.RunID, p.ID)
		portID, err := r.opts.Cloud.CreatePort(r.ctx, proj, scenariotest.PortSpec{
			Name:       name,
			NetworkID:  r.netLive[p.NetworkID],
			SubnetID:   r.subnetLive[fip.SubnetID],
			FixedIP:    fip.IPAddress,
			SecGroupID: r.secGroupID,
		})
		if err != nil {
			return err
		}
		mac, err := r.opts.Cloud.PortMAC(r.ctx, portID)
		if err != nil {
			return err
		}
		r.taps++
		r.rs.Ports = append(r.rs.Ports, scenariotest.ResourceRef{DSLID: p.ID, ID: portID, Name: name, ProjectID: proj, MAC: mac})
		if p.ID == vmID {
			// Primary NIC: this is the server, tracked for boot + FIP.
			r.vmPort[vmID] = portID
			r.vmProject[vmID] = proj
			r.vmInternalIP[vmID] = fip.IPAddress
			r.vmOrder = append(r.vmOrder, vmID)
		} else {
			r.vmExtraPorts[vmID] = append(r.vmExtraPorts[vmID], portID)
		}
		if err := r.save(); err != nil {
			return err
		}
		r.opts.Log.Debug("vm port ready", "vm", vmID, "port", portID, "ip", fip.IPAddress, "primary", p.ID == vmID)
	}
	return nil
}

func (r *realizer) bootServers() error {
	for _, vmID := range r.vmOrder {
		proj := r.vmProject[vmID]
		name := scenariotest.Mangle(r.prefix(), r.opts.RunID, vmID)
		// No security group here: the VM boots on a pre-created port
		// that already carries it, and Nova ignores boot-time secgroups
		// for pre-existing ports anyway.
		id, err := r.opts.Cloud.CreateServer(r.ctx, proj, scenariotest.ServerSpec{
			Name:             name,
			FlavorID:         r.flavorID,
			ImageID:          r.imageID,
			PortID:           r.vmPort[vmID],
			ExtraPortIDs:     r.vmExtraPorts[vmID],
			KeypairName:      r.opts.Config.Prerequisites.KeypairName,
			AvailabilityZone: scenariotest.PlacementAZ(r.placement, vmID),
		})
		if err != nil {
			return err
		}
		r.rs.Servers = append(r.rs.Servers, scenariotest.ResourceRef{DSLID: vmID, ID: id, Name: name, ProjectID: proj})
		if err := r.save(); err != nil {
			return err
		}
		r.opts.Log.Info("server booting", "vm", vmID, "id", id)
	}
	return nil
}

func (r *realizer) waitActive() error {
	for _, s := range r.rs.Servers {
		if err := r.waitOneActive(s); err != nil {
			return err
		}
		r.opts.Log.Info("server active", "vm", s.DSLID)
	}
	return nil
}

// waitOneActive bounds a single server's boot wait with
// [scenariotest.ServerActiveTimeout] so a server stuck in BUILD fails the run
// instead of hanging it.
func (r *realizer) waitOneActive(s scenariotest.ResourceRef) error {
	ctx, cancel := context.WithTimeout(r.ctx, scenariotest.ServerActiveTimeout)
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
		id, addr, err := r.opts.Cloud.CreateFIP(r.ctx, proj, scenariotest.FIPCreateSpec{
			ExternalNetworkID: extNetID,
			PortID:            r.vmPort[vmID],
			FixedIP:           r.vmInternalIP[vmID],
			FloatingIP:        spec.FixedIP,
		})
		if err != nil {
			return err
		}
		r.rs.FIPs = append(r.rs.FIPs, scenariotest.FIPRef{VMID: vmID, ID: id, Address: addr, ProjectID: proj})
		if err := r.save(); err != nil {
			return err
		}
		r.opts.Log.Debug("fip ready", "id", id, "addr", addr, "vm", vmID)
	}
	return nil
}

// attachGate blocks until the agents' summed attached-interface gauge
// has risen by expectedTaps over the baseline (one tap per new VM
// port) with no new attach failures, or the timeout fires. This is
// the only HTTP-visible attach signal — there is no per-interface
// surface — so it can be fooled by background tenant churn moving the
// count; that limitation is inherent and documented.
func (r *realizer) attachGate(baseline scenariotest.MetricsSnapshot, expectedTaps int) error {
	if expectedTaps == 0 {
		return nil
	}
	timeout := r.opts.AttachTimeout
	if timeout <= 0 {
		timeout = scenariotest.DefaultAttachTimeout
	}
	target := baseline.AttachedInterfaces + float64(expectedTaps)
	r.opts.Log.Info("attach gate: waiting", "target", target, "baseline", baseline.AttachedInterfaces, "taps", expectedTaps)

	ctx, cancel := context.WithTimeout(r.ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(scenariotest.AttachPollInterval)
	defer ticker.Stop()
	for {
		snap, err := scenariotest.SampleAcross(ctx, r.opts.Metrics, r.opts.Config.Cluster.Agents)
		if err != nil {
			return fmt.Errorf("attach gate scrape: %w", err)
		}
		if snap.AttachFailures > baseline.AttachFailures {
			return fmt.Errorf("attach gate: %0.f new TC attach failure(s) since baseline", snap.AttachFailures-baseline.AttachFailures)
		}
		if snap.AttachedInterfaces >= target {
			r.opts.Log.Info("attach gate: green", "attached", snap.AttachedInterfaces, "target", target)
			// Record the green state so a standalone `drive` can
			// re-confirm the taps are still attached before traffic.
			r.rs.Attach = scenariotest.AttachRecord{Target: target, Failures: snap.AttachFailures}
			return r.save()
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("attach gate: attached_interfaces %.0f < %.0f before timeout: %w", snap.AttachedInterfaces, target, ctx.Err())
		case <-ticker.C:
		}
	}
}

// loadBalancers creates every Octavia load balancer the topology
// declares, with its listener, pool and members, and records each in the
// run-state before waiting — an Amphora boot takes tens of seconds, and a
// crash in that window must still leave `down` able to reclaim it.
//
// Runs after the VMs are ACTIVE so pool members address real backends,
// and before the attach gate so the gate also waits for the Amphora taps
// to appear. Each Amphora contributes at least two taps (its management
// port and its VIP-subnet data port); a member on a foreign subnet adds
// another, but the gate's target is a minimum (>=), so counting the
// guaranteed two per Amphora never over-waits.
func (r *realizer) loadBalancers(snap neutron.Snapshot) error {
	if len(snap.LoadBalancers) == 0 {
		return nil
	}
	decls := make(map[string]scenario.LBDecl, len(snap.LoadBalancers))
	for _, d := range r.opts.Scenario.Builder.LoadBalancers() {
		decls[d.ID] = d
	}
	for _, lb := range snap.LoadBalancers {
		projectID, err := r.projectID(lb.ProjectID)
		if err != nil {
			return err
		}
		vipSubnet, err := r.vipSubnetFor(snap, lb.ID)
		if err != nil {
			return err
		}
		name := scenariotest.Mangle(r.prefix(), r.rs.RunID, lb.ID)
		id, vip, vipPortID, err := r.opts.Cloud.CreateLoadBalancer(r.ctx, projectID, scenariotest.LBSpec{
			Name:        name,
			VIPSubnetID: vipSubnet,
			FlavorID:    r.lbFlavorID,
		})
		if err != nil {
			return fmt.Errorf("create load balancer %s: %w", lb.ID, err)
		}
		r.rs.LoadBalancers = append(r.rs.LoadBalancers, scenariotest.ResourceRef{
			DSLID: lb.ID, ID: id, Name: name, ProjectID: projectID, VIP: vip,
		})
		r.lbVIP[lb.ID] = vip
		if err := r.save(); err != nil {
			return err
		}
		if err := r.opts.Cloud.WaitLBActive(r.ctx, projectID, id); err != nil {
			return err
		}
		// A floating IP on the VIP port is what lets a client reach the
		// load balancer from outside the cloud — the EXTERNAL Segment 1
		// path, which never touches the classifier's Amphora branch
		// (docs/architecture/octavia.md). Allocated after ACTIVE because
		// Octavia owns the VIP port until then.
		fipID, fipAddr, err := r.opts.Cloud.CreateFIP(r.ctx, projectID, scenariotest.FIPCreateSpec{
			ExternalNetworkID: r.extNetID,
			PortID:            vipPortID,
		})
		if err != nil {
			return fmt.Errorf("allocate floating ip for load balancer %s: %w", lb.ID, err)
		}
		// VMID names the load balancer rather than a VM: the FIP list is
		// keyed by DSL id, and `down` releases by allocation id anyway.
		r.rs.FIPs = append(r.rs.FIPs, scenariotest.FIPRef{
			VMID: lb.ID, ID: fipID, ProjectID: projectID, Address: fipAddr,
		})
		r.rs.LoadBalancers[len(r.rs.LoadBalancers)-1].FIP = fipAddr
		if err := r.save(); err != nil {
			return err
		}
		if err := r.lbBackends(projectID, id, decls[lb.ID]); err != nil {
			return err
		}
		amps, err := r.opts.Cloud.ListAmphorae(r.ctx, id)
		if err != nil {
			return err
		}
		r.taps += 2 * len(amps)
		r.opts.Log.Info("load balancer active",
			"lb", lb.ID, "vip", vip, "amphorae", len(amps))
	}
	return nil
}

// lbBackends adds the listener, pool and members a load balancer needs.
// Members are created last and each is checked afterwards, because a
// member on a subnet the Amphora is not attached to makes Octavia
// hot-plug a NIC — and that plug can fail (no free PCIe slot on the
// guest) while the load balancer itself stays ACTIVE.
func (r *realizer) lbBackends(projectID, lbID string, d scenario.LBDecl) error {
	listenerID, err := r.opts.Cloud.CreateListener(r.ctx, projectID, scenariotest.ListenerSpec{
		Name:           scenariotest.Mangle(r.prefix(), r.rs.RunID, d.ID+"-listener"),
		LoadBalancerID: lbID,
		Protocol:       d.Protocol,
		ProtocolPort:   d.Port,
	})
	if err != nil {
		return fmt.Errorf("create listener for %s: %w", d.ID, err)
	}
	poolID, err := r.opts.Cloud.CreatePool(r.ctx, projectID, scenariotest.PoolSpec{
		Name:        scenariotest.Mangle(r.prefix(), r.rs.RunID, d.ID+"-pool"),
		ListenerID:  listenerID,
		Protocol:    d.Protocol,
		LBAlgorithm: d.Algorithm,
	})
	if err != nil {
		return fmt.Errorf("create pool for %s: %w", d.ID, err)
	}
	for _, m := range d.Members {
		subnetID, ok := r.subnetLive[m.SubnetID]
		if !ok {
			return fmt.Errorf("load balancer %s: member subnet %s not realized", d.ID, m.SubnetID)
		}
		if _, err := r.opts.Cloud.CreateMember(r.ctx, projectID, scenariotest.MemberSpec{
			Name:         scenariotest.Mangle(r.prefix(), r.rs.RunID, d.ID+"-"+m.Address),
			PoolID:       poolID,
			Address:      m.Address,
			ProtocolPort: m.Port,
			SubnetID:     subnetID,
		}); err != nil {
			return fmt.Errorf("create member %s for %s: %w", m.Address, d.ID, err)
		}
		if err := r.opts.Cloud.WaitLBActive(r.ctx, projectID, lbID); err != nil {
			return err
		}
	}
	return nil
}

// vipSubnetFor finds the live subnet id the load balancer's VIP sits on,
// via the VIP reservation port the DSL emits ("<lb>-vip").
func (r *realizer) vipSubnetFor(snap neutron.Snapshot, lbID string) (string, error) {
	for _, p := range snap.Ports {
		if p.DeviceID != "lb-"+lbID || len(p.FixedIPs) == 0 {
			continue
		}
		live, ok := r.subnetLive[p.FixedIPs[0].SubnetID]
		if !ok {
			return "", fmt.Errorf("load balancer %s: VIP subnet %s not realized", lbID, p.FixedIPs[0].SubnetID)
		}
		return live, nil
	}
	return "", fmt.Errorf("load balancer %s: no VIP port in the topology", lbID)
}

// amphoraComputes is the set of Nova instance ids belonging to an
// Amphora — the ports realize must leave for Octavia to create.
func amphoraComputes(snap neutron.Snapshot) map[string]bool {
	out := make(map[string]bool, len(snap.Amphorae))
	for _, a := range snap.Amphorae {
		out[a.ComputeID] = true
	}
	return out
}

// --- helpers ---

func (r *realizer) prefix() string { return r.opts.Config.Naming.Prefix }

func (r *realizer) save() error {
	return r.rs.Save(r.opts.StatePath)
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
	mangled := scenariotest.MangleProject(r.prefix(), dslName)
	id, found, err := r.opts.Cloud.FindProject(r.ctx, mangled)
	if err != nil {
		return "", err
	}
	policy := r.opts.Scenario.Projects[dslName]
	if found && policy == scenariotest.ForceFresh {
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
	r.rs.Projects[dslName] = scenariotest.ProjectRef{Name: mangled, ID: id, Created: created}
	if err := r.save(); err != nil {
		return "", err
	}
	if created {
		r.opts.Log.Debug("project created", "dsl", dslName, "id", id)
	} else {
		r.opts.Log.Debug("project reused (kept across runs by policy)", "dsl", dslName, "id", id)
	}
	return id, nil
}
