// Neutron-mutation steps: floating IPs, router routes and gateways, and
// the in-guest routing that steers traffic onto them.

package steps

import (
	"context"
	"fmt"
	"strings"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/gate"
)

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
