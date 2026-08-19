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

// SetRouterRoutesStep replaces a router's static routes mid-run.
// Routes wholly replaces the set; an empty slice clears it.
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
// DSL external network mid-run. Flows on a changed router MAC settle
// under their OLD label first, so the external_network series stays
// monotone across the move.
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

// AddRouteStep adds an in-guest static route on a VM, steering traffic
// through a specific router. The platform cannot see in-guest routes,
// which is the point: per-flow router-MAC attribution must still label
// the traffic by the router that carried it.
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
// sysctls, not one: `ip_forward=1`, and `rp_filter=0`.
//
// rp_filter is the one that fails silently. A forwarded packet arrives
// on the transit NIC carrying the ORIGINAL source address, and the
// appliance has no route back to that subnet via that NIC — so with
// rp_filter on, Linux drops it before forwarding and no counter moves
// anywhere, which reads exactly like the platform never delivered the
// traffic.
//
// The forwarded packet keeps the original source IP, so the egress port
// must ALSO have port security off or OVN anti-spoofing drops it.
//
// docs/architecture/trie-construction.md#the-static-route-resolver
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
	// Straight to /proc: cirros has no sysctl in sudo's PATH. Both
	// values are read back so an ignored write fails HERE, not as a
	// mystifying zero-delta later. Every conf/*/rp_filter, not just
	// conf/all — the kernel takes max(all, <dev>).
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

// DeleteFIPStep removes the floating IPs a prior [AssociateFIPStep]
// bound to VM. The provider-net SSH FIP is never touched unless
// Provider is set — which targets exactly it, so Neutron will allow a
// gateway change. That sacrifices SSH, so only steps that drive nothing
// afterward use it.
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
