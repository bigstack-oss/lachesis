// Package down tears a realized scenario back down: every resource the
// run-state records, in dependency order, idempotently. It never
// deletes a project, and it never deletes the run-state or report
// files — the evidence outlives the topology.
package down

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
)

// Options bundles everything `down` needs to tear a realized
// topology back down.
type Options struct {
	Config    scenariotest.Config
	State     *scenariotest.RunState
	StatePath string
	Cloud     scenariotest.Cloud
	Log       *slog.Logger
}

// Run deletes everything the run-state records, in reverse creation
// order and idempotently, so a re-run after a partial failure
// converges. Errors are collected, not fatal. Three things are never
// touched: projects, the run-state file, and the assert report — the
// evidence outlives the topology.
//
// The order is forced by Neutron's own dependencies: FIPs (by exact
// recorded ID, never a listing) → servers (waited gone, so taps vanish
// before ports) → router routes → router interfaces → ports → routers →
// a residual port sweep per network (platform ports appear in no
// run-state but block deletion) → subnets → networks.
func Run(ctx context.Context, opts Options) error {
	if opts.Log == nil {
		opts.Log = slog.New(slog.DiscardHandler)
	}
	d := &downer{ctx: ctx, opts: opts}
	rs := opts.State
	opts.Log.Info("tearing down",
		"load_balancers", len(rs.LoadBalancers),
		"fips", len(rs.FIPs), "servers", len(rs.Servers), "ports", len(rs.Ports),
		"routers", len(rs.Routers), "subnets", len(rs.Subnets), "networks", len(rs.Networks))

	// Load balancers first: a cascade delete reclaims the Amphora VMs
	// and every port Octavia plugged for them. Deleting those ports
	// directly would leave Octavia's records dangling, and leaving them
	// would block the subnet deletes further down.
	for _, lb := range rs.LoadBalancers {
		d.do("delete load balancer "+lb.Name, func() error {
			return d.opts.Cloud.DeleteLoadBalancer(ctx, lb.ProjectID, lb.ID)
		})
	}
	for _, f := range rs.FIPs {
		d.do("fip "+f.Address, func() error { return opts.Cloud.DeleteFIP(ctx, f.ProjectID, f.ID) })
	}
	for _, s := range rs.Servers {
		d.do("server "+s.DSLID, func() error {
			if err := opts.Cloud.DeleteServer(ctx, s.ProjectID, s.ID); err != nil {
				return err
			}
			return opts.Cloud.WaitServerGone(ctx, s.ProjectID, s.ID)
		})
	}
	// Residual server sweep: a server Nova accepted in the create→save
	// window is recorded nowhere, so the loop above cannot reach it and
	// the sweeps below would strand it on no network, surviving every
	// `down`. Scoped to this run's projects AND its exact run id — the
	// mangled prefix is collision-free, so the listing can never reach
	// a sibling run sharing the project. Runs BEFORE port teardown, or
	// Neutron 409s the bound-port delete.
	runPrefix := scenariotest.Mangle(rs.Prefix, rs.RunID, "")
	for _, proj := range rs.Projects {
		found, err := opts.Cloud.ListProjectServers(ctx, proj.ID)
		if err != nil {
			d.errs = append(d.errs, err)
			continue
		}
		for _, srv := range found {
			if !strings.HasPrefix(srv.Name, runPrefix) {
				continue
			}
			d.do("residual server "+srv.ID+" in "+proj.Name, func() error {
				if err := opts.Cloud.DeleteServer(ctx, proj.ID, srv.ID); err != nil {
					return err
				}
				return opts.Cloud.WaitServerGone(ctx, proj.ID, srv.ID)
			})
		}
	}
	// Routes clear before any interface detach: a static route pins the
	// interface its next-hop sits on, so Neutron 409s the detach with
	// RouterInterfaceInUseByRoute while the route stands (observed on
	// cross-tenant-routed's transit interfaces). The clear is 404-
	// tolerant and a no-op on a route-free router, so it re-runs safely.
	for _, r := range rs.Routers {
		d.do("clear routes "+r.DSLID, func() error {
			return opts.Cloud.ClearRouterRoutes(ctx, r.ProjectID, r.ID)
		})
	}
	// Interfaces detach before ports and routers die: a subnet-based
	// detach frees the gateway, a port-based detach frees a transit
	// port (Neutron deletes the interface port itself; the follow-up
	// port delete then 404s harmlessly).
	for _, r := range rs.Routers {
		for _, s := range rs.Subnets {
			d.do("detach "+r.DSLID+"/"+s.DSLID, func() error {
				return opts.Cloud.RemoveRouterInterface(ctx, r.ProjectID, r.ID, s.ID, "")
			})
		}
		for _, p := range rs.Ports {
			d.do("detach "+r.DSLID+"/"+p.DSLID, func() error {
				return opts.Cloud.RemoveRouterInterface(ctx, r.ProjectID, r.ID, "", p.ID)
			})
		}
	}
	for _, p := range rs.Ports {
		d.do("port "+p.DSLID, func() error { return opts.Cloud.DeletePort(ctx, p.ProjectID, p.ID) })
	}
	for _, r := range rs.Routers {
		d.do("router "+r.DSLID, func() error { return opts.Cloud.DeleteRouter(ctx, r.ProjectID, r.ID) })
	}
	// Residual sweep, scoped strictly to the scenario's own networks.
	for _, n := range rs.Networks {
		ids, err := opts.Cloud.ListNetworkPorts(ctx, n.ID)
		if err != nil {
			d.errs = append(d.errs, err)
			continue
		}
		for _, id := range ids {
			d.do("residual port "+id+" on "+n.DSLID, func() error {
				return opts.Cloud.DeletePort(ctx, n.ProjectID, id)
			})
		}
	}
	for _, s := range rs.Subnets {
		d.do("subnet "+s.DSLID, func() error { return opts.Cloud.DeleteSubnet(ctx, s.ProjectID, s.ID) })
	}
	for _, n := range rs.Networks {
		d.do("network "+n.DSLID, func() error { return opts.Cloud.DeleteNetwork(ctx, n.ProjectID, n.ID) })
	}

	if len(d.errs) > 0 {
		return fmt.Errorf("down: %d step(s) failed (re-run to converge): %w", len(d.errs), errors.Join(d.errs...))
	}
	rs.TornDown = true
	if err := rs.Save(opts.StatePath); err != nil {
		return err
	}
	opts.Log.Info("down complete: run-state and report files kept", "projects_kept", len(rs.Projects))
	return nil
}

// downer accumulates step failures so one stuck resource doesn't
// strand everything behind it.
type downer struct {
	ctx  context.Context
	opts Options
	errs []error
}

func (d *downer) do(what string, f func() error) {
	if err := f(); err != nil {
		d.errs = append(d.errs, err)
		d.opts.Log.Warn("down: step failed", "what", what, "err", err)
		return
	}
	d.opts.Log.Debug("down: ok", "what", what)
}
