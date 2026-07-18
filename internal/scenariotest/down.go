package scenariotest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
)

// DownOptions bundles everything `down` needs to tear a realized
// topology back down.
type DownOptions struct {
	Config    Config
	State     *RunState
	StatePath string
	Cloud     Cloud
	Log       *slog.Logger
}

// Down deletes everything the run-state records, in reverse creation
// order, idempotently: every delete tolerates already-gone (a re-run
// after a partial failure converges), errors are collected rather
// than aborting the pass, and three things are never touched —
// projects (policy: reuse-or-create, never delete), the run-state
// file, and the assert report (the evidence outlives the topology).
//
// Order: FIPs (exact recorded IDs only — never a listing) → servers
// (wait until gone; their taps must vanish before ports die) →
// router routes (a route pins the interface its next-hop sits on) →
// router interfaces (subnet- and port-based) → recorded ports →
// routers (Neutron drops the gateway port itself) → a residual port
// sweep scoped to each scenario network (platform-created ports like
// CubeCOS's cube:mgr appear in no run-state but block deletion) →
// subnets → networks.
func Down(ctx context.Context, opts DownOptions) error {
	if opts.Log == nil {
		opts.Log = slog.New(slog.DiscardHandler)
	}
	d := &downer{ctx: ctx, opts: opts}
	rs := opts.State
	opts.Log.Info("tearing down",
		"fips", len(rs.FIPs), "servers", len(rs.Servers), "ports", len(rs.Ports),
		"routers", len(rs.Routers), "subnets", len(rs.Subnets), "networks", len(rs.Networks))

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
	// window (the process died after the boot call returned, before the
	// state save) is recorded nowhere, so the loop above can't reach it
	// and the port/network sweeps below would strand it — the port sweep
	// frees its network out from under it, leaving a live VM on no
	// network that survives every `down`. Mirror the residual-port
	// sweep, but scope it to the run's own projects AND to servers whose
	// name carries this exact run id: the mangled prefix
	// "<prefix>-<runID>-" is collision-free by construction, so the
	// listing can never reach a sibling run reusing the same project
	// (projects are shared across runs) or another tenant. This runs
	// before the port teardown so a swept server's tap vanishes before
	// `down` deletes the (recorded) port it sat on — Neutron 409s a
	// bound-port delete otherwise.
	runPrefix := Mangle(rs.Prefix, rs.RunID, "")
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
	opts DownOptions
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
