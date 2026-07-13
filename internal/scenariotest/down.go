package scenariotest

import (
	"context"
	"errors"
	"fmt"
	"io"
)

// DownOptions bundles everything `down` needs to tear a realized
// topology back down.
type DownOptions struct {
	Config    Config
	State     *RunState
	StatePath string
	Cloud     Cloud
	Log       io.Writer
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
// router interfaces (subnet- and port-based) → recorded ports →
// routers (Neutron drops the gateway port itself) → a residual port
// sweep scoped to each scenario network (platform-created ports like
// CubeCOS's cube:mgr appear in no run-state but block deletion) →
// subnets → networks.
func Down(ctx context.Context, opts DownOptions) error {
	if opts.Log == nil {
		opts.Log = io.Discard
	}
	d := &downer{ctx: ctx, opts: opts}
	rs := opts.State

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
	fmt.Fprintf(opts.Log, "down complete: %d project(s) kept by policy; run-state and report files kept\n", len(rs.Projects))
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
		fmt.Fprintf(d.opts.Log, "down: %s: %v\n", what, err)
		return
	}
	fmt.Fprintf(d.opts.Log, "down: %s ok\n", what)
}
