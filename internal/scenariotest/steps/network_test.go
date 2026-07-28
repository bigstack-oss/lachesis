package steps

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/fake"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

func TestDeleteFIPStep_ProviderAndGuard(t *testing.T) {
	// vm-a carries two FIPs: the provider SSH FIP (Network "") and a
	// scenario-net FIP (Network "net-ext").
	newEnv := func() *scenariotest.StepEnv {
		return &scenariotest.StepEnv{
			Config: fake.Config(),
			State: &scenariotest.RunState{FIPs: []scenariotest.FIPRef{
				{VMID: "vm-a", ID: "fip-ssh", Address: "203.0.113.9", Network: ""},
				{VMID: "vm-a", ID: "fip-ext", Address: "203.0.113.10", Network: "net-ext"},
			}},
			StatePath: t.TempDir() + "/s.json",
			Cloud:     fake.NewCloud(&fake.Env{}),
			Log:       slog.New(slog.DiscardHandler),
		}
	}
	remaining := func(env *scenariotest.StepEnv) []string {
		var ids []string
		for _, f := range env.State.FIPs {
			ids = append(ids, f.ID)
		}
		return ids
	}

	// Provider deletes exactly the SSH FIP, keeps the scenario one.
	t.Run("provider targets the SSH FIP", func(t *testing.T) {
		env := newEnv()
		if err := (DeleteFIPStep{VM: "vm-a", Provider: true}).Run(context.Background(), env); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if got := remaining(env); len(got) != 1 || got[0] != "fip-ext" {
			t.Errorf("remaining FIPs = %v, want [fip-ext]", got)
		}
	})

	// A normal (non-provider) delete targets the named scenario net and
	// leaves the SSH FIP alone.
	t.Run("non-provider targets the named net", func(t *testing.T) {
		env := newEnv()
		if err := (DeleteFIPStep{VM: "vm-a", Network: "net-ext"}).Run(context.Background(), env); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if got := remaining(env); len(got) != 1 || got[0] != "fip-ssh" {
			t.Errorf("remaining FIPs = %v, want [fip-ssh]", got)
		}
	})

	// The guard: a non-provider delete with an empty Network must NOT
	// sacrifice the SSH FIP — it matches nothing, errors, and deletes none.
	t.Run("non-provider empty network spares the SSH FIP", func(t *testing.T) {
		env := newEnv()
		err := (DeleteFIPStep{VM: "vm-a", Network: ""}).Run(context.Background(), env)
		if err == nil || !strings.Contains(err.Error(), "no matching FIP") {
			t.Fatalf("want a no-match error, got %v", err)
		}
		if len(env.State.FIPs) != 2 {
			t.Errorf("no FIP should have been deleted, have %d", len(env.State.FIPs))
		}
	})
}

func TestSetRouterGatewayStep(t *testing.T) {
	build := func() *scenariotest.Scenario {
		b := scenario.New()
		b.Network("net-T1", "T1").Subnet("sub-T1", "10.0.42.0/24", "10.0.42.1").VM("vm-a", "T1", "10.0.42.5")
		b.ExternalNetwork("net-ext", "admin") // provider marker (not created)
		b.ExternalNetwork("net-ext2", "admin").Subnet("sub-ext2", "172.24.98.0/24", "172.24.98.1")
		b.Router("r-T1", "T1").Attach("sub-T1", "10.0.42.1").ExternalGateway("net-ext")
		return &scenariotest.Scenario{Name: "regw", Builder: b, CreateExternalNets: []string{"net-ext2"}}
	}
	newEnv := func(cloud *fake.Cloud, nets []scenariotest.ResourceRef) *scenariotest.StepEnv {
		return &scenariotest.StepEnv{
			Config:   fake.Config(),
			Scenario: build(),
			State: &scenariotest.RunState{
				Routers:  []scenariotest.ResourceRef{{DSLID: "r-T1", ID: "rtr-1", ProjectID: "uuid-t1"}},
				Networks: nets,
			},
			StatePath: t.TempDir() + "/s.json",
			Cloud:     cloud,
			Log:       slog.New(slog.DiscardHandler),
		}
	}

	// A created external net (net-ext2) resolves straight from run-state.
	t.Run("created net resolves from run-state", func(t *testing.T) {
		cloud := fake.NewCloud(&fake.Env{})
		env := newEnv(cloud, []scenariotest.ResourceRef{{DSLID: "net-ext2", ID: "netid-ext2"}})
		if err := (SetRouterGatewayStep{Router: "r-T1", ExternalNet: "net-ext2"}).Run(context.Background(), env); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if got := cloud.RouterExt["rtr-1"]; got != "netid-ext2" {
			t.Errorf("gateway = %q, want netid-ext2", got)
		}
	})

	// A provider-bound marker (net-ext, absent from run-state) falls back
	// to FindExternalNetwork — the round-trip re-gateway-BACK path.
	t.Run("provider marker falls back to the config external net", func(t *testing.T) {
		cloud := fake.NewCloud(&fake.Env{})
		cloud.ExtNetID = "provider-real"
		env := newEnv(cloud, nil)
		if err := (SetRouterGatewayStep{Router: "r-T1", ExternalNet: "net-ext"}).Run(context.Background(), env); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if got := cloud.RouterExt["rtr-1"]; got != "provider-real" {
			t.Errorf("gateway = %q, want provider-real", got)
		}
	})

	// An id that is neither a created net nor an external marker errors.
	t.Run("unknown network errors", func(t *testing.T) {
		env := newEnv(fake.NewCloud(&fake.Env{}), nil)
		err := (SetRouterGatewayStep{Router: "r-T1", ExternalNet: "net-nope"}).Run(context.Background(), env)
		if err == nil || !strings.Contains(err.Error(), "no live network") {
			t.Fatalf("want a no-live-network error, got %v", err)
		}
	})
}

// forwardExec answers the ip_forward read-back with a canned value; the
// ssh-ready probe ("true") gets an empty reply like the plain fake.
type forwardExec struct {
	Calls    []fake.ExecCall
	readback string
}

func (e *forwardExec) Run(_ context.Context, addr, command string) (string, error) {
	e.Calls = append(e.Calls, fake.ExecCall{Addr: addr, Command: command})
	if strings.Contains(command, "ip_forward") {
		return e.readback, nil
	}
	return "", nil
}

func TestSteps_EnableForwarding(t *testing.T) {
	// Happy path: the guest reports forwarding on, over the SSH FIP.
	t.Run("sets and verifies ip_forward", func(t *testing.T) {
		_, _, senv := nicFixture(t)
		exec := &forwardExec{readback: "1\n0\n"}
		senv.Exec = exec
		if err := (EnableForwardingStep{VM: "vm-a"}).Run(context.Background(), senv); err != nil {
			t.Fatalf("enable-forwarding: %v", err)
		}
		last := exec.Calls[len(exec.Calls)-1]
		if last.Addr != "203.0.113.9" {
			t.Errorf("ran over %s, want the SSH FIP", last.Addr)
		}
		for _, want := range []string{"ip_forward", "rp_filter", "sort -u"} {
			if !strings.Contains(last.Command, want) {
				t.Errorf("command lacks %q: %s", want, last.Command)
			}
		}
	})

	// The branch that matters: a sysctl that did not take (a per-device
	// rp_filter left at 1, a read-only /proc) must fail HERE, not as a
	// mystifying zero-delta at the appliance's tap — which is exactly how
	// it presented the first time this scenario ran live.
	t.Run("a surviving rp_filter fails", func(t *testing.T) {
		_, _, senv := nicFixture(t)
		senv.Exec = &forwardExec{readback: "1\n1\n"} // a per-device rp_filter survived
		err := (EnableForwardingStep{VM: "vm-a"}).Run(context.Background(), senv)
		if err == nil || !strings.Contains(err.Error(), "want [1 0]") {
			t.Fatalf("want a read-back error, got %v", err)
		}
	})

	// No SSH FIP is a scenario bug, caught before any exec.
	t.Run("missing FIP errors", func(t *testing.T) {
		_, _, senv := nicFixture(t)
		senv.State.FIPs = nil
		if err := (EnableForwardingStep{VM: "vm-a"}).Run(context.Background(), senv); err == nil {
			t.Error("missing SSH FIP must error")
		}
	})
}
