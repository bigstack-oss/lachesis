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

// nicMetrics reports the attach gauge from the fake cloud's live
// state: boots plus hot-plugged NICs, minus deleted servers — so the
// attach/detach gates in the NIC lifecycle steps resolve instantly and
// truthfully against what the step just did.
type nicMetrics struct {
	fake.InstantMACs
	Env   *fake.Env
	cloud *fake.Cloud

	Servers []scenariotest.ServerSample
	Ports   []scenariotest.PortSample
	settled float64
	ghosts  float64
}

func (m *nicMetrics) Scrape(context.Context, string) (scenariotest.ScrapeResult, error) {
	deleted := 0
	for k := range m.cloud.Deleted {
		if strings.HasPrefix(k, "server:") {
			deleted++
		}
	}
	return scenariotest.ScrapeResult{
		Present: map[string]bool{
			scenariotest.MetricBytesTotal: true, scenariotest.MetricAttachedInterfaces: true,
			scenariotest.MetricAttachFailures: true, scenariotest.MetricSettledFlows: true,
			scenariotest.MetricServerBytesTotal: true, scenariotest.MetricLingeringGhosts: true,
		},
		AttachedInterfaces: m.Env.BaseAttached + float64(m.Env.Booted) + float64(len(m.cloud.HotAttached)) - float64(deleted),
		AttachFailures:     m.Env.Failures,
		SettledFlows:       m.settled,
		PortBytes:          m.Ports,
		LingeringGhosts:    m.ghosts,
		Servers:            m.Servers,
	}, nil
}

// nicFixture is a live vm-a (booted through the fake cloud so the
// server binding is real) with a second DSL network for hot-plugging.
func nicFixture(t *testing.T) (*fake.Cloud, *nicMetrics, *scenariotest.StepEnv) {
	t.Helper()
	b := scenario.New()
	b.Network("net-a", "T1").Subnet("sub-a", "10.0.30.0/24", "10.0.30.1").VM("vm-a", "T1", "10.0.30.5")
	b.Network("net-b", "T1").Subnet("sub-b", "10.0.31.0/24", "10.0.31.1")
	sc := &scenariotest.Scenario{Name: "nic-lifecycle", Builder: b}

	env := &fake.Env{BaseAttached: 3}
	cloud := fake.NewCloud(env)
	bootPort, err := cloud.CreatePort(context.Background(), "uuid-t1", scenariotest.PortSpec{Name: "boot", NetworkID: "net-1"})
	if err != nil {
		t.Fatal(err)
	}
	srvID, err := cloud.CreateServer(context.Background(), "uuid-t1", scenariotest.ServerSpec{Name: "vm-a", PortID: bootPort})
	if err != nil {
		t.Fatal(err)
	}
	rs := &scenariotest.RunState{
		RunID:    "run1",
		Projects: map[string]scenariotest.ProjectRef{"T1": {Name: "T1", ID: "uuid-t1"}},
		Networks: []scenariotest.ResourceRef{{DSLID: "net-b", ID: "net-2"}},
		Subnets:  []scenariotest.ResourceRef{{DSLID: "sub-b", ID: "sub-2"}},
		Servers:  []scenariotest.ResourceRef{{DSLID: "vm-a", ID: srvID, ProjectID: "uuid-t1"}},
		FIPs:     []scenariotest.FIPRef{{VMID: "vm-a", Address: "203.0.113.9", ProjectID: "uuid-t1"}},
	}
	nm := &nicMetrics{Env: env, cloud: cloud}
	senv := &scenariotest.StepEnv{
		Config: fake.Config(), Scenario: sc, State: rs,
		StatePath: t.TempDir() + "/s.json",
		Cloud:     cloud, Metrics: nm, Exec: &fake.Exec{},
		Log:    slog.New(slog.DiscardHandler),
		Report: &scenariotest.AssertReport{OK: true},
	}
	return cloud, nm, senv
}

func TestSteps_NICLifecycle(t *testing.T) {
	cloud, _, senv := nicFixture(t)
	ctx := context.Background()

	// Attach: fresh port on net-b, recorded with MAC, gate target +1.
	if err := (AttachPortStep{VM: "vm-a", ID: "vm-a-nic2", Network: "net-b", Subnet: "sub-b", IP: "10.0.31.9"}).Run(ctx, senv); err != nil {
		t.Fatalf("attach: %v", err)
	}
	nicID := scenariotest.LiveID(senv.State.Ports, "vm-a-nic2")
	if nicID == "" {
		t.Fatal("attach recorded no nic ref")
	}
	var ref scenariotest.ResourceRef
	for _, p := range senv.State.Ports {
		if p.DSLID == "vm-a-nic2" {
			ref = p
		}
	}
	if ref.MAC == "" {
		t.Error("nic ref carries no MAC — the MAC-learn gate would skip it")
	}
	if got, want := senv.State.Attach.Target, senv.Metrics.(*nicMetrics).Env.BaseAttached+1+1; got != want {
		t.Errorf("attach gate target = %v, want %v", got, want)
	}
	if len(cloud.IfaceOps) != 1 || !strings.HasPrefix(cloud.IfaceOps[0], "attach:") {
		t.Fatalf("ifaceOps = %v, want one attach", cloud.IfaceOps)
	}

	// A bound port must refuse deletion until detached.
	if err := cloud.DeletePort(ctx, "uuid-t1", nicID); err == nil {
		t.Error("DeletePort on an attached port must fail")
	}

	// Detach (keep the port): ref stays, attach record re-baselined down.
	if err := (DetachPortStep{VM: "vm-a", Port: "vm-a-nic2"}).Run(ctx, senv); err != nil {
		t.Fatalf("detach: %v", err)
	}
	if scenariotest.LiveID(senv.State.Ports, "vm-a-nic2") == "" {
		t.Error("detach without Delete must keep the ref")
	}
	// The detached MAC is recorded so a following AwaitSweepStep{ForMACOf}
	// can wait for its fold — even once Delete drops the ref.
	if senv.RecordedMAC("vm-a-nic2") != ref.MAC {
		t.Errorf("detach must record the MAC: RecordedMAC(vm-a-nic2)=%q, want %q", senv.RecordedMAC("vm-a-nic2"), ref.MAC)
	}
	if got, want := senv.State.Attach.Target, senv.Metrics.(*nicMetrics).Env.BaseAttached+1; got != want {
		t.Errorf("post-detach attach target = %v, want %v", got, want)
	}

	// Reattach the same port, then detach+delete it.
	if err := (ReattachPortStep{VM: "vm-a", Port: "vm-a-nic2"}).Run(ctx, senv); err != nil {
		t.Fatalf("reattach: %v", err)
	}
	if err := (DetachPortStep{VM: "vm-a", Port: "vm-a-nic2", Delete: true}).Run(ctx, senv); err != nil {
		t.Fatalf("detach+delete: %v", err)
	}
	if scenariotest.LiveID(senv.State.Ports, "vm-a-nic2") != "" {
		t.Error("detach with Delete must drop the ref (truthful inventory)")
	}
	if !cloud.Deleted["port:"+nicID] {
		t.Error("detach with Delete must delete the Neutron port")
	}
	if len(cloud.IfaceOps) != 4 {
		t.Errorf("ifaceOps = %v, want attach/detach/attach/detach", cloud.IfaceOps)
	}
}

func TestSteps_ConfigureNIC(t *testing.T) {
	_, _, senv := nicFixture(t)
	exec := senv.Exec.(*fake.Exec)
	if err := (ConfigureNICStep{VM: "vm-a", Dev: "eth1", CIDR: "10.0.31.9/24"}).Run(context.Background(), senv); err != nil {
		t.Fatalf("configure-nic: %v", err)
	}
	// Two Calls: the ssh-ready probe (lachesis#253 — the step must not
	// race the fresh VM's sshd), then the configure command.
	if len(exec.Calls) != 2 {
		t.Fatalf("exec calls = %d, want 2 (ssh-ready probe + command)", len(exec.Calls))
	}
	if exec.Calls[0].Command != "true" {
		t.Errorf("first call = %q, want the ssh-ready probe (lachesis#253)", exec.Calls[0].Command)
	}
	call := exec.Calls[1]
	if call.Addr != "203.0.113.9" {
		t.Errorf("configured over %s, want the SSH FIP", call.Addr)
	}
	for _, want := range []string{"ip addr add 10.0.31.9/24 dev eth1", "netmask 255.255.255.0", "link set eth1 up"} {
		if !strings.Contains(call.Command, want) {
			t.Errorf("command lacks %q: %s", want, call.Command)
		}
	}
	// Malformed CIDR fails before any SSH.
	if err := (ConfigureNICStep{VM: "vm-a", Dev: "eth1", CIDR: "not-a-cidr"}).Run(context.Background(), senv); err == nil {
		t.Error("bad CIDR must error")
	}
	// A shell-unsafe Dev is rejected before it reaches the command line.
	if err := (ConfigureNICStep{VM: "vm-a", Dev: "eth1; reboot", CIDR: "10.0.31.9/24"}).Run(context.Background(), senv); err == nil {
		t.Error("shell-unsafe Dev must error")
	}
}

// TestSteps_AttachPortMACFrom: MACFrom pins a previously recorded MAC
// onto the new port; an unrecorded handle errors before any cloud call.
func TestSteps_AttachPortMACFrom(t *testing.T) {
	cloud, _, senv := nicFixture(t)
	ctx := context.Background()

	// Record a MAC as DetachPortStep{Delete:true} would.
	senv.RecordMAC("vm-a-nic2", "fa:16:3e:00:00:aa")
	if err := (AttachPortStep{VM: "vm-a", ID: "vm-a-nic3", Network: "net-b", Subnet: "sub-b",
		IP: "10.0.31.10", MACFrom: "vm-a-nic2"}).Run(ctx, senv); err != nil {
		t.Fatalf("attach with MACFrom: %v", err)
	}
	nicID := scenariotest.LiveID(senv.State.Ports, "vm-a-nic3")
	if got := cloud.MACs[nicID]; got != "fa:16:3e:00:00:aa" {
		t.Errorf("created port MAC = %q, want the pinned MAC", got)
	}
	if err := (AttachPortStep{VM: "vm-a", ID: "vm-a-nic4", Network: "net-b", Subnet: "sub-b",
		IP: "10.0.31.11", MACFrom: "never-recorded"}).Run(ctx, senv); err == nil {
		t.Error("MACFrom with no recorded MAC must error")
	}
}
