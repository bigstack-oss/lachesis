package scenariotest

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// macReuseScenario mirrors the registered mac-reuse scenario: a
// step-scripted run with a deferred VM reborn from a deleted VM's MAC.
func macReuseScenario() *Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.7.0/24", "10.0.7.1").
		VM("vm-a", "T1", "10.0.7.5").
		VM("vm-b", "T1", "10.0.7.6")
	b.Network("net-T2", "T2").
		Subnet("sub-T2", "10.0.8.0/24", "10.0.8.1").
		VM("vm-c", "T2", "10.0.8.5").
		VM("vm-d", "T2", "10.0.8.6")
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").Attach("sub-T1", "10.0.7.1").ExternalGateway("net-ext")
	b.Router("r-T2", "T2").Attach("sub-T2", "10.0.8.1").ExternalGateway("net-ext")

	const budget = 256 << 10
	return &Scenario{
		Name:     "mac-reuse",
		Builder:  b,
		Deferred: []string{"vm-d"},
		Steps: []Step{
			DriveStep{Flows: []Flow{{From: "vm-a", To: VMTarget("vm-b"), Bytes: 1 << 20, Proto: TCP}}},
			AssertStep{Note: "tenant A drive", Expect: []Expect{
				{TenantID: "T1", Zone: "same_tenant", Direction: "tx", MinBytes: 1 << 20},
			}},
			CaptureStep{},
			DeleteVMStep{VM: "vm-a"},
			// Deliberately the global-settled fallback (no ForMACOf): this
			// helper exercises that path + its metric gate; the ForMACOf
			// path is covered by the sweepMetrics tests and the registered
			// mac-reuse scenario.
			AwaitSweepStep{},
			MonotoneStep{Tenant: "T1", Note: "monotone across ghost sweep"},
			MaxGrowthStep{Tenant: "unknown", Zone: "same_tenant", Budget: budget, Note: "no re-bucket to unknown"},
			BootVMStep{VM: "vm-d", MACFrom: "vm-a"},
			MaxGrowthStep{Tenant: "T2", Zone: "same_tenant", Budget: budget, Note: "reborn MAC starts from zero"},
			DriveStep{Flows: []Flow{{From: "vm-d", To: VMTarget("vm-c"), Bytes: 1 << 20, Proto: TCP}}},
			AssertStep{Note: "tenant B drive", Expect: []Expect{
				{TenantID: "T2", Zone: "same_tenant", Direction: "tx", MinBytes: 1 << 20},
			}},
			MonotoneStep{Tenant: "T1", Note: "old tenant unchanged after reuse"},
		},
	}
}

// streamExec counts driven TCP streams so the metrics fake can tell
// "after tenant A's drive" from "after tenant B's drive".
type streamExec struct {
	fakeExec
	streams int
}

func (e *streamExec) Run(ctx context.Context, addr, command string) (string, error) {
	if strings.Contains(command, "dd if=/dev/zero") {
		e.streams++
	}
	return e.fakeExec.Run(ctx, addr, command)
}

// stepMetrics scripts the agent's visible behavior across the steps,
// keyed off the shared fake environment: tenant counters follow the
// driven streams, the settled-flows counter advances once a server has
// been deleted (the "sweep"), and the attach gauge follows boots minus
// deletions.
//
// With bug set it reproduces the pre-fix agent instead: the sweep
// re-buckets tenant A's bytes to "unknown", and the reborn MAC hands
// tenant A's history to tenant B.
type stepMetrics struct {
	env   *fakeEnv
	cloud *fakeCloud
	exec  *streamExec

	bug         bool
	frozenSweep bool // the sweep never fires: settled stays flat
	noSettled   bool // agent predates the fold: metric absent entirely
}

// LookupMAC mirrors a fully-synced agent: a MAC resolves to the
// project of the live (undeleted) port carrying it. Shadows the
// embedded tenant-agnostic instantMACs so the mac-reuse loop
// exercises the MAC-learn gate's stale-tenant rule (lachesis#153).
func (m *stepMetrics) LookupMAC(_ context.Context, _, mac string) (MACLookup, error) {
	for pid, pmac := range m.cloud.portMAC {
		// Router-interface ports never resolve — mirroring the real
		// mac_tenant_map, which holds VM ports only. The MAC-learn
		// gate must not wait on them (lachesis#146 regression).
		if pmac == mac && !m.cloud.deleted["port:"+pid] && !strings.Contains(m.cloud.portName[pid], "p-rif-") {
			return MACLookup{Found: true, TenantID: m.cloud.portProject[pid]}, nil
		}
	}
	return MACLookup{}, nil
}

// LookupFlows: mac-reuse's script never asserts flow peers.
func (m *stepMetrics) LookupFlows(context.Context, string, string) ([]FlowRow, error) {
	return nil, nil
}

const drivenBytes = float64(2 << 20)

func (m *stepMetrics) Scrape(context.Context, string) (ScrapeResult, error) {
	deleted := 0
	for k := range m.cloud.deleted {
		if strings.HasPrefix(k, "server:") {
			deleted++
		}
	}
	swept := deleted > 0

	var t1, t2, unknown, settled float64
	if m.exec.streams >= 1 {
		t1 = drivenBytes
	}
	if m.exec.streams >= 2 {
		t2 += drivenBytes
	}
	if swept && !m.frozenSweep {
		settled = 4
		if m.bug {
			unknown = t1 // re-bucketed to unknown...
			t1 = 0       // ...and gone from the tenant
		}
	}
	if m.bug && m.rebornExists() {
		t2 += drivenBytes // the reborn MAC inherited tenant A's history
	}

	present := map[string]bool{
		metricBytesTotal:         true,
		metricAttachedInterfaces: true,
		metricAttachFailures:     true,
		metricSettledFlows:       !m.noSettled,
	}
	return ScrapeResult{
		Present:            present,
		AttachedInterfaces: m.env.baseAttached + float64(m.env.booted) - float64(deleted),
		AttachFailures:     m.env.failures,
		SettledFlows:       settled,
		Bytes: []BytesSample{
			{TenantID: "uuid-t1", Zone: "same_tenant", Direction: "tx", Value: t1},
			{TenantID: "uuid-t2", Zone: "same_tenant", Direction: "tx", Value: t2},
			{TenantID: "unknown", Zone: "same_tenant", Direction: "tx", Value: unknown},
		},
	}, nil
}

// rebornExists reports whether the explicit-MAC port has been created.
func (m *stepMetrics) rebornExists() bool {
	for _, p := range m.cloud.ports {
		if p.MACAddress != "" {
			return true
		}
	}
	return false
}

// stepsFixture runs the mac-reuse scenario through the plain Run with
// the scripted fakes.
func stepsFixture(t *testing.T, mm *stepMetrics, sc *Scenario) (*fakeCloud, *streamExec, string, AssertReport, error) {
	t.Helper()
	env := &fakeEnv{baseAttached: 5}
	cloud := newFakeCloud(env)
	cloud.preProjects["scenariotest-T1"] = "uuid-t1"
	cloud.preProjects["scenariotest-T2"] = "uuid-t2"
	exec := &streamExec{}
	mm.env, mm.cloud, mm.exec = env, cloud, exec

	statePath := t.TempDir() + "/state.json"
	rep, err := Run(context.Background(), RunOptions{
		Config:     testConfig(),
		Scenario:   sc,
		RunID:      "run1",
		StatePath:  statePath,
		ReportPath: DefaultReportPath(statePath),
		Cloud:      cloud,
		Metrics:    mm,
		Exec:       exec,
		Log:        slog.New(slog.DiscardHandler),
		SinkDelay:  -1,
		// Small gate timeout: with a truthful run-state the MAC-learn
		// gate resolves instantly against the fake cloud; a stale dead
		// port ref (the lachesis#153 mac-reuse regression) fails fast
		// here instead of hanging the suite.
		MACLearnTimeout: time.Second,
	})
	return cloud, exec, statePath, rep, err
}

func TestSteps_BootVMHonorsPlacementSlot(t *testing.T) {
	sc := macReuseScenario()
	sc.Placement = Placement{"vm-d": "node:0"} // testConfig's only agent is compute-0
	cloud, _, _, _, err := stepsFixture(t, &stepMetrics{}, sc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// The deferred vm-d's pin must resolve to the slot's agent host.
	byName := map[string]string{}
	for _, s := range cloud.servers {
		byName[s.Name] = s.AvailabilityZone
	}
	if az := byName["scenariotest-run1-vm-d"]; az != "nova:compute-0" {
		t.Errorf("deferred boot AZ = %q, want %q", az, "nova:compute-0")
	}
}

func TestSteps_MACReuseFullLoop(t *testing.T) {
	cloud, exec, statePath, rep, err := stepsFixture(t, &stepMetrics{}, macReuseScenario())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !rep.OK {
		t.Fatalf("report should pass: %+v", rep)
	}
	if exec.streams != 2 {
		t.Errorf("driven streams = %d, want 2 (one per tenant)", exec.streams)
	}

	// `up` deferred vm-d: only three servers booted by realize, the
	// fourth (with the pinned MAC) by the BootVMStep.
	if len(cloud.servers) != 4 {
		t.Fatalf("servers booted = %d, want 4 (3 realized + 1 deferred)", len(cloud.servers))
	}

	// The reborn port pinned exactly the deleted VM's MAC. vm-a's ref
	// is gone from the run-state (DeleteVMStep keeps the inventory
	// truthful — the MAC-learn gate must never wait on a dead port),
	// so read the ground truth from the fake cloud: the first created
	// port is vm-a's, and it must be deleted with its MAC reborn on
	// the pinned-MAC port.
	rs, err := LoadRunState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range rs.Ports {
		if p.DSLID == "vm-a" {
			t.Errorf("deleted vm-a's port ref still in run-state: %+v", p)
		}
	}
	var rebornMAC string
	for _, p := range cloud.ports {
		if p.MACAddress != "" {
			rebornMAC = p.MACAddress
		}
	}
	macCount := map[string]int{}
	for _, m := range cloud.portMAC {
		macCount[m]++
	}
	if rebornMAC == "" || macCount[rebornMAC] != 2 {
		t.Errorf("reborn MAC %q appears on %d port(s), want 2 (vm-a's auto-assigned + the pinned reborn)",
			rebornMAC, macCount[rebornMAC])
	}
	if len(cloud.downOps) == 0 {
		t.Error("down did not run")
	}
	if !mustLoadReport(t, DefaultReportPath(statePath)).OK {
		t.Error("persisted report should pass")
	}

	// The report carries every step's checks.
	notes := map[string]int{}
	for _, row := range rep.Rows {
		notes[row.Note]++
	}
	for _, want := range []string{"tenant A drive", "monotone across ghost sweep", "no re-bucket to unknown",
		"reborn MAC starts from zero", "tenant B drive", "old tenant unchanged after reuse"} {
		if notes[want] == 0 {
			t.Errorf("report has no %q rows: %v", want, notes)
		}
	}
}

// TestSteps_DetectsRebucketRegression proves the scenario is a real
// detector: against an agent with the ghost-sweep bug (history moves
// to "unknown", the reborn MAC inherits it), the monotone, unknown,
// and zero-inheritance rows must all fail.
func TestSteps_DetectsRebucketRegression(t *testing.T) {
	_, _, _, rep, err := stepsFixture(t, &stepMetrics{bug: true}, macReuseScenario())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.OK {
		t.Fatal("report passed against a buggy agent — the scenario detects nothing")
	}
	failed := map[string]bool{}
	for _, row := range rep.Rows {
		if !row.Pass {
			failed[row.Note] = true
		}
	}
	for _, want := range []string{"monotone across ghost sweep", "no re-bucket to unknown", "reborn MAC starts from zero"} {
		if !failed[want] {
			t.Errorf("expected failing %q rows against the buggy agent; failures: %v", want, failed)
		}
	}
}

// TestSteps_RefusesPreFoldAgent: an agent without
// lachesis_gc_settled_flows_total can't signal its sweep; run must
// refuse up front — before realizing anything — instead of timing out
// mid-scenario.
func TestSteps_RefusesPreFoldAgent(t *testing.T) {
	cloud, _, _, _, err := stepsFixture(t, &stepMetrics{noSettled: true}, macReuseScenario())
	if err == nil || !strings.Contains(err.Error(), metricSettledFlows) {
		t.Fatalf("want pre-fold agent refusal, got %v", err)
	}
	if len(cloud.servers) != 0 {
		t.Errorf("refusal must precede realize; %d server(s) booted", len(cloud.servers))
	}
}

// TestSteps_SweepTimeout: an agent whose settled counter never
// advances (sweep lost) fails the run with a diagnosable error, and
// teardown still runs.
func TestSteps_SweepTimeout(t *testing.T) {
	sc := macReuseScenario()
	for i, st := range sc.Steps {
		if _, ok := st.(AwaitSweepStep); ok {
			sc.Steps[i] = AwaitSweepStep{Timeout: 50 * time.Millisecond}
		}
	}
	cloud, _, _, _, err := stepsFixture(t, &stepMetrics{frozenSweep: true}, sc)
	if err == nil || !strings.Contains(err.Error(), "ghost sweep not observed") {
		t.Fatalf("want sweep-timeout error, got %v", err)
	}
	if len(cloud.downOps) == 0 {
		t.Error("down did not run after the sweep timeout")
	}
}

// TestSteps_DefaultScriptIsDriveAssert: a scenario with no Steps still
// runs the classic linear loop — the plain zone scenarios must be
// untouched by the step machinery. (run_test.go covers the full plain
// loop; this pins that defaultSteps is what runs.)
func TestSteps_DefaultScriptIsDriveAssert(t *testing.T) {
	steps := defaultSteps(runScenario())
	if len(steps) != 2 {
		t.Fatalf("default steps = %d, want 2", len(steps))
	}
	if _, ok := steps[0].(DriveStep); !ok {
		t.Errorf("default step 0 = %T, want DriveStep", steps[0])
	}
	if _, ok := steps[1].(AssertStep); !ok {
		t.Errorf("default step 1 = %T, want AssertStep", steps[1])
	}
}

// extPathScenario mirrors the registered multi-external-path scenario:
// a created second external network, a second router for FIP
// reachability, and the associate → assert-anomaly → drive →
// delete-fip script.
func extPathScenario() *Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.11.0/24", "10.0.11.1").
		VM("vm-a", "T1", "10.0.11.5")
	b.ExternalNetwork("net-ext", "admin")
	b.ExternalNetwork("net-ext2", "T1").
		Subnet("sub-ext2", "172.24.99.0/24", "172.24.99.1")
	b.Router("r-T1", "T1").Attach("sub-T1", "10.0.11.1").ExternalGateway("net-ext")
	b.Router("r-ext2", "T1").Attach("sub-T1", "10.0.11.254").ExternalGateway("net-ext2")
	b.Router("r-nogw", "T1").Attach("sub-T1", "10.0.11.253")

	return &Scenario{
		Name:               "multi-external-path",
		Builder:            b,
		CreateExternalNets: []string{"net-ext2"},
		Steps: []Step{
			AssertAnomalyStep{Class: "multi_external_path", Min: 0, Max: 0, Timeout: time.Second,
				Note: "single external path — no anomaly"},
			AssociateFIPStep{VM: "vm-a", Network: "net-ext2"},
			AssertAnomalyStep{Class: "multi_external_path", Min: 1, Max: 1, Timeout: time.Second,
				Note: "second FIP surfaces the ambiguity"},
			CaptureStep{},
			DriveStep{Flows: []Flow{{From: "vm-a", To: ExternalTarget("8.8.8.8"), Bytes: 1 << 20, Proto: TCP}}},
			AssertStep{Note: "default route bills under the carrying network", Expect: []Expect{
				{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 1 << 20, ExternalNetwork: "net-ext"},
				{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 1 << 20, ExternalNetwork: "net-ext", VM: "vm-a"},
			}},
			AddRouteStep{VM: "vm-a", CIDR: "8.8.9.0/24", Via: "10.0.11.254"},
			CaptureStep{},
			DriveStep{Flows: []Flow{{From: "vm-a", To: ExternalTarget("8.8.9.9"), Bytes: 1 << 20, Proto: TCP}}},
			AssertStep{Note: "second-router flow bills under ITS carrying network", Expect: []Expect{
				{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 1 << 20, ExternalNetwork: "net-ext2"},
				{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 1 << 20, ExternalNetwork: "net-ext2", VM: "vm-a"},
			}},
			AssertFlowPeerStep{Router: "r-ext2", Via: "10.0.11.254", Zone: "external",
				MinBytes: 1 << 20, Note: "steered bytes observed on r-ext2's interface"},
			AddRouteStep{VM: "vm-a", CIDR: "8.8.10.0/24", Via: "10.0.11.253"},
			CaptureStep{},
			DriveStep{Flows: []Flow{{From: "vm-a", To: ExternalTarget("8.8.10.9"), Bytes: 1 << 20, Proto: TCP}}},
			AssertStep{Note: "gateway-less router falls back to the per-VM attribution", Expect: []Expect{
				{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 1 << 20, ExternalNetwork: "net-ext"},
				{TenantID: "T1", Zone: "external", Direction: "tx", MinBytes: 1 << 20, ExternalNetwork: "net-ext", VM: "vm-a"},
			}},
			AssertFlowPeerStep{Router: "r-nogw", Via: "10.0.11.253", Zone: "external",
				MinBytes: 1 << 20, Note: "fallback bytes observed on the gateway-less interface"},
			DeleteFIPStep{VM: "vm-a", Network: "net-ext2"},
			AssertAnomalyStep{Class: "multi_external_path", Min: 0, Max: 0, Timeout: time.Second,
				Note: "ambiguity clears after FIP removal"},
			MonotoneStep{Tenant: "T1", Note: "series stable through FIP churn"},
		},
	}
}

// extExec counts external ping pushes the way streamExec counts TCP
// streams.
type extExec struct {
	fakeExec
	pings  int
	pings2 int // pings at the second-router prefix (8.8.9.x)
	pings3 int // pings at the gateway-less-router prefix (8.8.10.x)
	routes int // in-guest route adds
}

func (e *extExec) Run(ctx context.Context, addr, command string) (string, error) {
	switch {
	case strings.Contains(command, "ping -c") && strings.Contains(command, "8.8.9."):
		e.pings2++
	case strings.Contains(command, "ping -c") && strings.Contains(command, "8.8.10."):
		e.pings3++
	case strings.Contains(command, "ping -c"):
		e.pings++
	case strings.Contains(command, "ip route add"):
		e.routes++
	}
	return e.fakeExec.Run(ctx, addr, command)
}

// extPathMetrics scripts the agent's visible behavior for the
// multi-external-path scenario: the anomaly gauge follows whether an
// extra (non-provider) FIP is live in the fake cloud, external-zone
// counters follow the ping drive under the deterministic pick, and the
// per-server family mirrors the tenant family for the one VM.
type extPathMetrics struct {
	env   *fakeEnv
	cloud *fakeCloud
	exec  *extExec
}

// LookupMAC mirrors the real mac_tenant_map: VM ports resolve,
// router-interface ports never do — so a MAC-learn gate wrongly
// waiting on a rif ref times out the loop test in seconds.
func (m *extPathMetrics) LookupMAC(_ context.Context, _, mac string) (MACLookup, error) {
	for pid, pmac := range m.cloud.portMAC {
		if pmac == mac && !m.cloud.deleted["port:"+pid] && !strings.Contains(m.cloud.portName[pid], "p-rif-") {
			return MACLookup{Found: true, TenantID: m.cloud.portProject[pid]}, nil
		}
	}
	return MACLookup{}, nil
}

// LookupFlows answers the flow-peer gates: a queried MAC belonging to
// a router's interface port reports the driven bytes once the drive
// that rides that router has run.
func (m *extPathMetrics) LookupFlows(_ context.Context, _, mac string) ([]FlowRow, error) {
	for pid, pmac := range m.cloud.portMAC {
		if pmac != mac {
			continue
		}
		name := m.cloud.portName[pid]
		switch {
		case strings.Contains(name, "r-ext2") && m.exec.pings2 >= 1:
			return []FlowRow{{DstMAC: mac, Zone: "external", Direction: "tx", Bytes: drivenBytes}}, nil
		case strings.Contains(name, "r-nogw") && m.exec.pings3 >= 1:
			return []FlowRow{{DstMAC: mac, Zone: "external", Direction: "tx", Bytes: drivenBytes}}, nil
		}
	}
	return nil, nil
}

func (m *extPathMetrics) Scrape(context.Context, string) (ScrapeResult, error) {
	extraFIP := 0.0
	for i, spec := range m.cloud.fips {
		if spec.ExternalNetworkID != m.cloud.extNetID && !m.cloud.deleted["fip:"+m.cloud.fipIDs[i]] {
			extraFIP = 1
		}
	}
	var ext, ext2 float64
	if m.exec.pings >= 1 {
		ext = drivenBytes
	}
	if m.exec.pings3 >= 1 {
		ext += drivenBytes // fallback tier lands on the provider label
	}
	if m.exec.pings2 >= 1 {
		ext2 = drivenBytes
	}
	var serverID string
	if len(m.cloud.serverIDs) > 0 {
		serverID = m.cloud.serverIDs[0]
	}
	// The created network's agent-emitted label is its run-mangled
	// Neutron name — what the per-flow router-MAC attribution resolves
	// for flows riding r-ext2.
	created := Mangle("scenariotest", "run1", "net-ext2")
	return ScrapeResult{
		Present: map[string]bool{
			metricBytesTotal:         true,
			metricAttachedInterfaces: true,
			metricAttachFailures:     true,
			metricNeutronAnomalies:   true,
		},
		AttachedInterfaces: m.env.baseAttached + float64(m.env.booted),
		Anomalies:          map[string]float64{"multi_external_path": extraFIP},
		Bytes: []BytesSample{
			{TenantID: "uuid-t1", Zone: "external", ExternalNetwork: "ext", Direction: "tx", Value: ext},
			{TenantID: "uuid-t1", Zone: "external", ExternalNetwork: created, Direction: "tx", Value: ext2},
		},
		Servers: []ServerSample{
			{ServerID: serverID, TenantID: "uuid-t1", Zone: "external", ExternalNetwork: "ext", Direction: "tx", Value: ext},
			{ServerID: serverID, TenantID: "uuid-t1", Zone: "external", ExternalNetwork: created, Direction: "tx", Value: ext2},
		},
	}, nil
}

func TestSteps_MultiExternalPathFullLoop(t *testing.T) {
	env := &fakeEnv{baseAttached: 5}
	cloud := newFakeCloud(env)
	cloud.preProjects["scenariotest-T1"] = "uuid-t1"
	exec := &extExec{}
	mm := &extPathMetrics{env: env, cloud: cloud, exec: exec}

	statePath := t.TempDir() + "/state.json"
	rep, err := Run(context.Background(), RunOptions{
		Config:     testConfig(),
		Scenario:   extPathScenario(),
		RunID:      "run1",
		StatePath:  statePath,
		ReportPath: DefaultReportPath(statePath),
		Cloud:      cloud,
		Metrics:    mm,
		Exec:       exec,
		Log:        slog.New(slog.DiscardHandler),
		SinkDelay:  -1,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !rep.OK {
		t.Fatalf("report should pass: %+v", rep)
	}

	// The second external network was CREATED as router:external —
	// not bound to the provider net — and its FIP subnet realized.
	extCreated := false
	for _, n := range cloud.nets {
		if n.External {
			extCreated = true
		}
	}
	if !extCreated {
		t.Error("net-ext2 was not created as an external network")
	}

	// Exactly one extra FIP (beyond vm-a's provider SSH FIP) was
	// allocated from the created network, and deleted mid-run.
	if len(cloud.fips) != 2 {
		t.Fatalf("fips created = %d, want 2 (SSH + extra)", len(cloud.fips))
	}
	extraIdx := -1
	for i, spec := range cloud.fips {
		if spec.ExternalNetworkID != cloud.extNetID {
			extraIdx = i
		}
	}
	if extraIdx < 0 {
		t.Fatal("no FIP drawn from the created external network")
	}
	if !cloud.deleted["fip:"+cloud.fipIDs[extraIdx]] {
		t.Error("the extra FIP was not deleted by DeleteFIPStep")
	}
	if exec.routes != 2 {
		t.Errorf("in-guest route adds = %d, want 2 (second router + gateway-less)", exec.routes)
	}
	if exec.pings2 != 1 || exec.pings3 != 1 {
		t.Errorf("router-steered ping drives = %d/%d, want 1/1", exec.pings2, exec.pings3)
	}

	// The deleted FIP is gone from the persisted run-state too — down
	// must not re-delete it; the provider SSH FIP ref stays.
	rs, err := LoadRunState(statePath)
	if err != nil {
		t.Fatalf("LoadRunState: %v", err)
	}
	for _, f := range rs.FIPs {
		if f.Network == "net-ext2" {
			t.Errorf("deleted FIP still in run-state: %+v", f)
		}
	}
	if len(rs.FIPs) != 1 {
		t.Errorf("run-state FIPs = %+v, want only the provider SSH FIP", rs.FIPs)
	}

	// Every phase's rows are in the report.
	notes := map[string]int{}
	for _, row := range rep.Rows {
		notes[row.Note]++
	}
	for _, want := range []string{"single external path — no anomaly", "second FIP surfaces the ambiguity",
		"default route bills under the carrying network", "second-router flow bills under ITS carrying network",
		"gateway-less router falls back to the per-VM attribution",
		"steered bytes observed on r-ext2's interface",
		"fallback bytes observed on the gateway-less interface",
		"ambiguity clears after FIP removal", "series stable through FIP churn"} {
		if notes[want] == 0 {
			t.Errorf("report has no %q rows: %v", want, notes)
		}
	}
}

func TestSteps_MigrateMovesAndRecords(t *testing.T) {
	env := &fakeEnv{baseAttached: 1}
	cloud := newFakeCloud(env)
	cloud.hyps = []string{"compute-0", "compute-1"}
	cloud.serverHost["srv-1"] = "compute-0"
	cfg := testConfig()
	cfg.Cluster.Agents = append(cfg.Cluster.Agents, AgentConfig{Host: "compute-1", MetricsURL: "http://compute-1:9100/metrics"})
	statePath := t.TempDir() + "/state.json"
	rs := &RunState{RunID: "run1", Scenario: "x", Servers: []ResourceRef{{DSLID: "vm-a", ID: "srv-1", ProjectID: "p1"}}}
	senv := &StepEnv{Config: cfg, State: rs, StatePath: statePath, Cloud: cloud, Metrics: &fakeMetrics{env: env}, Log: slog.New(slog.DiscardHandler)}

	step := MigrateStep{VM: "vm-a", Target: "node:1", Timeout: time.Second}
	if err := step.Run(context.Background(), senv); err != nil {
		t.Fatalf("MigrateStep: %v", err)
	}
	if got := cloud.serverHost["srv-1"]; got != "compute-1" {
		t.Errorf("server host = %q, want compute-1", got)
	}
	if len(rs.Migrations) != 1 || rs.Migrations[0] != (MigrationRecord{VM: "vm-a", From: "compute-0", To: "compute-1"}) {
		t.Errorf("migrations = %+v", rs.Migrations)
	}
	saved, err := LoadRunState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(saved.Migrations) != 1 {
		t.Errorf("migration not persisted: %+v", saved.Migrations)
	}
}

func TestSteps_MigrateErrors(t *testing.T) {
	env := &fakeEnv{baseAttached: 1}
	cloud := newFakeCloud(env)
	cloud.hyps = []string{"compute-0", "compute-1"}
	cloud.serverHost["srv-1"] = "compute-0"
	cfg := testConfig()
	cfg.Cluster.Agents = append(cfg.Cluster.Agents, AgentConfig{Host: "compute-1", MetricsURL: "http://compute-1:9100/metrics"})
	rs := &RunState{RunID: "run1", Servers: []ResourceRef{{DSLID: "vm-a", ID: "srv-1", ProjectID: "p1"}}}
	senv := &StepEnv{Config: cfg, State: rs, StatePath: t.TempDir() + "/s.json", Cloud: cloud, Metrics: &fakeMetrics{env: env}, Log: slog.New(slog.DiscardHandler)}

	for name, tc := range map[string]struct {
		step    MigrateStep
		wantErr string
	}{
		"unknown vm":        {MigrateStep{VM: "vm-x", Timeout: time.Second}, "no server for VM"},
		"target is current": {MigrateStep{VM: "vm-a", Target: "node:0", Timeout: time.Second}, "already on"},
		"bad slot":          {MigrateStep{VM: "vm-a", Target: "node:9", Timeout: time.Second}, "config lists 2 agent(s)"},
	} {
		t.Run(name, func(t *testing.T) {
			err := tc.step.Run(context.Background(), senv)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
	if len(rs.Migrations) != 0 {
		t.Errorf("failed steps must record nothing: %+v", rs.Migrations)
	}
}

// restartMetrics is a minimal agent /metrics. attached is the tap
// count; when notReadyPolls > 0 the readiness scrapes (every call after
// the pre-restart baseline, call #1) report one tap short for that many
// polls before recovering — modelling the boot re-attach window.
type restartMetrics struct {
	instantMACs
	attached      float64
	notReadyPolls int
	scrapes       int
}

func (m *restartMetrics) Scrape(context.Context, string) (ScrapeResult, error) {
	m.scrapes++
	a := m.attached
	if m.scrapes >= 2 && m.scrapes <= 1+m.notReadyPolls {
		a = m.attached - 1 // still re-attaching
	}
	return ScrapeResult{
		Present: map[string]bool{
			metricBytesTotal: true, metricAttachedInterfaces: true,
			metricSettledFlows: true, metricServerBytesTotal: true,
		},
		AttachedInterfaces: a,
	}, nil
}

// restartExec models the agent host: it records commands, reports the
// unit's MainPID (bumping it once a restart is issued, so awaitReady's
// PID-change evidence fires), and can be told to never cycle (the
// restart-didn't-take case) or to fail a command matching failOn.
type restartExec struct {
	calls     []execCall
	restarted bool
	noCycle   bool   // MainPID never changes — restart did not take
	failOn    string // a command substring that returns an error
}

func (e *restartExec) Run(_ context.Context, addr, command string) (string, error) {
	e.calls = append(e.calls, execCall{addr, command})
	if e.failOn != "" && strings.Contains(command, e.failOn) {
		return "", fmt.Errorf("fake ssh: command failed: %s", command)
	}
	switch {
	case strings.Contains(command, "systemctl restart"):
		e.restarted = true
		return "", nil
	case strings.Contains(command, "MainPID"):
		if e.restarted && !e.noCycle {
			return "MainPID=2222\n", nil
		}
		return "MainPID=1111\n", nil
	}
	return "", nil
}

func (e *restartExec) has(substr string) bool {
	for _, c := range e.calls {
		if strings.Contains(c.command, substr) {
			return true
		}
	}
	return false
}

func restartEnv(t *testing.T, agents []AgentConfig, ac AgentControlConfig, exec VMExec, m MetricsSource) *StepEnv {
	t.Helper()
	cfg := testConfig()
	cfg.Cluster.Agents = agents
	cfg.AgentControl = ac
	if m == nil {
		m = &restartMetrics{attached: 5}
	}
	return &StepEnv{
		Config:    cfg,
		Scenario:  &Scenario{Name: "restart"},
		State:     &RunState{RunID: "run1"},
		StatePath: t.TempDir() + "/s.json",
		Metrics:   m,
		AgentExec: exec,
		Log:       slog.New(slog.DiscardHandler),
		Report:    &AssertReport{OK: true},
	}
}

func TestSteps_RestartAgent(t *testing.T) {
	agents := []AgentConfig{{Host: "compute-0", MetricsURL: "http://compute-0:9100/metrics", SSHHost: "10.0.0.10"}}
	ac := AgentControlConfig{User: "root", KeyPath: "/k", Unit: "lachesis-agent", ReadyTimeout: time.Second}
	exec := &restartExec{}

	if err := (RestartAgentStep{}).Run(context.Background(), restartEnv(t, agents, ac, exec, nil)); err != nil {
		t.Fatalf("restart: %v", err)
	}
	if !exec.has("systemctl restart lachesis-agent") {
		t.Errorf("no restart command issued: %+v", exec.calls)
	}
	if !exec.has("MainPID") {
		t.Errorf("no MainPID read (restart evidence) issued: %+v", exec.calls)
	}
	for _, c := range exec.calls {
		if c.addr != "10.0.0.10" {
			t.Errorf("SSHed to %q, want the agent's ssh_host 10.0.0.10", c.addr)
		}
	}
}

func TestSteps_RestartAgentAltConfig(t *testing.T) {
	agents := []AgentConfig{{Host: "compute-0", MetricsURL: "http://c0/m"}}
	ac := AgentControlConfig{User: "root", KeyPath: "/k", ConfigPath: "/etc/lachesis/agent.yaml", ReadyTimeout: time.Second}
	exec := &restartExec{}

	if err := (RestartAgentStep{AltConfig: "/tmp/shrunk.yaml"}).Run(context.Background(), restartEnv(t, agents, ac, exec, nil)); err != nil {
		t.Fatalf("restart alt: %v", err)
	}
	if !exec.has("/etc/lachesis/agent.yaml.scenariotest.bak") || !exec.has("cp -f /tmp/shrunk.yaml /etc/lachesis/agent.yaml") {
		t.Errorf("alt-config swap not issued (backup + copy): %+v", exec.calls)
	}
	if !exec.has("systemctl restart") {
		t.Errorf("restart not issued after swap: %+v", exec.calls)
	}

	// AltConfig without a config_path is a usage error, before any SSH.
	acNoPath := AgentControlConfig{User: "root", KeyPath: "/k", ReadyTimeout: time.Second}
	exec2 := &restartExec{}
	if err := (RestartAgentStep{AltConfig: "/tmp/x.yaml"}).Run(context.Background(), restartEnv(t, agents, acNoPath, exec2, nil)); err == nil {
		t.Error("AltConfig with no config_path must error")
	}
	if exec2.has("systemctl restart") {
		t.Error("must not restart when config is invalid")
	}
}

// TestSteps_RestartAgentAwaitsReattach: the step must keep polling until
// the taps have re-attached, not return on the boot re-attach dip.
func TestSteps_RestartAgentAwaitsReattach(t *testing.T) {
	agents := []AgentConfig{{Host: "compute-0", MetricsURL: "http://c0/m"}}
	ac := AgentControlConfig{User: "root", KeyPath: "/k", ReadyTimeout: 5 * time.Second}
	m := &restartMetrics{attached: 5, notReadyPolls: 2} // two short polls, then recovered
	if err := (RestartAgentStep{}).Run(context.Background(), restartEnv(t, agents, ac, &restartExec{}, m)); err != nil {
		t.Fatalf("restart: %v", err)
	}
	if m.scrapes < 4 {
		t.Errorf("expected several readiness polls awaiting re-attach, got %d scrapes", m.scrapes)
	}
}

// TestSteps_RestartAgentTimeout: when the unit never cycles (MainPID
// unchanged) the restart is not confirmed and the step times out with a
// clear message, rather than passing on the still-running old process.
func TestSteps_RestartAgentTimeout(t *testing.T) {
	agents := []AgentConfig{{Host: "compute-0", MetricsURL: "http://c0/m"}}
	ac := AgentControlConfig{User: "root", KeyPath: "/k", ReadyTimeout: 150 * time.Millisecond}
	exec := &restartExec{noCycle: true}
	err := (RestartAgentStep{}).Run(context.Background(), restartEnv(t, agents, ac, exec, nil))
	if err == nil || !strings.Contains(err.Error(), "restart not confirmed") {
		t.Fatalf("want a 'restart not confirmed' timeout, got %v", err)
	}
}

func TestSteps_RestartAgentErrors(t *testing.T) {
	agents := []AgentConfig{{Host: "compute-0", MetricsURL: "http://c0/m"}}
	ac := AgentControlConfig{User: "root", KeyPath: "/k", ReadyTimeout: time.Second}
	twoAgents := []AgentConfig{agents[0], {Host: "compute-1", MetricsURL: "http://c1/m"}}

	cases := map[string]struct {
		agents  []AgentConfig
		ac      AgentControlConfig
		exec    VMExec
		step    RestartAgentStep
		wantErr string
	}{
		"no agent exec": {agents, ac, nil, RestartAgentStep{}, "no agent-host SSH transport"},
		"missing creds": {agents, AgentControlConfig{ReadyTimeout: time.Second}, &restartExec{}, RestartAgentStep{}, "user and agent_control.key_path"},
		"node needed":   {twoAgents, ac, &restartExec{}, RestartAgentStep{}, "node is required"},
		"unknown host":  {agents, ac, &restartExec{}, RestartAgentStep{Node: "ghost"}, "not a configured agent host"},
		"unsafe unit":   {agents, AgentControlConfig{User: "root", KeyPath: "/k", Unit: "agent; rm -rf /", ReadyTimeout: time.Second}, &restartExec{}, RestartAgentStep{}, "unsafe for a shell command"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := tc.step.Run(context.Background(), restartEnv(t, tc.agents, tc.ac, tc.exec, nil))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestSkip_AgentControlUnconfigured(t *testing.T) {
	sc := &Scenario{Name: "r", Steps: []Step{RestartAgentStep{}}}
	cfg := testConfig() // no agent_control creds
	if r := skipReason(sc, cfg); r == "" {
		t.Error("a restart scenario must SKIP when agent_control.key_path is unset")
	}
	cfg.AgentControl.KeyPath = "/k"
	if r := skipReason(sc, cfg); r != "" {
		t.Errorf("with creds set it must run, got skip %q", r)
	}
}

// nicMetrics reports the attach gauge from the fake cloud's live
// state: boots plus hot-plugged NICs, minus deleted servers — so the
// attach/detach gates in the NIC lifecycle steps resolve instantly and
// truthfully against what the step just did.
type nicMetrics struct {
	instantMACs
	env   *fakeEnv
	cloud *fakeCloud

	servers []ServerSample
	settled float64
	ghosts  float64
}

func (m *nicMetrics) Scrape(context.Context, string) (ScrapeResult, error) {
	deleted := 0
	for k := range m.cloud.deleted {
		if strings.HasPrefix(k, "server:") {
			deleted++
		}
	}
	return ScrapeResult{
		Present: map[string]bool{
			metricBytesTotal: true, metricAttachedInterfaces: true,
			metricAttachFailures: true, metricSettledFlows: true,
			metricServerBytesTotal: true, metricLingeringGhosts: true,
		},
		AttachedInterfaces: m.env.baseAttached + float64(m.env.booted) + float64(len(m.cloud.hotAttached)) - float64(deleted),
		AttachFailures:     m.env.failures,
		SettledFlows:       m.settled,
		LingeringGhosts:    m.ghosts,
		Servers:            m.servers,
	}, nil
}

// nicFixture is a live vm-a (booted through the fake cloud so the
// server binding is real) with a second DSL network for hot-plugging.
func nicFixture(t *testing.T) (*fakeCloud, *nicMetrics, *StepEnv) {
	t.Helper()
	b := scenario.New()
	b.Network("net-a", "T1").Subnet("sub-a", "10.0.30.0/24", "10.0.30.1").VM("vm-a", "T1", "10.0.30.5")
	b.Network("net-b", "T1").Subnet("sub-b", "10.0.31.0/24", "10.0.31.1")
	sc := &Scenario{Name: "nic-lifecycle", Builder: b}

	env := &fakeEnv{baseAttached: 3}
	cloud := newFakeCloud(env)
	bootPort, err := cloud.CreatePort(context.Background(), "uuid-t1", PortSpec{Name: "boot", NetworkID: "net-1"})
	if err != nil {
		t.Fatal(err)
	}
	srvID, err := cloud.CreateServer(context.Background(), "uuid-t1", ServerSpec{Name: "vm-a", PortID: bootPort})
	if err != nil {
		t.Fatal(err)
	}
	rs := &RunState{
		RunID:    "run1",
		Projects: map[string]ProjectRef{"T1": {Name: "T1", ID: "uuid-t1"}},
		Networks: []ResourceRef{{DSLID: "net-b", ID: "net-2"}},
		Subnets:  []ResourceRef{{DSLID: "sub-b", ID: "sub-2"}},
		Servers:  []ResourceRef{{DSLID: "vm-a", ID: srvID, ProjectID: "uuid-t1"}},
		FIPs:     []FIPRef{{VMID: "vm-a", Address: "203.0.113.9", ProjectID: "uuid-t1"}},
	}
	nm := &nicMetrics{env: env, cloud: cloud}
	senv := &StepEnv{
		Config: testConfig(), Scenario: sc, State: rs,
		StatePath: t.TempDir() + "/s.json",
		Cloud:     cloud, Metrics: nm, Exec: &fakeExec{},
		Log:    slog.New(slog.DiscardHandler),
		Report: &AssertReport{OK: true},
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
	nicID := liveID(senv.State.Ports, "vm-a-nic2")
	if nicID == "" {
		t.Fatal("attach recorded no nic ref")
	}
	var ref ResourceRef
	for _, p := range senv.State.Ports {
		if p.DSLID == "vm-a-nic2" {
			ref = p
		}
	}
	if ref.MAC == "" {
		t.Error("nic ref carries no MAC — the MAC-learn gate would skip it")
	}
	if got, want := senv.State.Attach.Target, senv.Metrics.(*nicMetrics).env.baseAttached+1+1; got != want {
		t.Errorf("attach gate target = %v, want %v", got, want)
	}
	if len(cloud.ifaceOps) != 1 || !strings.HasPrefix(cloud.ifaceOps[0], "attach:") {
		t.Fatalf("ifaceOps = %v, want one attach", cloud.ifaceOps)
	}

	// A bound port must refuse deletion until detached.
	if err := cloud.DeletePort(ctx, "uuid-t1", nicID); err == nil {
		t.Error("DeletePort on an attached port must fail")
	}

	// Detach (keep the port): ref stays, attach record re-baselined down.
	if err := (DetachPortStep{VM: "vm-a", Port: "vm-a-nic2"}).Run(ctx, senv); err != nil {
		t.Fatalf("detach: %v", err)
	}
	if liveID(senv.State.Ports, "vm-a-nic2") == "" {
		t.Error("detach without Delete must keep the ref")
	}
	// The detached MAC is recorded so a following AwaitSweepStep{ForMACOf}
	// can wait for its fold — even once Delete drops the ref.
	if senv.macs["vm-a-nic2"] != ref.MAC {
		t.Errorf("detach must record the MAC: macs[vm-a-nic2]=%q, want %q", senv.macs["vm-a-nic2"], ref.MAC)
	}
	if got, want := senv.State.Attach.Target, senv.Metrics.(*nicMetrics).env.baseAttached+1; got != want {
		t.Errorf("post-detach attach target = %v, want %v", got, want)
	}

	// Reattach the same port, then detach+delete it.
	if err := (ReattachPortStep{VM: "vm-a", Port: "vm-a-nic2"}).Run(ctx, senv); err != nil {
		t.Fatalf("reattach: %v", err)
	}
	if err := (DetachPortStep{VM: "vm-a", Port: "vm-a-nic2", Delete: true}).Run(ctx, senv); err != nil {
		t.Fatalf("detach+delete: %v", err)
	}
	if liveID(senv.State.Ports, "vm-a-nic2") != "" {
		t.Error("detach with Delete must drop the ref (truthful inventory)")
	}
	if !cloud.deleted["port:"+nicID] {
		t.Error("detach with Delete must delete the Neutron port")
	}
	if len(cloud.ifaceOps) != 4 {
		t.Errorf("ifaceOps = %v, want attach/detach/attach/detach", cloud.ifaceOps)
	}
}

func TestSteps_ConfigureNIC(t *testing.T) {
	_, _, senv := nicFixture(t)
	exec := senv.Exec.(*fakeExec)
	if err := (ConfigureNICStep{VM: "vm-a", Dev: "eth1", CIDR: "10.0.31.9/24"}).Run(context.Background(), senv); err != nil {
		t.Fatalf("configure-nic: %v", err)
	}
	if len(exec.calls) != 1 {
		t.Fatalf("exec calls = %d, want 1", len(exec.calls))
	}
	call := exec.calls[0]
	if call.addr != "203.0.113.9" {
		t.Errorf("configured over %s, want the SSH FIP", call.addr)
	}
	for _, want := range []string{"ip addr add 10.0.31.9/24 dev eth1", "netmask 255.255.255.0", "link set eth1 up"} {
		if !strings.Contains(call.command, want) {
			t.Errorf("command lacks %q: %s", want, call.command)
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

func TestSteps_ServerMonotone(t *testing.T) {
	_, nm, senv := nicFixture(t)
	ctx := context.Background()
	srvID := senv.State.Servers[0].ID

	nm.servers = []ServerSample{
		{ServerID: srvID, Zone: "same_tenant", Direction: "tx", Value: 100},
		{ServerID: srvID, Zone: "external", Direction: "tx", Value: 40},
	}
	if err := (CaptureStep{}).Run(ctx, senv); err != nil {
		t.Fatal(err)
	}

	// One tuple dips (the partial-fold shape), one keeps growing.
	nm.servers = []ServerSample{
		{ServerID: srvID, Zone: "same_tenant", Direction: "tx", Value: 60},
		{ServerID: srvID, Zone: "external", Direction: "tx", Value: 41},
	}
	if err := (ServerMonotoneStep{VM: "vm-a", Note: "dip"}).Run(ctx, senv); err != nil {
		t.Fatal(err)
	}
	if senv.Report.OK {
		t.Error("a dipped server tuple must fail the report")
	}
	var fails, passes int
	for _, r := range senv.Report.Rows {
		if r.Pass {
			passes++
		} else {
			fails++
			if r.Zone != "same_tenant" {
				t.Errorf("failing row zone = %s, want same_tenant", r.Zone)
			}
		}
	}
	if fails != 1 || passes != 1 {
		t.Errorf("rows = %d fail / %d pass, want 1/1", fails, passes)
	}

	// No captured tuples for the VM is a scenario bug, not a pass.
	senv.capturedServers = map[serverTuple]float64{}
	if err := (ServerMonotoneStep{VM: "vm-a"}).Run(ctx, senv); err == nil {
		t.Error("no captured tuples must error")
	}
}

func TestSteps_MaxSettled(t *testing.T) {
	_, nm, senv := nicFixture(t)
	ctx := context.Background()

	nm.settled = 7
	if err := (CaptureStep{}).Run(ctx, senv); err != nil {
		t.Fatal(err)
	}

	// Unchanged counter passes a zero budget.
	if err := (MaxSettledStep{Note: "none"}).Run(ctx, senv); err != nil {
		t.Fatal(err)
	}
	if !senv.Report.OK {
		t.Fatalf("no growth must pass: %+v", senv.Report.Rows)
	}

	// Any fold beyond budget fails.
	nm.settled = 9
	if err := (MaxSettledStep{Budget: 1, Note: "folded"}).Run(ctx, senv); err != nil {
		t.Fatal(err)
	}
	if senv.Report.OK {
		t.Error("growth beyond budget must fail the report")
	}
}

func TestSteps_MaxGhosts(t *testing.T) {
	_, nm, senv := nicFixture(t)
	ctx := context.Background()

	nm.ghosts = 3 // a pre-existing ghost on the (shared) agent
	if err := (CaptureStep{}).Run(ctx, senv); err != nil {
		t.Fatal(err)
	}
	// No NEW ghost marked → delta 0 → passes a zero budget, even though
	// the absolute count is non-zero (delta-from-capture, not absolute).
	if err := (MaxGhostsStep{Note: "migration marks no ghost"}).Run(ctx, senv); err != nil {
		t.Fatal(err)
	}
	if !senv.Report.OK {
		t.Fatalf("no new ghost must pass despite a non-zero baseline: %+v", senv.Report.Rows)
	}
	// A newly-marked ghost (e.g. a wrongful migration ghost) fails.
	nm.ghosts = 4
	if err := (MaxGhostsStep{Note: "wrongful ghost"}).Run(ctx, senv); err != nil {
		t.Fatal(err)
	}
	if senv.Report.OK {
		t.Error("a newly-marked ghost must fail the report")
	}
}

// sweepMetrics models a SHARED agent: the global settled counter rises
// on every scrape (other tenants' folds), while the target MAC leaves
// the metadata map only after macGoneAfterLookups lookups.
type sweepMetrics struct {
	settledStart        float64
	macGoneAfterLookups int
	lookups             int
	scrapes             int
}

func (m *sweepMetrics) Scrape(context.Context, string) (ScrapeResult, error) {
	m.scrapes++
	return ScrapeResult{
		Present:      map[string]bool{metricSettledFlows: true, metricBytesTotal: true, metricAttachedInterfaces: true},
		SettledFlows: m.settledStart + float64(m.scrapes), // always rising
	}, nil
}

func (m *sweepMetrics) LookupMAC(_ context.Context, _, _ string) (MACLookup, error) {
	m.lookups++
	if m.lookups >= m.macGoneAfterLookups {
		return MACLookup{Found: false}, nil
	}
	return MACLookup{Found: true, TenantID: "t"}, nil
}

func (m *sweepMetrics) LookupFlows(context.Context, string, string) ([]FlowRow, error) {
	return nil, nil
}

func sweepEnv(t *testing.T, m MetricsSource) *StepEnv {
	t.Helper()
	return &StepEnv{
		Config:      testConfig(), // one agent
		State:       &RunState{RunID: "r"},
		Metrics:     m,
		Log:         slog.New(slog.DiscardHandler),
		Report:      &AssertReport{OK: true},
		macs:        map[string]string{"nic": "fa:16:3e:00:00:aa"},
		settledBase: 10,
	}
}

// The fix (lachesis#240): ForMACOf waits for the MAC to leave metadata,
// returning as soon as it does — regardless of the rising global counter.
func TestSteps_AwaitSweep_ForMACReturnsWhenGone(t *testing.T) {
	m := &sweepMetrics{settledStart: 10, macGoneAfterLookups: 1}
	if err := (AwaitSweepStep{ForMACOf: "nic", Timeout: time.Second}).Run(context.Background(), sweepEnv(t, m)); err != nil {
		t.Fatalf("await-sweep: %v", err)
	}
	if m.lookups != 1 {
		t.Errorf("lookups = %d, want 1 (MAC gone on first poll)", m.lookups)
	}
}

// The bug it fixes: a rising global settled counter must NOT satisfy a
// ForMACOf wait — while the MAC is still in metadata the step keeps
// waiting and ultimately times out on the MAC, never on the counter.
func TestSteps_AwaitSweep_ForMACIgnoresGlobalSettled(t *testing.T) {
	m := &sweepMetrics{settledStart: 10, macGoneAfterLookups: 1_000_000} // never gone
	err := (AwaitSweepStep{ForMACOf: "nic", Timeout: 60 * time.Millisecond}).Run(context.Background(), sweepEnv(t, m))
	if err == nil || !strings.Contains(err.Error(), "still in metadata") {
		t.Fatalf("want a MAC-still-in-metadata timeout (not a global-settled pass), got %v", err)
	}
}

// Fallback (no ForMACOf) keeps the legacy global-settled behavior.
func TestSteps_AwaitSweep_GlobalFallback(t *testing.T) {
	m := &sweepMetrics{settledStart: 10, macGoneAfterLookups: 1}
	if err := (AwaitSweepStep{Timeout: time.Second}).Run(context.Background(), sweepEnv(t, m)); err != nil {
		t.Fatalf("await-sweep global fallback: %v", err)
	}
	if m.lookups != 0 {
		t.Errorf("global fallback must not call LookupMAC, got %d lookups", m.lookups)
	}
}

// twoAgentCfg returns a config with two agents, for all-agents semantics.
func twoAgentCfg() Config {
	cfg := testConfig()
	cfg.Cluster.Agents = []AgentConfig{
		{Host: "compute-0", MetricsURL: "http://compute-0:9100/metrics"},
		{Host: "compute-1", MetricsURL: "http://compute-1:9100/metrics"},
	}
	return cfg
}

// perAgentSweep answers LookupMAC per agent URL, and errors when errAll
// is set — for the all-agents and transient-tolerance tests.
type perAgentSweep struct {
	foundOn map[string]bool // metrics URL → MAC still resolves there
	errAll  bool
}

func (m *perAgentSweep) Scrape(context.Context, string) (ScrapeResult, error) {
	return ScrapeResult{Present: map[string]bool{metricBytesTotal: true, metricAttachedInterfaces: true}}, nil
}
func (m *perAgentSweep) LookupMAC(_ context.Context, url, _ string) (MACLookup, error) {
	if m.errAll {
		return MACLookup{}, fmt.Errorf("boom: %s unreachable", url)
	}
	return MACLookup{Found: m.foundOn[url]}, nil
}
func (m *perAgentSweep) LookupFlows(context.Context, string, string) ([]FlowRow, error) {
	return nil, nil
}

// Happy path with a real Found→gone transition (fast: shrunk poll interval).
func TestSteps_AwaitSweep_ForMACTransition(t *testing.T) {
	defer func(d time.Duration) { sweepPollInterval = d }(sweepPollInterval)
	sweepPollInterval = 2 * time.Millisecond

	m := &sweepMetrics{settledStart: 10, macGoneAfterLookups: 3} // Found twice, then gone
	env := sweepEnv(t, m)
	if err := (AwaitSweepStep{ForMACOf: "nic", Timeout: time.Second}).Run(context.Background(), env); err != nil {
		t.Fatalf("await-sweep: %v", err)
	}
	if m.lookups < 3 {
		t.Errorf("expected to poll until the MAC folded (>=3 lookups), got %d", m.lookups)
	}
}

// All-agents semantics: while the MAC still resolves on ANY agent the
// wait must not return — it times out here because compute-1 keeps it.
func TestSteps_AwaitSweep_WaitsForAllAgents(t *testing.T) {
	m := &perAgentSweep{foundOn: map[string]bool{
		"http://compute-0:9100/metrics": false, // swept here
		"http://compute-1:9100/metrics": true,  // still present here
	}}
	env := &StepEnv{
		Config: twoAgentCfg(), State: &RunState{RunID: "r"}, Metrics: m,
		Log: slog.New(slog.DiscardHandler), Report: &AssertReport{OK: true},
		macs: map[string]string{"nic": "fa:16:3e:00:00:aa"},
	}
	err := (AwaitSweepStep{ForMACOf: "nic", Timeout: 60 * time.Millisecond}).Run(context.Background(), env)
	if err == nil || !strings.Contains(err.Error(), "still in metadata") {
		t.Fatalf("must keep waiting while any agent still has the MAC; got %v", err)
	}
}

// Transient lookup errors must not abort the wait: it keeps polling and
// surfaces the last error on timeout, rather than returning immediately.
func TestSteps_AwaitSweep_ToleratesTransientErrors(t *testing.T) {
	m := &perAgentSweep{errAll: true}
	env := sweepEnv(t, m)
	start := time.Now()
	err := (AwaitSweepStep{ForMACOf: "nic", Timeout: 60 * time.Millisecond}).Run(context.Background(), env)
	if err == nil || !strings.Contains(err.Error(), "last lookup error") {
		t.Fatalf("want a timeout carrying the last lookup error (not an immediate abort), got %v", err)
	}
	if time.Since(start) < 40*time.Millisecond {
		t.Errorf("returned too fast (%s) — it aborted on the first error instead of waiting", time.Since(start))
	}
}
