package scenariotest

import (
	"context"
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
