package steps

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/fake"
)

func TestSteps_ServerMonotone(t *testing.T) {
	_, nm, senv := nicFixture(t)
	ctx := context.Background()
	srvID := senv.State.Servers[0].ID

	nm.Servers = []scenariotest.ServerSample{
		{ServerID: srvID, Zone: "same_tenant", Direction: "tx", Value: 100},
		{ServerID: srvID, Zone: "external", Direction: "tx", Value: 40},
	}
	if err := (CaptureStep{}).Run(ctx, senv); err != nil {
		t.Fatal(err)
	}

	// One tuple dips (the partial-fold shape), one keeps growing.
	nm.Servers = []scenariotest.ServerSample{
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
	senv.Captured.Servers = map[scenariotest.ServerTuple]float64{}
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

// TestSteps_PortSeries: the port-tier assertion sums only the target
// port's samples; a port whose id is absent (mislabeled traffic) fails.
func TestSteps_PortSeries(t *testing.T) {
	_, nm, senv := nicFixture(t)
	ctx := context.Background()
	senv.State.Ports = append(senv.State.Ports, scenariotest.ResourceRef{DSLID: "vm-a-nic3", ID: "port-new"})

	nm.Ports = []scenariotest.PortSample{
		{PortID: "port-new", ServerID: "srv", Zone: "same_tenant", Direction: "tx", Value: 2 << 20},
		{PortID: "port-old", ServerID: "srv", Zone: "same_tenant", Direction: "tx", Value: 9 << 20},
	}
	if err := (PortSeriesStep{VM: "vm-a", Port: "vm-a-nic3", MinBytes: 1 << 20, Note: "ok"}).Run(ctx, senv); err != nil {
		t.Fatal(err)
	}
	if !senv.Report.OK {
		t.Fatalf("port with enough bytes must pass: %+v", senv.Report.Rows)
	}
	// Traffic mislabeled under another port's id → the target sums 0.
	nm.Ports = []scenariotest.PortSample{
		{PortID: "port-old", ServerID: "srv", Zone: "same_tenant", Direction: "tx", Value: 9 << 20},
	}
	defer func(d time.Duration) { sweepPollInterval = d }(sweepPollInterval)
	sweepPollInterval = 2 * time.Millisecond
	if err := (PortSeriesStep{VM: "vm-a", Port: "vm-a-nic3", MinBytes: 1 << 20, Timeout: 30 * time.Millisecond, Note: "stale"}).Run(ctx, senv); err != nil {
		t.Fatal(err)
	}
	if senv.Report.OK {
		t.Error("absent port_id must fail the row (mislabeled traffic)")
	}
}

func TestZoneGrowthStep(t *testing.T) {
	// The loop timing isn't under test — kill the settle and shrink the
	// poll so cases resolve in milliseconds.
	defer func(s, p time.Duration) { zoneGrowthSettle, sweepPollInterval = s, p }(zoneGrowthSettle, sweepPollInterval)
	zoneGrowthSettle, sweepPollInterval = 0, time.Millisecond

	k := scenariotest.Tuple{Tenant: "u1", Zone: "external", Direction: "tx"}
	cases := []struct {
		name     string
		min, max int64
		current  float64
		wantPass bool
	}{
		{"within [min,max]", 1 << 20, 3 << 20, 2 << 20, true},
		{"below min", 1 << 20, 0, 512 << 10, false},
		{"min met, no ceiling", 1 << 20, 0, 2 << 20, true},
		{"pure upper bound satisfied", 0, 256 << 10, 100 << 10, true},
		{"pure upper bound exceeded", 0, 256 << 10, 1 << 20, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := &scenariotest.StepEnv{
				Config:   fake.Config(),
				State:    &scenariotest.RunState{},
				Metrics:  fake.HealthyMetrics{Bytes: []scenariotest.BytesSample{{TenantID: "u1", Zone: "external", Direction: "tx", Value: tc.current}}},
				Log:      slog.New(slog.DiscardHandler),
				Report:   &scenariotest.AssertReport{OK: true},
				Captured: scenariotest.Capture{Tuples: map[scenariotest.Tuple]float64{k: 0}},
			}
			step := ZoneGrowthStep{Tenant: "u1", Zone: "external", Direction: "tx",
				MinBytes: tc.min, MaxBytes: tc.max, Timeout: 10 * time.Millisecond}
			if err := step.Run(context.Background(), env); err != nil {
				t.Fatalf("Run: %v", err)
			}
			row := env.Report.Rows[len(env.Report.Rows)-1]
			if row.Pass != tc.wantPass {
				t.Errorf("Pass = %v, want %v (delta %.0f, bounds [%d,%d])", row.Pass, tc.wantPass, row.Delta, tc.min, tc.max)
			}
		})
	}
}

// tupleMetrics reports a fixed settled-tuple sum, for SettledTuplesGrewStep.
type tupleMetrics struct{ tuples float64 }

func (m tupleMetrics) Scrape(context.Context, string) (scenariotest.ScrapeResult, error) {
	return scenariotest.ScrapeResult{
		Present:       map[string]bool{scenariotest.MetricTenantSettledTuples: true, scenariotest.MetricBytesTotal: true, scenariotest.MetricAttachedInterfaces: true},
		SettledTuples: m.tuples,
	}, nil
}

func (tupleMetrics) LookupMAC(context.Context, string, string) (scenariotest.MACLookup, error) {
	return scenariotest.MACLookup{}, nil
}

func (tupleMetrics) LookupFlows(context.Context, string, string) ([]scenariotest.FlowRow, error) {
	return nil, nil
}

func TestSettledTuplesGrewStep(t *testing.T) {
	// Timing isn't under test: shrink the poll so the timeout (fail) cases
	// resolve in milliseconds.
	defer func(d time.Duration) { sweepPollInterval = d }(sweepPollInterval)
	sweepPollInterval = time.Millisecond

	cases := []struct {
		name          string
		base, current float64
		min           int64
		wantPass      bool
	}{
		{"fold fired (grew past floor)", 5, 8, 1, true},
		{"exactly at floor", 5, 6, 1, true},
		{"flat — no fold — fails", 5, 5, 1, false},
		{"grew but short of floor", 5, 6, 3, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := &scenariotest.StepEnv{
				Config:   fake.Config(),
				State:    &scenariotest.RunState{},
				Metrics:  tupleMetrics{tuples: tc.current},
				Log:      slog.New(slog.DiscardHandler),
				Report:   &scenariotest.AssertReport{OK: true},
				Captured: scenariotest.Capture{SettledTuples: tc.base},
			}
			step := SettledTuplesGrewStep{Min: tc.min, Timeout: 10 * time.Millisecond}
			if err := step.Run(context.Background(), env); err != nil {
				t.Fatalf("Run: %v", err)
			}
			row := env.Report.Rows[len(env.Report.Rows)-1]
			if row.Pass != tc.wantPass {
				t.Errorf("Pass = %v, want %v (delta %.0f, min %d)", row.Pass, tc.wantPass, row.Delta, tc.min)
			}
		})
	}
}
