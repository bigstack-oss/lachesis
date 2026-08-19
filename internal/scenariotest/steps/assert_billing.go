// Billing assertions: the four-layer counter hierarchy the product
// bills on — tenant, server and port series, their monotonicity, and
// bounded growth.
//
// Billing tiers: docs/architecture/billing.md

package steps

import (
	"context"
	"fmt"
	"time"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
)

// MonotoneStep asserts every captured tuple of Tenant is still at or
// above its captured value — the live form of the Contract 7
// series-monotonicity guarantee. One row per tuple.
//
// Contract 7: docs/architecture/contracts.md#required-contracts
type MonotoneStep struct {
	Tenant string
	Note   string
}

func (MonotoneStep) Kind() string { return "assert-monotone" }

func (s MonotoneStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	ref, err := env.Project(s.Tenant)
	if err != nil {
		return err
	}
	snap, err := env.Scrape(ctx)
	if err != nil {
		return err
	}
	cur := scenariotest.SumByTuple(snap.Bytes)
	for k, base := range env.Captured.Tuples {
		if k.Tenant != ref.ID {
			continue
		}
		env.AddRow(scenariotest.AssertRow{
			Tenant: s.Tenant, TenantID: k.Tenant,
			Zone: k.Zone, Direction: k.Direction,
			Baseline: base, Current: cur[k], Delta: cur[k] - base,
			Pass: cur[k] >= base, Note: s.Note,
		})
	}
	return nil
}

// MaxGrowthStep asserts a (tenant, zone) pair's tx and rx tuples have
// grown by less than Budget since the most recent capture. It is the
// negative-space check: "the deleted VM's bytes did not re-bucket to
// unknown" and "the reborn MAC brought no history" are both bounded-
// growth claims, differing only in target. Budget separates background
// chatter (KiBs) from a mis-attributed flow (MiBs).
type MaxGrowthStep struct {
	Tenant string // DSL project name, or a literal label like "unknown"
	Zone   string
	Budget int64
	Note   string
}

func (MaxGrowthStep) Kind() string { return "assert-max-growth" }

func (s MaxGrowthStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	label := env.TenantLabel(s.Tenant)
	snap, err := env.Scrape(ctx)
	if err != nil {
		return err
	}
	cur := scenariotest.SumByTuple(snap.Bytes)
	for _, dir := range []string{"tx", "rx"} {
		k := scenariotest.Tuple{Tenant: label, Zone: s.Zone, Direction: dir}
		env.AddRow(scenariotest.AssertRow{
			Tenant: s.Tenant, TenantID: label,
			Zone: s.Zone, Direction: dir,
			Baseline: env.Captured.Tuples[k], Current: cur[k], Delta: cur[k] - env.Captured.Tuples[k],
			Pass: cur[k]-env.Captured.Tuples[k] < float64(s.Budget),
			Note: s.Note,
		})
	}
	return nil
}

// SettledTuplesGrewStep asserts the summed settled-tuple gauges rose by
// at least Min since the last [CaptureStep] — live proof a fold fired.
// Polls, because folds land a reconcile pass after the mutation. Unlike
// the GC-only settled_flows counter this also moves on a
// reconcile-driven [state.SettleRebase].
type SettledTuplesGrewStep struct {
	Min     int64
	Timeout time.Duration
	Note    string
}

func (SettledTuplesGrewStep) Kind() string { return "assert-settled-tuples-grew" }

func (SettledTuplesGrewStep) RequiredMetrics() []string {
	return []string{scenariotest.MetricTenantSettledTuples}
}

func (s SettledTuplesGrewStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultSweepTimeout
	}
	deadline := time.Now().Add(timeout)
	var delta float64
	for {
		snap, err := env.Scrape(ctx)
		if err != nil {
			return err
		}
		delta = snap.SettledTuples - env.Captured.SettledTuples
		if delta >= float64(s.Min) || time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(sweepPollInterval):
		}
	}
	env.AddRow(scenariotest.AssertRow{
		Tenant: "settled-tuples", Zone: "-", Direction: "-",
		Baseline: env.Captured.SettledTuples, Current: env.Captured.SettledTuples + delta, Delta: delta,
		MinBytes: s.Min, Pass: delta >= float64(s.Min), Note: s.Note,
	})
	return nil
}

// PortSeriesStep asserts the per-port family attributes traffic to the
// RIGHT port_id. The coarser tiers cannot express this: after a
// same-MAC port rebirth, traffic mislabeled under the dead port leaves
// the new id's series empty. Data-dependent, so no preflight gate.
type PortSeriesStep struct {
	VM       string // DSL VM the port belongs to (for the report row)
	Port     string // the [AttachPortStep.ID] run-state handle
	MinBytes float64
	// Timeout bounds the stabilize poll (default
	// [DefaultPortSeriesTimeout]): a drive returns when the traffic is
	// SENT, but the bytes surface only at the agent's next kernel drain
	// (the scrape interval), so a single immediate scrape races the
	// tick. Poll until the sum reaches MinBytes; a timeout is the
	// failing row (traffic never attributed to this port).
	Timeout time.Duration
	Note    string
}

func (PortSeriesStep) Kind() string { return "assert-port-series" }

func (s PortSeriesStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	portID := scenariotest.LiveID(env.State.Ports, s.Port)
	if portID == "" {
		return fmt.Errorf("assert-port-series: run-state has no live port for %q", s.Port)
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultPortSeriesTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var sum float64
	for {
		snap, err := env.Scrape(ctx)
		if err != nil {
			return err
		}
		sum = 0
		for _, p := range snap.PortBytes {
			if p.PortID == portID {
				sum += p.Value
			}
		}
		if sum >= s.MinBytes {
			break
		}
		select {
		case <-ctx.Done():
			env.Log.Warn("assert-port-series: timeout — traffic never attributed to the port",
				"port", s.Port, "id", portID, "sum", sum, "min", s.MinBytes)
			env.AddRow(scenariotest.AssertRow{
				Tenant: s.VM, VM: s.VM, Zone: "-", Direction: "-",
				Baseline: s.MinBytes, Current: sum, Delta: sum - s.MinBytes,
				Pass: false, Note: s.Note,
			})
			return nil
		case <-time.After(sweepPollInterval):
		}
	}
	env.AddRow(scenariotest.AssertRow{
		Tenant: s.VM, VM: s.VM, Zone: "-", Direction: "-",
		Baseline: s.MinBytes, Current: sum, Delta: sum - s.MinBytes,
		Pass: true, Note: s.Note,
	})
	return nil
}

// zoneGrowthSettle is how long a pure upper-bound [ZoneGrowthStep]
// (MinBytes 0) waits for the drive to drain before its single read —
// bytes surface a kernel drain (scrape interval) after traffic, so a
// too-early read could let a late-arriving mis-attribution slip under
// the ceiling. A var, not a const, so tests shrink it to zero.
var zoneGrowthSettle = 15 * time.Second

// ZoneGrowthStep asserts one (tenant, zone, DIRECTION) tuple's growth
// since the last [CaptureStep] falls inside [MinBytes, MaxBytes].
// MaxBytes 0 is unbounded above.
//
// It refines [MaxGrowthStep] with a single direction and a pollable
// lower bound. With MinBytes 0 there is no floor to poll toward, so it
// waits [zoneGrowthSettle] before its single read rather than depending
// on a preceding step having drained the traffic.
type ZoneGrowthStep struct {
	Tenant    string // DSL project name, or a literal label like "unknown"
	Zone      string
	Direction string // "tx" or "rx"
	MinBytes  int64
	MaxBytes  int64
	Timeout   time.Duration
	Note      string
}

func (ZoneGrowthStep) Kind() string { return "assert-zone-growth" }

func (s ZoneGrowthStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	label := env.TenantLabel(s.Tenant)
	k := scenariotest.Tuple{Tenant: label, Zone: s.Zone, Direction: s.Direction}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultPortSeriesTimeout
	}
	// Pure upper bound: no floor to poll toward, so settle first so the
	// drive has drained before the single read (see [zoneGrowthSettle]).
	if s.MinBytes == 0 && zoneGrowthSettle > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(zoneGrowthSettle):
		}
	}
	deadline := time.Now().Add(timeout)
	var delta float64
	for {
		snap, err := env.Scrape(ctx)
		if err != nil {
			return err
		}
		delta = scenariotest.SumByTuple(snap.Bytes)[k] - env.Captured.Tuples[k]
		if delta >= float64(s.MinBytes) || time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(sweepPollInterval):
		}
	}
	pass := delta >= float64(s.MinBytes) && (s.MaxBytes <= 0 || delta <= float64(s.MaxBytes))
	env.AddRow(scenariotest.AssertRow{
		Tenant: s.Tenant, TenantID: label,
		Zone: s.Zone, Direction: s.Direction,
		Baseline: env.Captured.Tuples[k], Current: env.Captured.Tuples[k] + delta, Delta: delta,
		MinBytes: s.MinBytes,
		Pass:     pass, Note: s.Note,
	})
	return nil
}

// ServerMonotoneStep asserts every captured per-server tuple of VM is
// still at or above its captured value — [MonotoneStep]'s counterpart
// on the mortal lachesis_server_bytes_total family, and the live form
// of the mortal-series monotonicity invariant (lachesis#226/#227): a
// fold must never make a server's series observable below an earlier
// observation. One row per tuple.
type ServerMonotoneStep struct {
	VM   string
	Note string
}

func (ServerMonotoneStep) Kind() string { return "assert-server-monotone" }

// requiredMetrics deliberately returns nil: the per-server family is
// data-dependent, so a preflight gate cannot tell "agent too old" from
// "no traffic yet" and would falsely block a freshly-started agent.
// A genuinely absent family fails in Run with a clear error.
func (ServerMonotoneStep) RequiredMetrics() []string { return nil }

func (s ServerMonotoneStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	serverID, ok := scenariotest.ServerIDFor(env.State, s.VM)
	if !ok {
		return fmt.Errorf("run-state has no server for VM %q", s.VM)
	}
	snap, err := env.Scrape(ctx)
	if err != nil {
		return err
	}
	cur := scenariotest.SumByServerTuple(snap.Servers)
	rows := 0
	for k, base := range env.Captured.Servers {
		if k.Server != serverID {
			continue
		}
		rows++
		env.AddRow(scenariotest.AssertRow{
			Tenant: s.VM, VM: s.VM, ServerID: serverID,
			Zone: k.Zone, ExternalNetwork: k.Ext, Direction: k.Direction,
			Baseline: base, Current: cur[k], Delta: cur[k] - base,
			Pass: cur[k] >= base, Note: s.Note,
		})
	}
	if rows == 0 {
		return fmt.Errorf("assert-server-monotone: no captured server tuples for VM %q — capture after its traffic was driven", s.VM)
	}
	return nil
}

// MaxSettledStep asserts the ghost-fold counter grew by at most Budget
// since the last [CaptureStep]. CAUTION: a fold registers only after
// the grace plus a sweep tick, so this is meaningful only after that
// window (e.g. following an [AwaitSweepStep]). For an immediate answer
// use [MaxGhostsStep], which is not blinded by the grace.
type MaxSettledStep struct {
	Budget int64
	Note   string
}

func (MaxSettledStep) Kind() string { return "assert-max-settled" }

func (MaxSettledStep) RequiredMetrics() []string { return []string{scenariotest.MetricSettledFlows} }

func (s MaxSettledStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	snap, err := env.Scrape(ctx)
	if err != nil {
		return err
	}
	delta := snap.SettledFlows - env.Captured.SettledFlows
	env.AddRow(scenariotest.AssertRow{
		Tenant: "settled-flows", Zone: "-", Direction: "-",
		Baseline: env.Captured.SettledFlows, Current: snap.SettledFlows, Delta: delta,
		Pass: delta <= float64(s.Budget), Note: s.Note,
	})
	return nil
}
