// Agent-internal assertions: the gauges and counters that prove the
// agent's own machinery ran — the ghost sweep, the unresolved buffer's
// late binding, GC pressure relief, the counters-reset epoch, and the
// topology-anomaly classes.

package steps

import (
	"context"
	"fmt"
	"time"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
)

// sweepPollInterval is the pause between [AwaitSweepStep] polls. A var,
// not a const, so poll-loop tests can shrink it.
var sweepPollInterval = 5 * time.Second

// AwaitSweepStep blocks until the ghost sweep has processed a deleted
// VM/NIC. Always set ForMACOf: it polls /debug/lookup for that MAC and
// returns once it stops resolving, which the sweep does LAST — after
// the fold — so it is a precise per-entity signal.
//
// The ForMACOf-empty fallback waits on the global settled_flows
// counter, which is only trustworthy on a quiet single-tenant agent;
// elsewhere other tenants' folds move it and the wait returns before
// THIS entity's grace elapses.
type AwaitSweepStep struct {
	// ForMACOf is the DSL id of the VM or NIC whose deleted MAC's fold to
	// wait for — recorded by the preceding [DeleteVMStep] / [DetachPortStep].
	ForMACOf string
	Timeout  time.Duration
}

func (AwaitSweepStep) Kind() string { return "await-sweep" }

func (s AwaitSweepStep) RequiredMetrics() []string {
	if s.ForMACOf != "" {
		return nil // uses /debug/lookup, not a metric family
	}
	return []string{scenariotest.MetricSettledFlows}
}

func (s AwaitSweepStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultSweepTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if s.ForMACOf != "" {
		return s.awaitMACSwept(ctx, env, timeout)
	}
	env.Log.Warn("await-sweep: waiting on the GLOBAL settled counter — unreliable on a shared agent (lachesis#240); set ForMACOf", "settled_flows_above", env.Captured.SettledFlows, "timeout", timeout)
	for {
		snap, err := env.Scrape(ctx)
		if err != nil {
			return err
		}
		if snap.SettledFlows > env.Captured.SettledFlows {
			env.Log.Info("await-sweep: observed", "settled_flows_from", env.Captured.SettledFlows, "settled_flows_to", snap.SettledFlows)
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("ghost sweep not observed within %s (settled_flows still %.0f): %w",
				timeout, snap.SettledFlows, ctx.Err())
		case <-time.After(sweepPollInterval):
		}
	}
}

// awaitMACSwept polls every agent's /debug/lookup for the MAC recorded
// against ForMACOf and returns once it resolves on none of them — the
// userspace metadata delete that ends the ghost sweep, which happens
// after the fold.
func (s AwaitSweepStep) awaitMACSwept(ctx context.Context, env *scenariotest.StepEnv, timeout time.Duration) error {
	mac, err := env.VMMAC(ctx, s.ForMACOf)
	if err != nil {
		return fmt.Errorf("await-sweep: no MAC known for %q (delete or detach it first): %w", s.ForMACOf, err)
	}
	env.Log.Info("await-sweep: waiting for MAC to leave metadata", "for", s.ForMACOf, "mac", mac, "timeout", timeout)
	everFound := false // did the MAC resolve on any agent at any poll?
	var lastErr error  // most recent transient lookup failure, surfaced on timeout
	for {
		gone := true
		for _, u := range scenariotest.AgentURLs(env.Config) {
			res, err := env.Metrics.LookupMAC(ctx, u, mac)
			if err != nil {
				// A momentarily-unreachable agent can't confirm the MAC is
				// gone there — keep waiting rather than abort, so one bad
				// scrape on a multi-node cluster doesn't fail the wait.
				lastErr = err
				gone = false
				continue
			}
			if res.Found {
				everFound = true
				gone = false
			}
		}
		if gone {
			if !everFound {
				// The MAC never resolved on any agent during the wait: it was
				// already swept before the first poll, or ForMACOf points at
				// an entity whose traffic was never driven/learned. Nothing to
				// wait for — return, but loudly, since a silent pass here would
				// mask a mis-targeted ForMACOf.
				env.Log.Warn("await-sweep: MAC never in metadata during the wait — nothing to await (already swept, or ForMACOf never learned)",
					"for", s.ForMACOf, "mac", mac)
				return nil
			}
			env.Log.Info("await-sweep: swept (MAC gone from metadata)", "for", s.ForMACOf, "mac", mac)
			return nil
		}
		select {
		case <-ctx.Done():
			if lastErr != nil {
				return fmt.Errorf("await-sweep: MAC %s (%s) not confirmed gone after %s (last lookup error: %v): %w", mac, s.ForMACOf, timeout, lastErr, ctx.Err())
			}
			return fmt.Errorf("await-sweep: MAC %s (%s) still in metadata after %s — ghost not swept: %w", mac, s.ForMACOf, timeout, ctx.Err())
		case <-time.After(sweepPollInterval):
		}
	}
}

// AssertFlowPeerStep proves WHICH interface carried the bytes, by
// summing /debug/flows rows that carry the router interface's MAC. A
// label assertion cannot do this: a fallback-tier flow's
// external_network label equals the default route's, so only the peer
// MAC distinguishes "rode the intended router" from "rode the default
// route".
type AssertFlowPeerStep struct {
	Router   string // DSL router id
	Via      string // the Attach IP naming which interface of the router
	Zone     string
	MinBytes int64
	Note     string
}

func (AssertFlowPeerStep) Kind() string { return "assert-flow-peer" }

func (s AssertFlowPeerStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	// The DSL declares the interface port; the run-state ref carries
	// the Neutron-assigned MAC realize recorded.
	snap := env.Scenario.Builder.Build()
	dslPort := ""
	for _, p := range snap.Ports {
		if p.DeviceOwner == "network:router_interface" && p.DeviceID == s.Router &&
			len(p.FixedIPs) > 0 && p.FixedIPs[0].IPAddress == s.Via {
			dslPort = p.ID
		}
	}
	if dslPort == "" {
		return fmt.Errorf("scenario declares no %s interface at %s", s.Router, s.Via)
	}
	mac := ""
	for _, ref := range env.State.Ports {
		if ref.DSLID == dslPort {
			mac = ref.MAC
		}
	}
	if mac == "" {
		return fmt.Errorf("run-state has no MAC for %s (port %s)", s.Router, dslPort)
	}

	var total float64
	for _, u := range scenariotest.AgentURLs(env.Config) {
		rows, err := env.Metrics.LookupFlows(ctx, u, mac)
		if err != nil {
			return fmt.Errorf("assert-flow-peer: %w", err)
		}
		for _, r := range rows {
			if r.Zone == s.Zone {
				total += r.Bytes
			}
		}
	}
	env.AddRow(scenariotest.AssertRow{
		Tenant: "flow-peer", Zone: s.Zone, Direction: "-",
		Current: total, Delta: total, MinBytes: s.MinBytes,
		Pass: total >= float64(s.MinBytes),
		Note: s.Note,
	})
	env.Log.Info("assert-flow-peer", "router", s.Router, "via", s.Via, "mac", mac, "zone", s.Zone, "bytes", total, "min", s.MinBytes)
	return nil
}

// AssertAnomalyStep polls the agents' summed
// lachesis_neutron_anomalies{class=Class} until Min ≤ value ≤ Max
// (both inclusive) or Timeout (default [DefaultAnomalyTimeout])
// fires, then records one report row either way. Polling — rather
// than a one-shot read — because the gauge only updates when a
// reconcile pass commits the topology change the step just made.
type AssertAnomalyStep struct {
	Class   string
	Min     int64
	Max     int64
	Timeout time.Duration
	Note    string
}

func (AssertAnomalyStep) Kind() string { return "assert-anomaly" }

func (AssertAnomalyStep) RequiredMetrics() []string {
	return []string{scenariotest.MetricNeutronAnomalies}
}

func (s AssertAnomalyStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultAnomalyTimeout
	}
	env.Log.Info("assert-anomaly", "class", s.Class, "min", s.Min, "max", s.Max, "timeout", timeout)
	deadline := time.Now().Add(timeout)
	var last float64
	for {
		snap, err := env.Scrape(ctx)
		if err != nil {
			return err
		}
		last = snap.Anomalies[s.Class]
		if last >= float64(s.Min) && last <= float64(s.Max) {
			break
		}
		if time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(anomalyPollInterval):
		}
	}
	env.AddRow(scenariotest.AssertRow{
		Tenant: "anomaly", Zone: s.Class, Direction: "-",
		Current: last, Delta: last, MinBytes: s.Min,
		Pass: last >= float64(s.Min) && last <= float64(s.Max),
		Note: s.Note,
	})
	return nil
}

// EpochStep asserts the counters-reset epoch's behaviour across the
// most recent [CaptureStep]: Changed false pins the warm-restart
// contract (the stored epoch carries forward — the gauge keeps naming
// the last TRUE state restart), Changed true pins the cold-boot one
// (an empty-WAL start stamps a fresh, later epoch, scrapable as soon
// as /metrics answers — the readiness gate inside [RestartAgentStep]
// already proved that timing before this step runs).
type EpochStep struct {
	// Node selects the agent, as in [RestartAgentStep]. Empty = the
	// sole agent.
	Node string
	// Changed is the expectation: true = a fresh epoch was stamped
	// (strictly later than the captured one), false = the captured
	// epoch carried through unchanged.
	Changed bool
	Note    string
}

func (EpochStep) Kind() string { return "assert-epoch" }

func (EpochStep) RequiredMetrics() []string {
	return []string{scenariotest.MetricCountersReset}
}

func (s EpochStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	agent, err := scenariotest.AgentForNode(env.Config, s.Node)
	if err != nil {
		return fmt.Errorf("assert-epoch: %w", err)
	}
	base, ok := env.Captured.Epochs[agent.Host]
	if !ok {
		return fmt.Errorf("assert-epoch: no captured epoch for %s — add a CaptureStep before the restart", agent.Host)
	}
	res, err := env.Metrics.Scrape(ctx, agent.MetricsURL)
	if err != nil {
		return fmt.Errorf("assert-epoch: scrape %s: %w", agent.MetricsURL, err)
	}
	cur := res.CountersResetEpoch
	pass := cur == base && cur != 0
	if s.Changed {
		pass = cur > base
	}
	env.AddRow(scenariotest.AssertRow{
		Tenant:   agent.Host,
		Zone:     "epoch",
		Baseline: base, Current: cur, Delta: cur - base,
		Pass: pass, Note: s.Note,
	})
	return nil
}

// ResolvedGrewStep asserts the UnresolvedBuffer late-binding counter
// (lachesis_unresolved_resolved_total) rose by at least Min since the
// most recent [CaptureStep] — the proof that a flow's bytes were parked
// unknown and then re-attributed to the right tenant WITHIN the TTL (not
// expired to unknown). Polls until the floor is met or Timeout (default
// [DefaultSweepTimeout]) records a failing row, because resolution lands
// a reconcile-plus-scrape after the MAC becomes known.
type ResolvedGrewStep struct {
	Min     int64
	Timeout time.Duration
	Note    string
}

func (ResolvedGrewStep) Kind() string { return "assert-resolved-grew" }

func (ResolvedGrewStep) RequiredMetrics() []string {
	return []string{scenariotest.MetricUnresolvedResolved}
}

func (s ResolvedGrewStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
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
		delta = snap.UnresolvedResolved - env.Captured.Resolved
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
		Tenant: "unresolved-resolved", Zone: "-", Direction: "-",
		Baseline: env.Captured.Resolved, Current: env.Captured.Resolved + delta, Delta: delta,
		MinBytes: s.Min, Pass: delta >= float64(s.Min), Note: s.Note,
	})
	return nil
}

// EvictionsGrewStep asserts the pressure-relief eviction counter rose
// by at least Min since the last [CaptureStep]. Reads the
// pressure_relief reason ALONE — the family also carries ttl and
// ghost_residual_flow, and conflating them lets a ghost expiry pass as
// pressure relief.
//
// Its value is in pairing with the byte assertions around it: evicted
// bytes must already be in GlobalState, so the tenant's total keeps
// growing across the eviction. Polls, because relief runs on the scrape
// tick.
type EvictionsGrewStep struct {
	Min     int64
	Timeout time.Duration
	Note    string
}

func (EvictionsGrewStep) Kind() string { return "assert-evictions-grew" }

func (EvictionsGrewStep) RequiredMetrics() []string { return []string{scenariotest.MetricGCEvictions} }

func (s EvictionsGrewStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
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
		delta = snap.PressureReliefEvictions - env.Captured.Evictions
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
		Tenant: "gc-pressure-relief", Zone: "-", Direction: "-",
		Baseline: env.Captured.Evictions, Current: env.Captured.Evictions + delta, Delta: delta,
		MinBytes: s.Min, Pass: delta >= float64(s.Min), Note: s.Note,
	})
	return nil
}

// MaxGhostsStep asserts the lingering-ghost gauge grew by at most
// Budget since the last [CaptureStep]. Unlike [MaxSettledStep] the
// gauge rises the instant a MAC is marked, before any grace, so
// Budget 0 across a live migration genuinely proves nothing was
// ghosted. Delta from capture, so a pre-existing ghost cannot
// false-fail it.
type MaxGhostsStep struct {
	Budget int64
	Note   string
}

func (MaxGhostsStep) Kind() string { return "assert-max-ghosts" }

func (MaxGhostsStep) RequiredMetrics() []string { return []string{scenariotest.MetricLingeringGhosts} }

func (s MaxGhostsStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	snap, err := env.Scrape(ctx)
	if err != nil {
		return err
	}
	delta := snap.LingeringGhosts - env.Captured.Ghosts
	env.AddRow(scenariotest.AssertRow{
		Tenant: "lingering-ghosts", Zone: "-", Direction: "-",
		Baseline: env.Captured.Ghosts, Current: snap.LingeringGhosts, Delta: delta,
		Pass: delta <= float64(s.Budget), Note: s.Note,
	})
	return nil
}
