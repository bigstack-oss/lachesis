package scenariotest

import (
	"context"
)

// The metric names scenariotest reads off the agent's /metrics. These
// are a stable exposition contract (see internal/metrics/schema.go and
// internal/netlink/metrics.go); kept as local constants so this tool
// does not import internal/bpf and its generated kernel bindings.
// Exported because the whole harness speaks them: steps declare which
// families they need, and the agentmetrics driver parses by them.
const (
	// MetricBytesTotal is the TENANT tier of the four-layer billing
	// hierarchy — the family carrying tenant_id, which every tenant
	// expectation and monotonicity assertion reads
	// (docs/architecture/billing.md).
	MetricBytesTotal         = "lachesis_tenant_bytes_total"
	MetricAttachedInterfaces = "lachesis_attached_interfaces"
	MetricAttachFailures     = "lachesis_tc_attach_failures_total"
	// MetricSettledFlows counts GlobalState rows the agent's ghost sweep
	// folded into the settled-bytes accumulator (docs/architecture/data-structures.md#settled-bytes). The
	// mac-reuse scenario polls it to know the sweep has processed a
	// deleted VM. Absent on pre-fold agents — the scenario checks
	// presence and refuses to run rather than hanging on the poll.
	MetricSettledFlows = "lachesis_gc_settled_flows_total"
	// MetricLingeringGhosts is the live count of MACs marked for deletion
	// but not yet swept (the lingering-ghost grace window). Unlike
	// MetricSettledFlows (which only moves when the sweep folds, after the
	// 60s grace), this gauge rises the instant a MAC is MarkDelete'd — the
	// immediate signal that something was marked gone (docs/architecture/data-structures.md#lingering-ghost).
	MetricLingeringGhosts = "lachesis_lingering_ghosts_active"
	// MetricCountersReset is the agent's state-restart epoch — the
	// discontinuity marker behind the cold-restart scenario
	// (docs/architecture/boot-and-recovery.md#counters-reset-epoch). Constant per
	// process; a changed value across an agent restart means the agent
	// declared its counter baselines incomparable with what preceded them.
	MetricCountersReset = "lachesis_agent_counters_reset_timestamp_seconds"
	// MetricServerBytesTotal is the per-server billing family
	// (docs/architecture/billing.md). Absent on agents predating the per-server export;
	// only expectations with a VM target need it, and assert refuses
	// those against agents that don't expose it.
	MetricServerBytesTotal = "lachesis_server_bytes_total"
	// MetricPortBytesTotal is the per-port drill-down family — the
	// mortal leaf of the four-layer hierarchy (docs/architecture/billing.md).
	// Data-dependent like the server family (a series exists only once
	// its port carries attributed traffic), so no step preflight-gates
	// on it; PortSeriesStep fails with a clear row instead.
	MetricPortBytesTotal = "lachesis_port_bytes_total"
	// MetricNeutronAnomalies is the per-class topology-anomaly gauge.
	// AssertAnomalyStep polls it; the class vocabulary is the agent's
	// (cycle, ambiguity, …, multi_external_path).
	MetricNeutronAnomalies = "lachesis_neutron_anomalies"
	// The three settled-accumulator tuple gauges of the four-layer model
	// (docs/architecture/data-structures.md#settled-bytes). Unlike
	// MetricSettledFlows (which only the GC sweep moves), these rise
	// whenever ANY fold adds a tuple — including a reconcile-driven
	// [state.SettleRebase] from an attribution change on a LIVE port. The
	// port-reassignment / router-regateway scenarios read their SUM to
	// prove the reconcile fold fired.
	MetricTenantSettledTuples = "lachesis_state_tenant_settled_tuples"
	MetricServerSettledTuples = "lachesis_state_server_settled_tuples"
	MetricTotalSettledTuples  = "lachesis_state_total_settled_tuples"
	// MetricUnresolvedResolved counts UnresolvedBuffer late-binding
	// successes: a flow whose MAC was unknown when its first bytes
	// arrived, then became known within the TTL and was re-attributed to
	// the right tenant (docs/architecture/data-structures.md#userspace-structures).
	// The unresolved-latebind scenario reads it to prove the buffer
	// resolved rather than expired to unknown.
	MetricUnresolvedResolved = "lachesis_unresolved_resolved_total"
	// MetricGCEvictions counts map entries the GC evicted, split by a
	// `reason` label. Only reason="pressure_relief" is the telemetry_map
	// fill-watermark eviction EvictionsGrewStep asserts on; the family
	// also carries ttl (mac_tenant_map ghost expiry) and
	// ghost_residual_flow, so it must be read per-reason rather than
	// summed whole
	// (docs/architecture/data-structures.md#kernel-side-bpf-maps).
	MetricGCEvictions = "lachesis_gc_evictions_total"
	// ReasonPressureRelief is the [MetricGCEvictions] `reason` value for a
	// telemetry_map fill-watermark eviction.
	ReasonPressureRelief = "pressure_relief"
)

// BytesSample is one lachesis_tenant_bytes_total series: the {tenant_id, zone,
// external_network, direction} label tuple and its cumulative value.
// JSON-tagged because drive persists the pre-traffic snapshot into the
// run-state file for assert to diff against. ExternalNetwork is empty
// on samples parsed from pre-label agents and on old run-states — both
// aggregate identically to "any".
type BytesSample struct {
	TenantID        string  `json:"tenant_id"`
	Zone            string  `json:"zone"`
	ExternalNetwork string  `json:"external_network,omitempty"`
	Direction       string  `json:"direction"`
	Value           float64 `json:"value"`
	// Node is the configured host of the agent that exposed this
	// series, stamped by [SampleAcross] — what lets a node-targeted
	// [Expect] evaluate one agent's tap instead of the cluster sum.
	// Empty on samples from run-states predating per-node capture.
	Node string `json:"node,omitempty"`
}

// ServerSample is one lachesis_server_bytes_total series — the mortal
// per-server billing family (docs/architecture/billing.md). Captured alongside
// BytesSample so Expect entries with a VM target can lower-bound a
// specific server's delta.
type ServerSample struct {
	ServerID        string  `json:"server_id"`
	TenantID        string  `json:"tenant_id"`
	Zone            string  `json:"zone"`
	ExternalNetwork string  `json:"external_network,omitempty"`
	Direction       string  `json:"direction"`
	Value           float64 `json:"value"`
	// Node mirrors [BytesSample.Node].
	Node string `json:"node,omitempty"`
}

// PortSample is one lachesis_port_bytes_total series — the mortal
// per-port leaf (docs/architecture/billing.md). PortSeriesStep uses it
// to assert which port_id actually carried driven traffic.
type PortSample struct {
	PortID    string  `json:"port_id"`
	ServerID  string  `json:"server_id"`
	Zone      string  `json:"zone"`
	Direction string  `json:"direction"`
	Value     float64 `json:"value"`
	// Node mirrors [BytesSample.Node].
	Node string `json:"node,omitempty"`
}

// ScrapeResult is one agent's /metrics scrape: which of the metrics
// scenariotest depends on are present (for preflight), plus the
// agent-health gauge values and bytes series (for the attach gate and
// assert).
type ScrapeResult struct {
	Present            map[string]bool
	AttachedInterfaces float64
	AttachFailures     float64
	SettledFlows       float64
	SettledTuples      float64
	UnresolvedResolved float64
	LingeringGhosts    float64
	Bytes              []BytesSample
	Servers            []ServerSample
	PortBytes          []PortSample
	// PressureReliefEvictions is lachesis_gc_evictions_total for the
	// pressure_relief reason alone.
	PressureReliefEvictions float64
	// Anomalies is lachesis_neutron_anomalies broken out by its
	// `class` label.
	Anomalies map[string]float64
	// CountersResetEpoch is this agent's state-restart epoch gauge
	// (0 when the family is absent — a pre-epoch build).
	CountersResetEpoch float64
}

// MetricsSnapshot aggregates one scrape across all configured agents:
// the attach-gauge and attach-failure sums power the `up` attach-ready
// gate, and the bytes samples back the (later) assert delta check.
type MetricsSnapshot struct {
	AttachedInterfaces float64
	AttachFailures     float64
	SettledFlows       float64
	SettledTuples      float64
	UnresolvedResolved float64
	LingeringGhosts    float64
	Bytes              []BytesSample
	Servers            []ServerSample
	PortBytes          []PortSample
	// PressureReliefEvictions sums pressure-relief evictions across all
	// agents.
	PressureReliefEvictions float64
	// Anomalies sums each anomaly class across all agents.
	Anomalies map[string]float64
	// CountersResetEpochs is each agent's state-restart epoch, keyed by
	// agent host — per-instance by nature, never summed.
	CountersResetEpochs map[string]float64
}

// MACLookup is one agent's answer to "have you learned this MAC?" —
// the `mac_tenant_map` section of its /debug/lookup response. A Found
// hit means the reconcile pass that learned the MAC has committed, so
// the kernel-side insert (userspace-then-kernel, same pass) has been
// performed too.
type MACLookup struct {
	Found    bool
	TenantID string
	// PortID is the Neutron port the agent currently binds the MAC to
	// — AwaitPortBindingStep polls it after a same-MAC port rebirth.
	PortID string
}

// MetricsSource scrapes and parses one agent's observability surfaces:
// /metrics (Scrape) and the /debug/lookup MAC query (LookupMAC, used
// by drive's MAC-learn gate). preflight, realize, and drive consume it
// through this seam so they are testable without a live agent. url is
// always the agent's metrics URL; the live implementation derives the
// debug endpoint from it.
//
// The live implementation is internal/scenariotest/agentmetrics.
type MetricsSource interface {
	Scrape(ctx context.Context, url string) (ScrapeResult, error)
	LookupMAC(ctx context.Context, url, mac string) (MACLookup, error)
	// LookupFlows returns the agent's live flow rows carrying mac on
	// either side (/debug/flows) — the flow-granular evidence behind
	// AssertFlowPeerStep: which peer actually carried driven bytes.
	LookupFlows(ctx context.Context, url, mac string) ([]FlowRow, error)
}

// FlowRow is one live GlobalState row as /debug/flows reports it.
type FlowRow struct {
	SrcMAC    string  `json:"src_mac"`
	DstMAC    string  `json:"dst_mac"`
	Direction string  `json:"direction"`
	Zone      string  `json:"zone"`
	Bytes     float64 `json:"bytes"`
	Packets   float64 `json:"packets"`
}

// SampleAcross scrapes every configured agent and aggregates the
// health gauges (each compute node exposes its own) plus the bytes
// series, stamping each sample with its agent's host so node-targeted
// expectations can tell the taps apart.
func SampleAcross(ctx context.Context, src MetricsSource, agents []AgentConfig) (MetricsSnapshot, error) {
	var snap MetricsSnapshot
	for _, a := range agents {
		r, err := src.Scrape(ctx, a.MetricsURL)
		if err != nil {
			return MetricsSnapshot{}, err
		}
		snap.AttachedInterfaces += r.AttachedInterfaces
		snap.AttachFailures += r.AttachFailures
		snap.SettledFlows += r.SettledFlows
		snap.SettledTuples += r.SettledTuples
		snap.UnresolvedResolved += r.UnresolvedResolved
		snap.PressureReliefEvictions += r.PressureReliefEvictions
		snap.LingeringGhosts += r.LingeringGhosts
		for _, s := range r.Bytes {
			s.Node = a.Host
			snap.Bytes = append(snap.Bytes, s)
		}
		for _, s := range r.Servers {
			s.Node = a.Host
			snap.Servers = append(snap.Servers, s)
		}
		for _, s := range r.PortBytes {
			s.Node = a.Host
			snap.PortBytes = append(snap.PortBytes, s)
		}
		// Anomaly counts are a topology-global fact: every agent derives
		// them from the same Neutron snapshot, so all agents report the
		// same value. Take the max across agents (not the sum, which would
		// multiply the count by the cluster size), so an anomaly bound
		// stays cluster-size-independent — and a lagging agent that hasn't
		// resynced yet reads as the lower value, letting the poll wait.
		for class, v := range r.Anomalies {
			if snap.Anomalies == nil {
				snap.Anomalies = map[string]float64{}
			}
			if v > snap.Anomalies[class] {
				snap.Anomalies[class] = v
			}
		}
		if snap.CountersResetEpochs == nil {
			snap.CountersResetEpochs = map[string]float64{}
		}
		snap.CountersResetEpochs[a.Host] = r.CountersResetEpoch
	}
	return snap, nil
}
