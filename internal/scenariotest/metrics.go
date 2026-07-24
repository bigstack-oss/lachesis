package scenariotest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

// The metric names scenariotest reads off the agent's /metrics. These
// are a stable exposition contract (see internal/metrics/schema.go and
// internal/netlink/metrics.go); kept as local constants so this tool
// does not import internal/bpf and its generated kernel bindings.
const (
	// metricBytesTotal is the TENANT tier of the four-layer billing
	// hierarchy — the family carrying tenant_id, which every tenant
	// expectation and monotonicity assertion reads
	// (docs/architecture/billing.md).
	metricBytesTotal         = "lachesis_tenant_bytes_total"
	metricAttachedInterfaces = "lachesis_attached_interfaces"
	metricAttachFailures     = "lachesis_tc_attach_failures_total"
	// metricSettledFlows counts GlobalState rows the agent's ghost sweep
	// folded into the settled-bytes accumulator (docs/architecture/data-structures.md#settled-bytes). The
	// mac-reuse scenario polls it to know the sweep has processed a
	// deleted VM. Absent on pre-fold agents — the scenario checks
	// presence and refuses to run rather than hanging on the poll.
	metricSettledFlows = "lachesis_gc_settled_flows_total"
	// metricLingeringGhosts is the live count of MACs marked for deletion
	// but not yet swept (the lingering-ghost grace window). Unlike
	// metricSettledFlows (which only moves when the sweep folds, after the
	// 60s grace), this gauge rises the instant a MAC is MarkDelete'd — the
	// immediate signal that something was marked gone (docs/architecture/data-structures.md#lingering-ghost).
	metricLingeringGhosts = "lachesis_lingering_ghosts_active"
	// metricServerBytesTotal is the per-server billing family
	// (docs/architecture/billing.md). Absent on agents predating the per-server export;
	// only expectations with a VM target need it, and assert refuses
	// those against agents that don't expose it.
	metricServerBytesTotal = "lachesis_server_bytes_total"
	// metricPortBytesTotal is the per-port drill-down family — the
	// mortal leaf of the four-layer hierarchy (docs/architecture/billing.md).
	// Data-dependent like the server family (a series exists only once
	// its port carries attributed traffic), so no step preflight-gates
	// on it; [PortSeriesStep] fails with a clear row instead.
	metricPortBytesTotal = "lachesis_port_bytes_total"
	// metricNeutronAnomalies is the per-class topology-anomaly gauge.
	// [AssertAnomalyStep] polls it; the class vocabulary is the agent's
	// (cycle, ambiguity, …, multi_external_path).
	metricNeutronAnomalies = "lachesis_neutron_anomalies"
	// The three settled-accumulator tuple gauges of the four-layer model
	// (docs/architecture/data-structures.md#settled-bytes). Unlike
	// metricSettledFlows (which only the GC sweep moves), these rise
	// whenever ANY fold adds a tuple — including a reconcile-driven
	// [state.SettleRebase] from an attribution change on a LIVE port. The
	// port-reassignment / router-regateway scenarios read their SUM to
	// prove the reconcile fold fired.
	metricTenantSettledTuples = "lachesis_state_tenant_settled_tuples"
	metricServerSettledTuples = "lachesis_state_server_settled_tuples"
	metricTotalSettledTuples  = "lachesis_state_total_settled_tuples"
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
	// series, stamped by [sampleAcross] — what lets a node-targeted
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
// per-port leaf (docs/architecture/billing.md). [PortSeriesStep] uses it
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
	LingeringGhosts    float64
	Bytes              []BytesSample
	Servers            []ServerSample
	PortBytes          []PortSample
	// Anomalies is lachesis_neutron_anomalies broken out by its
	// `class` label.
	Anomalies map[string]float64
}

// MetricsSnapshot aggregates one scrape across all configured agents:
// the attach-gauge and attach-failure sums power the `up` attach-ready
// gate, and the bytes samples back the (later) assert delta check.
type MetricsSnapshot struct {
	AttachedInterfaces float64
	AttachFailures     float64
	SettledFlows       float64
	SettledTuples      float64
	LingeringGhosts    float64
	Bytes              []BytesSample
	Servers            []ServerSample
	PortBytes          []PortSample
	// Anomalies sums each anomaly class across all agents.
	Anomalies map[string]float64
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
	// — [AwaitPortBindingStep] polls it after a same-MAC port rebirth.
	PortID string
}

// MetricsSource scrapes and parses one agent's observability surfaces:
// /metrics (Scrape) and the /debug/lookup MAC query (LookupMAC, used
// by drive's MAC-learn gate). preflight, realize, and drive consume it
// through this seam so they are testable without a live agent. url is
// always the agent's metrics URL; the live implementation derives the
// debug endpoint from it.
type MetricsSource interface {
	Scrape(ctx context.Context, url string) (ScrapeResult, error)
	LookupMAC(ctx context.Context, url, mac string) (MACLookup, error)
	// LookupFlows returns the agent's live flow rows carrying mac on
	// either side (/debug/flows) — the flow-granular evidence behind
	// [AssertFlowPeerStep]: which peer actually carried driven bytes.
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

// HTTPMetrics is the live [MetricsSource]: it GETs each /metrics URL
// and parses the Prometheus text exposition format.
type HTTPMetrics struct {
	Client *http.Client
}

// NewHTTPMetrics returns an [HTTPMetrics] using c, or http.DefaultClient
// when c is nil.
func NewHTTPMetrics(c *http.Client) *HTTPMetrics {
	if c == nil {
		c = http.DefaultClient
	}
	return &HTTPMetrics{Client: c}
}

// Scrape fetches and parses one agent's /metrics.
func (h *HTTPMetrics) Scrape(ctx context.Context, url string) (ScrapeResult, error) {
	fams, err := h.fetch(ctx, url)
	if err != nil {
		return ScrapeResult{}, err
	}
	r := ScrapeResult{Present: map[string]bool{}}
	for _, n := range []string{metricBytesTotal, metricAttachedInterfaces, metricAttachFailures,
		metricSettledFlows, metricLingeringGhosts, metricServerBytesTotal, metricNeutronAnomalies,
		metricTenantSettledTuples} {
		_, ok := fams[n]
		r.Present[n] = ok
	}
	r.AttachedInterfaces = familySum(fams, metricAttachedInterfaces)
	r.AttachFailures = familySum(fams, metricAttachFailures)
	r.SettledFlows = familySum(fams, metricSettledFlows)
	r.SettledTuples = familySum(fams, metricTenantSettledTuples) +
		familySum(fams, metricServerSettledTuples) +
		familySum(fams, metricTotalSettledTuples)
	r.LingeringGhosts = familySum(fams, metricLingeringGhosts)
	r.Bytes = bytesSamples(fams)
	r.Servers = serverSamples(fams)
	r.PortBytes = portSamples(fams)
	r.Anomalies = anomalySamples(fams)
	return r, nil
}

// LookupMAC implements the MAC half of [MetricsSource] against the
// agent's /debug/lookup endpoint, derived from the metrics URL (the
// agent serves /metrics and /debug on one listener). A 200 with no
// mac_tenant_map section decodes as not-found — the endpoint reports
// what it saw, it does not 404 on misses.
func (h *HTTPMetrics) LookupMAC(ctx context.Context, metricsURL, mac string) (MACLookup, error) {
	base, ok := strings.CutSuffix(metricsURL, "/metrics")
	if !ok {
		return MACLookup{}, fmt.Errorf("lookup: metrics URL %q does not end in /metrics — cannot derive /debug/lookup (check cluster.agents[].metrics_url)", metricsURL)
	}
	u := base + "/debug/lookup?mac=" + url.QueryEscape(mac)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return MACLookup{}, fmt.Errorf("lookup: build request %s: %w", u, err)
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		return MACLookup{}, fmt.Errorf("lookup: get %s: %w", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return MACLookup{}, fmt.Errorf("lookup: get %s: status %d", u, resp.StatusCode)
	}
	var body struct {
		MAC *struct {
			Found    bool   `json:"found"`
			TenantID string `json:"tenant_id"`
			PortID   string `json:"port_id"`
		} `json:"mac_tenant_map"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return MACLookup{}, fmt.Errorf("lookup: decode %s: %w", u, err)
	}
	if body.MAC == nil {
		return MACLookup{}, nil
	}
	return MACLookup{Found: body.MAC.Found, TenantID: body.MAC.TenantID, PortID: body.MAC.PortID}, nil
}

// LookupFlows implements the flow-query half of [MetricsSource]
// against /debug/flows, derived from the metrics URL like [LookupMAC].
func (h *HTTPMetrics) LookupFlows(ctx context.Context, metricsURL, mac string) ([]FlowRow, error) {
	base, ok := strings.CutSuffix(metricsURL, "/metrics")
	if !ok {
		return nil, fmt.Errorf("flows: metrics URL %q does not end in /metrics — cannot derive /debug/flows (check cluster.agents[].metrics_url)", metricsURL)
	}
	u := base + "/debug/flows?mac=" + url.QueryEscape(mac)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("flows: build request %s: %w", u, err)
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("flows: get %s: %w", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("flows: get %s: status %d", u, resp.StatusCode)
	}
	var body struct {
		Rows []FlowRow `json:"rows"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("flows: decode %s: %w", u, err)
	}
	return body.Rows, nil
}

// sampleAcross scrapes every configured agent and aggregates the
// health gauges (each compute node exposes its own) plus the bytes
// series, stamping each sample with its agent's host so node-targeted
// expectations can tell the taps apart.
func sampleAcross(ctx context.Context, src MetricsSource, agents []AgentConfig) (MetricsSnapshot, error) {
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
	}
	return snap, nil
}

func (h *HTTPMetrics) fetch(ctx context.Context, url string) (map[string]*dto.MetricFamily, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("metrics: build request %s: %w", url, err)
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("metrics: scrape %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metrics: scrape %s: status %d", url, resp.StatusCode)
	}
	// NewTextParser is required: a zero-value TextParser carries an
	// unset name-validation scheme and panics. UTF8 is the library's
	// current default and accepts the agent's metric names.
	parser := expfmt.NewTextParser(model.UTF8Validation)
	fams, err := parser.TextToMetricFamilies(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("metrics: parse %s: %w", url, err)
	}
	return fams, nil
}

// familySum totals every sample in a metric family, whatever its
// value type. Used for the attach gauge and the attach-failure
// counter, neither of which scenariotest cares to break down by label.
func familySum(fams map[string]*dto.MetricFamily, name string) float64 {
	fam, ok := fams[name]
	if !ok {
		return 0
	}
	var total float64
	for _, m := range fam.GetMetric() {
		total += sampleValue(m)
	}
	return total
}

// bytesSamples extracts every lachesis_tenant_bytes_total series with its
// {tenant_id, zone, external_network, direction} labels.
func bytesSamples(fams map[string]*dto.MetricFamily) []BytesSample {
	fam, ok := fams[metricBytesTotal]
	if !ok {
		return nil
	}
	out := make([]BytesSample, 0, len(fam.GetMetric()))
	for _, m := range fam.GetMetric() {
		s := BytesSample{Value: sampleValue(m)}
		for _, lp := range m.GetLabel() {
			switch lp.GetName() {
			case "tenant_id":
				s.TenantID = lp.GetValue()
			case "zone":
				s.Zone = lp.GetValue()
			case "external_network":
				s.ExternalNetwork = lp.GetValue()
			case "direction":
				s.Direction = lp.GetValue()
			}
		}
		out = append(out, s)
	}
	return out
}

// serverSamples extracts every lachesis_server_bytes_total series.
// Returns nil against agents predating the per-server family.
func serverSamples(fams map[string]*dto.MetricFamily) []ServerSample {
	fam, ok := fams[metricServerBytesTotal]
	if !ok {
		return nil
	}
	out := make([]ServerSample, 0, len(fam.GetMetric()))
	for _, m := range fam.GetMetric() {
		s := ServerSample{Value: sampleValue(m)}
		for _, lp := range m.GetLabel() {
			switch lp.GetName() {
			case "server_id":
				s.ServerID = lp.GetValue()
			case "tenant_id":
				s.TenantID = lp.GetValue()
			case "zone":
				s.Zone = lp.GetValue()
			case "external_network":
				s.ExternalNetwork = lp.GetValue()
			case "direction":
				s.Direction = lp.GetValue()
			}
		}
		out = append(out, s)
	}
	return out
}

// portSamples extracts every lachesis_port_bytes_total series. Returns
// nil against agents predating the port family.
func portSamples(fams map[string]*dto.MetricFamily) []PortSample {
	fam, ok := fams[metricPortBytesTotal]
	if !ok {
		return nil
	}
	out := make([]PortSample, 0, len(fam.GetMetric()))
	for _, m := range fam.GetMetric() {
		s := PortSample{Value: sampleValue(m)}
		for _, lp := range m.GetLabel() {
			switch lp.GetName() {
			case "port_id":
				s.PortID = lp.GetValue()
			case "server_id":
				s.ServerID = lp.GetValue()
			case "zone":
				s.Zone = lp.GetValue()
			case "direction":
				s.Direction = lp.GetValue()
			}
		}
		out = append(out, s)
	}
	return out
}

// anomalySamples extracts lachesis_neutron_anomalies by its class
// label. nil when the family is absent (pre-anomaly-gauge agents).
func anomalySamples(fams map[string]*dto.MetricFamily) map[string]float64 {
	fam, ok := fams[metricNeutronAnomalies]
	if !ok {
		return nil
	}
	out := make(map[string]float64, len(fam.GetMetric()))
	for _, m := range fam.GetMetric() {
		for _, lp := range m.GetLabel() {
			if lp.GetName() == "class" {
				out[lp.GetValue()] += sampleValue(m)
			}
		}
	}
	return out
}

// sampleValue returns whichever typed value a metric carries. The
// agent emits lachesis_tenant_bytes_total as a counter and the attach metrics
// as gauge/counter; reading all three shapes keeps this robust to the
// exact type.
func sampleValue(m *dto.Metric) float64 {
	switch {
	case m.Counter != nil:
		return m.Counter.GetValue()
	case m.Gauge != nil:
		return m.Gauge.GetValue()
	case m.Untyped != nil:
		return m.Untyped.GetValue()
	default:
		return 0
	}
}
