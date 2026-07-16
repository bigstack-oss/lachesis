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
	metricBytesTotal         = "lachesis_bytes_total"
	metricAttachedInterfaces = "lachesis_attached_interfaces"
	metricAttachFailures     = "lachesis_tc_attach_failures_total"
	// metricSettledFlows counts GlobalState rows the agent's ghost sweep
	// folded into the settled-bytes accumulator (DESIGN §3.5). The
	// mac-reuse scenario polls it to know the sweep has processed a
	// deleted VM. Absent on pre-fold agents — the scenario checks
	// presence and refuses to run rather than hanging on the poll.
	metricSettledFlows = "lachesis_gc_settled_flows_total"
	// metricServerBytesTotal is the mortal per-server billing family
	// (DESIGN §11.5). Absent on agents predating the per-server export;
	// only expectations with a VM target need it, and assert refuses
	// those against agents that don't expose it.
	metricServerBytesTotal = "lachesis_server_bytes_total"
	// metricNeutronAnomalies is the per-class topology-anomaly gauge.
	// [AssertAnomalyStep] polls it; the class vocabulary is the agent's
	// (cycle, ambiguity, …, multi_external_path).
	metricNeutronAnomalies = "lachesis_neutron_anomalies"
)

// BytesSample is one lachesis_bytes_total series: the {tenant_id, zone,
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
}

// ServerSample is one lachesis_server_bytes_total series — the mortal
// per-server billing family (DESIGN §11.5). Captured alongside
// BytesSample so Expect entries with a VM target can lower-bound a
// specific server's delta.
type ServerSample struct {
	ServerID        string  `json:"server_id"`
	TenantID        string  `json:"tenant_id"`
	Zone            string  `json:"zone"`
	ExternalNetwork string  `json:"external_network,omitempty"`
	Direction       string  `json:"direction"`
	Value           float64 `json:"value"`
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
	Bytes              []BytesSample
	Servers            []ServerSample
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
	Bytes              []BytesSample
	Servers            []ServerSample
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
		metricSettledFlows, metricServerBytesTotal, metricNeutronAnomalies} {
		_, ok := fams[n]
		r.Present[n] = ok
	}
	r.AttachedInterfaces = familySum(fams, metricAttachedInterfaces)
	r.AttachFailures = familySum(fams, metricAttachFailures)
	r.SettledFlows = familySum(fams, metricSettledFlows)
	r.Bytes = bytesSamples(fams)
	r.Servers = serverSamples(fams)
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
		} `json:"mac_tenant_map"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return MACLookup{}, fmt.Errorf("lookup: decode %s: %w", u, err)
	}
	if body.MAC == nil {
		return MACLookup{}, nil
	}
	return MACLookup{Found: body.MAC.Found, TenantID: body.MAC.TenantID}, nil
}

// sampleAcross scrapes every agent URL and aggregates the health
// gauges (each compute node exposes its own) plus the bytes series.
func sampleAcross(ctx context.Context, src MetricsSource, urls []string) (MetricsSnapshot, error) {
	var snap MetricsSnapshot
	for _, u := range urls {
		r, err := src.Scrape(ctx, u)
		if err != nil {
			return MetricsSnapshot{}, err
		}
		snap.AttachedInterfaces += r.AttachedInterfaces
		snap.AttachFailures += r.AttachFailures
		snap.SettledFlows += r.SettledFlows
		snap.Bytes = append(snap.Bytes, r.Bytes...)
		snap.Servers = append(snap.Servers, r.Servers...)
		for class, v := range r.Anomalies {
			if snap.Anomalies == nil {
				snap.Anomalies = map[string]float64{}
			}
			snap.Anomalies[class] += v
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

// bytesSamples extracts every lachesis_bytes_total series with its
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
// agent emits lachesis_bytes_total as a counter and the attach metrics
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
