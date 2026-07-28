package agentmetrics

import (
	dto "github.com/prometheus/client_model/go"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
)

// reasonSum sums only the samples of family name whose `reason` label
// equals want. The eviction families pack several distinct reasons into
// one family, so [familySum] would conflate unrelated eviction paths —
// notably pressure-relief (telemetry_map fill) with the ghost sweep's
// ttl expiry.
func reasonSum(fams map[string]*dto.MetricFamily, name, want string) float64 {
	fam, ok := fams[name]
	if !ok {
		return 0
	}
	var total float64
	for _, m := range fam.GetMetric() {
		for _, lp := range m.GetLabel() {
			if lp.GetName() == "reason" && lp.GetValue() == want {
				total += sampleValue(m)
			}
		}
	}
	return total
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
func bytesSamples(fams map[string]*dto.MetricFamily) []scenariotest.BytesSample {
	fam, ok := fams[scenariotest.MetricBytesTotal]
	if !ok {
		return nil
	}
	out := make([]scenariotest.BytesSample, 0, len(fam.GetMetric()))
	for _, m := range fam.GetMetric() {
		s := scenariotest.BytesSample{Value: sampleValue(m)}
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
func serverSamples(fams map[string]*dto.MetricFamily) []scenariotest.ServerSample {
	fam, ok := fams[scenariotest.MetricServerBytesTotal]
	if !ok {
		return nil
	}
	out := make([]scenariotest.ServerSample, 0, len(fam.GetMetric()))
	for _, m := range fam.GetMetric() {
		s := scenariotest.ServerSample{Value: sampleValue(m)}
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
func portSamples(fams map[string]*dto.MetricFamily) []scenariotest.PortSample {
	fam, ok := fams[scenariotest.MetricPortBytesTotal]
	if !ok {
		return nil
	}
	out := make([]scenariotest.PortSample, 0, len(fam.GetMetric()))
	for _, m := range fam.GetMetric() {
		s := scenariotest.PortSample{Value: sampleValue(m)}
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
	fam, ok := fams[scenariotest.MetricNeutronAnomalies]
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
