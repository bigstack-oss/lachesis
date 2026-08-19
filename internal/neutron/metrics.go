package neutron

import (
	"errors"
	"strconv"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds the Neutron-subsystem instruments, owned by [Neutron]
// and registered by the agent. nil is a valid receiver on every
// observation helper, so test paths can elide it.
//
// docs/architecture/metrics.md
type Metrics struct {
	syncAge       prometheus.GaugeFunc
	apiErrors     *prometheus.CounterVec
	unknownOwners *prometheus.CounterVec
	builderStep   *prometheus.HistogramVec
	anomalies     *prometheus.GaugeVec
	trunkSubports prometheus.Gauge
	amphoraPorts  prometheus.Gauge
}

// NewMetrics constructs the bundle. A never-synced lastSync reports
// -1, so operators can filter `sync_age_seconds < 0`.
//
// Per-endpoint error counters are seeded at zero: a labelled counter
// emits nothing until first increment, so without the seed a healthy
// agent reads "No data" instead of 0. Open-ended label spaces (HTTP
// codes, unknown owners) stay unseeded.
func NewMetrics(lastSync func() time.Time) *Metrics {
	m := &Metrics{
		apiErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "lachesis_neutron_api_errors_total",
			Help: "Count of failed Neutron API calls by endpoint and HTTP status code ('network' for connection-level failures).",
		}, []string{"endpoint", "code"}),
		unknownOwners: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "lachesis_neutron_unknown_device_owner_total",
			Help: "Count of port admissions to mac_tenant_map under device_owner values outside the IsKnownVMOwner allowlist.",
		}, []string{"owner"}),
		builderStep: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "lachesis_neutron_builder_step_duration_seconds",
			Help:    "BuildTrie per-step duration (docs/architecture/trie-construction.md#the-five-step-algorithm steps 1-5), in seconds.",
			Buckets: prometheus.DefBuckets,
		}, []string{"step"}),
		anomalies: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "lachesis_neutron_anomalies",
			Help: "Count of topology anomalies by class detected at the last Neutron cold-start or resync.",
		}, []string{"class"}),
		trunkSubports: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "lachesis_neutron_trunk_subports",
			Help: "Count of trunk subport MACs admitted to mac_tenant_map at the last Neutron cold-start or resync; nonzero means 802.1Q-tagged subport traffic passes the data plane uncounted (docs/architecture/edge-cases.md).",
		}),
		amphoraPorts: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "lachesis_neutron_amphora_ports",
			Help: "Count of Octavia Amphora ports re-attributed from the service project to their load balancer's owning tenant at the last Neutron cold-start or resync (docs/architecture/octavia.md); drops to 0 if the Octavia lists stop resolving.",
		}),
	}
	m.syncAge = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "lachesis_neutron_sync_age_seconds",
		Help: "Seconds since the last successful Neutron cold-start or reconcile; -1 means never synced.",
	}, func() float64 {
		t := lastSync()
		if t.IsZero() {
			return -1
		}
		return time.Since(t).Seconds()
	})
	for _, ep := range []string{endpointKeystone, endpointNetworks, endpointSubnets, endpointRouters,
		endpointPorts, endpointProjects, endpointFloatingIPs, endpointServers,
		endpointLoadBalancers, endpointAmphorae} {
		m.apiErrors.WithLabelValues(ep, codeNetwork).Add(0)
	}
	for _, c := range []string{anomalyClassCycle, anomalyClassAmbiguity, anomalyClassDanglingRoute,
		anomalyClassZeroTrieTenant, anomalyClassDuplicateRouterMAC, anomalyClassMultiExternalPath} {
		m.anomalies.WithLabelValues(c).Set(0)
	}
	return m
}

// Collectors returns the underlying prometheus.Collector values for
// the agent's registry to register.
func (m *Metrics) Collectors() []prometheus.Collector {
	return []prometheus.Collector{m.syncAge, m.apiErrors, m.unknownOwners, m.builderStep, m.anomalies, m.trunkSubports, m.amphoraPorts}
}

// ObserveBuilderStep records the duration of one BuildTrie step. The
// step label is one of the step* consts in schema.go (stepCatchall,
// stepOwned, stepShared, stepInfra, stepExtraRoutes). nil receivers
// no-op so the builder can be called without metrics in tests.
func (m *Metrics) ObserveBuilderStep(step string, d time.Duration) {
	if m == nil {
		return
	}
	m.builderStep.WithLabelValues(step).Observe(d.Seconds())
}

// RecordAPIError increments the api_errors counter for endpoint with
// a status code label derived from err. Endpoint label is one of the
// endpoint* consts in schema.go.
func (m *Metrics) RecordAPIError(endpoint string, err error) {
	if m == nil || err == nil {
		return
	}
	m.apiErrors.WithLabelValues(endpoint, errCodeLabel(err)).Inc()
}

// RecordUnknownOwner increments the unknown-owner counter for
// deviceOwner. Cardinality is bounded by Neutron's device_owner
// space (a small enumerable set in practice); if a vendor plugin
// ever floods the label, the warn-log in coldstart_linux.go gives
// the operator a heads-up first.
func (m *Metrics) RecordUnknownOwner(deviceOwner string) {
	if m == nil {
		return
	}
	m.unknownOwners.WithLabelValues(deviceOwner).Inc()
}

// SetTrunkSubports publishes how many trunk subport MACs the last sync
// admitted. The data plane cannot count their 802.1Q traffic, so a
// nonzero value flags a billing blind spot.
//
// docs/architecture/edge-cases.md#tier-1--hard-limits
func (m *Metrics) SetTrunkSubports(n int) {
	if m == nil {
		return
	}
	m.trunkSubports.Set(float64(n))
}

// SetAmphoraPorts publishes how many Amphora ports the latest
// cold-start or resync re-attributed to their load balancer's owner.
// Gauge semantics — a drop to 0 while load balancers still exist means
// the Octavia lists stopped resolving and that traffic has silently
// reverted to billing the service project, so it is worth alerting on.
// nil receivers no-op.
func (m *Metrics) SetAmphoraPorts(n int) {
	if m == nil {
		return
	}
	m.amphoraPorts.Set(float64(n))
}

// SetAnomalies publishes the per-class counts from the latest
// [DetectAnomalies] pass. Gauge semantics — every sync replaces the
// previous counts, so a fixed misconfiguration drops the class back
// to 0 on the next pass. nil receivers no-op.
func (m *Metrics) SetAnomalies(a Anomalies) {
	if m == nil {
		return
	}
	m.anomalies.WithLabelValues(anomalyClassCycle).Set(float64(len(a.Cycles)))
	m.anomalies.WithLabelValues(anomalyClassAmbiguity).Set(float64(len(a.Ambiguities)))
	m.anomalies.WithLabelValues(anomalyClassDanglingRoute).Set(float64(len(a.DanglingRoutes)))
	m.anomalies.WithLabelValues(anomalyClassZeroTrieTenant).Set(float64(len(a.ZeroTrieTenants)))
	m.anomalies.WithLabelValues(anomalyClassDuplicateRouterMAC).Set(float64(len(a.DuplicateRouterMACs)))
	m.anomalies.WithLabelValues(anomalyClassMultiExternalPath).Set(float64(len(a.MultiExternalPaths)))
}

// errCodeLabel maps an error to a stable label value. gophercloud's
// ErrUnexpectedResponseCode becomes its numeric code as a string;
// every other error type ("connection refused", DNS, TLS, parse)
// maps to "network".
func errCodeLabel(err error) string {
	var u gophercloud.ErrUnexpectedResponseCode
	if errors.As(err, &u) {
		return strconv.Itoa(u.Actual)
	}
	return "network"
}
