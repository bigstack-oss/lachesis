package neutron

import (
	"errors"
	"strconv"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds the Neutron-subsystem Prometheus instruments. Owned
// by the [Neutron] struct ([New] constructs the bundle and threads
// it through Sync/Commit); the agent registers the slice from
// [Metrics.Collectors] with its `prometheus.Registry`. nil is a
// valid receiver on every observation helper, so code paths that
// elide metrics for tests can pass nil safely.
//
// The instruments:
//
//   - lachesis_neutron_sync_age_seconds                          gauge (sync recency)
//   - lachesis_neutron_api_errors_total{endpoint, code}          counter
//   - lachesis_neutron_unknown_device_owner_total{owner}         counter
//   - lachesis_neutron_builder_step_duration_seconds{step}       histogram
//   - lachesis_neutron_anomalies{class}                          gauge (topology health)
//   - lachesis_neutron_trunk_subports                            gauge (data-plane blind spot)
type Metrics struct {
	syncAge       prometheus.GaugeFunc
	apiErrors     *prometheus.CounterVec
	unknownOwners *prometheus.CounterVec
	builderStep   *prometheus.HistogramVec
	anomalies     *prometheus.GaugeVec
	trunkSubports prometheus.Gauge
}

// NewMetrics constructs the bundle. `lastSync` returns the most
// recent successful cold-start / reconcile time. A zero time.Time
// (never synced) is reported as `-1` — operators filter
// `lachesis_neutron_sync_age_seconds < 0` to surface
// never-yet-synced agents.
//
// Each Endpoint* child of the api_errors counter is seeded at zero
// under the codeNetwork class — a labelled counter emits no series
// until its first increment, so without the seed a healthy agent
// shows "No data" instead of 0 on the dashboard. HTTP status codes
// are not enumerable in advance and appear on first occurrence. The
// unknown-owner counter stays unseeded for the same reason: its
// owner label space is open-ended.
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
			Help:    "BuildTrie per-step duration (DESIGN §5.2 steps 1-5), in seconds.",
			Buckets: prometheus.DefBuckets,
		}, []string{"step"}),
		anomalies: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "lachesis_neutron_anomalies",
			Help: "Count of topology anomalies by class detected at the last Neutron cold-start or resync.",
		}, []string{"class"}),
		trunkSubports: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "lachesis_neutron_trunk_subports",
			Help: "Count of trunk subport MACs admitted to mac_tenant_map at the last Neutron cold-start or resync; nonzero means 802.1Q-tagged subport traffic passes the data plane uncounted (DESIGN §8).",
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
	for _, ep := range []string{endpointKeystone, endpointNetworks, endpointSubnets, endpointPorts, endpointRouters, endpointProjects, endpointFloatingIPs} {
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
	return []prometheus.Collector{m.syncAge, m.apiErrors, m.unknownOwners, m.builderStep, m.anomalies, m.trunkSubports}
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

// SetTrunkSubports publishes how many trunk subport MACs the latest
// cold-start or resync admitted to mac_tenant_map. Gauge semantics —
// every sync replaces the previous count, so deleting the last trunk
// drops the gauge back to 0 on the next pass. The data plane cannot
// count 802.1Q-tagged subport traffic (docs/DESIGN.md §8 Tier 1), so
// a nonzero value flags a billing blind spot. nil receivers no-op.
func (m *Metrics) SetTrunkSubports(n int) {
	if m == nil {
		return
	}
	m.trunkSubports.Set(float64(n))
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
