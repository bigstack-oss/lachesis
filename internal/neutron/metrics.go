package neutron

import (
	"errors"
	"strconv"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds the Neutron-subsystem Prometheus instruments.
// Construct with [NewMetrics], register the slice from
// [Metrics.Collectors] with the agent's `prometheus.Registry`, then
// thread the *Metrics through to cold-start and any future
// incremental updater. nil is a valid receiver on every observation
// helper, so code paths that elide metrics for tests can pass nil
// safely.
//
// The instruments:
//
//   - cubecos_neutron_sync_age_seconds                          gauge (sync recency)
//   - cubecos_neutron_api_errors_total{endpoint, code}          counter
//   - cubecos_neutron_unknown_device_owner_total{owner}         counter
//   - cubecos_neutron_builder_step_duration_seconds{step}       histogram
type Metrics struct {
	syncAge       prometheus.GaugeFunc
	apiErrors     *prometheus.CounterVec
	unknownOwners *prometheus.CounterVec
	builderStep   *prometheus.HistogramVec
}

// NewMetrics constructs the bundle. `lastSync` returns the most
// recent successful cold-start / reconcile time. A zero time.Time
// (never synced) is reported as `-1` — operators filter
// `cubecos_neutron_sync_age_seconds < 0` to surface
// never-yet-synced agents.
func NewMetrics(lastSync func() time.Time) *Metrics {
	m := &Metrics{
		apiErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "cubecos_neutron_api_errors_total",
			Help: "Count of failed Neutron API calls by endpoint and HTTP status code ('network' for connection-level failures).",
		}, []string{"endpoint", "code"}),
		unknownOwners: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "cubecos_neutron_unknown_device_owner_total",
			Help: "Count of port admissions to mac_tenant_map under device_owner values outside the IsKnownVMOwner allowlist.",
		}, []string{"owner"}),
		builderStep: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "cubecos_neutron_builder_step_duration_seconds",
			Help:    "BuildTrie per-step duration (DESIGN §5.2 steps 1-5), in seconds.",
			Buckets: prometheus.DefBuckets,
		}, []string{"step"}),
	}
	m.syncAge = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "cubecos_neutron_sync_age_seconds",
		Help: "Seconds since the last successful Neutron cold-start or reconcile; -1 means never synced.",
	}, func() float64 {
		t := lastSync()
		if t.IsZero() {
			return -1
		}
		return time.Since(t).Seconds()
	})
	return m
}

// Collectors returns the underlying prometheus.Collector values for
// the agent's registry to register.
func (m *Metrics) Collectors() []prometheus.Collector {
	return []prometheus.Collector{m.syncAge, m.apiErrors, m.unknownOwners, m.builderStep}
}

// ObserveBuilderStep records the duration of one BuildTrie step
// (labels: "1_catchall", "2_owned", "3_shared", "4_infra",
// "5_extraroutes"). nil receivers no-op so the builder can be
// called without metrics in tests.
func (m *Metrics) ObserveBuilderStep(step string, d time.Duration) {
	if m == nil {
		return
	}
	m.builderStep.WithLabelValues(step).Observe(d.Seconds())
}

// RecordAPIError increments the api_errors counter for endpoint with
// a status code label derived from err. Endpoint label is one of
// "keystone", "networks", "subnets", "ports", "routers".
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
