package netlink

import "github.com/prometheus/client_golang/prometheus"

// Metrics holds the netlink-subscriber Prometheus instruments.
// Construct with [NewMetrics], register the slice from
// [Metrics.Collectors] with the agent's registry.
//
// The instruments are cataloged under health metrics:
//
//   - lachesis_tc_attach_failures_total{iface_kind}  per-attempt
//     failure counter on the event path, labelled by iface_kind for
//     which the attach was attempted ("tap" for prefix-matched links,
//     "other" for explicit-allowlist entries)
//   - lachesis_attached_interfaces                   current size of
//     the Interface Registry
//   - lachesis_tc_unattached_interfaces{iface_kind}  allowlisted links
//     the last attach-presence sweep left unattached
//   - lachesis_tc_reattach_total{iface_kind,outcome} the sweep's
//     re-attach attempts; a healed one is a missed event or a filter
//     removed out-of-band
//   - lachesis_netlink_subscriber_restarts_total     re-subscribes
//     after a lost netlink subscription
//
// Metric catalogue: docs/architecture/metrics.md
type Metrics struct {
	attachFailures *prometheus.CounterVec
	attached       prometheus.GaugeFunc
	unattached     *prometheus.GaugeVec
	reattaches     *prometheus.CounterVec
	restarts       prometheus.Counter
}

// NewMetrics constructs the bundle. The current-size gauge is
// backed by registrySize so it reflects live state on every scrape
// without the subscriber having to push updates. Every child of the
// labelled instruments is seeded at zero — a labelled series is not
// emitted until first touched, so without the seed a healthy agent
// shows "No data" instead of 0 on the dashboard.
func NewMetrics(registrySize func() int) *Metrics {
	m := &Metrics{
		attachFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "lachesis_tc_attach_failures_total",
			Help: "TC clsact attach failures from the netlink subscriber, labelled by iface_kind (\"tap\" for prefix-matched, \"other\" for explicit-list entries).",
		}, []string{"iface_kind"}),
		attached: prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "lachesis_attached_interfaces",
			Help: "Number of interfaces currently carrying telemetry TC programs.",
		}, func() float64 { return float64(registrySize()) }),
		unattached: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "lachesis_tc_unattached_interfaces",
			Help: "Allowlisted interfaces the last attach-presence sweep found without the telemetry TC programs and failed to re-attach, labelled by iface_kind. Sustained > 0 means traffic on them is unbilled.",
		}, []string{"iface_kind"}),
		reattaches: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "lachesis_tc_reattach_total",
			Help: "Attach-presence sweep re-attach attempts, labelled by iface_kind and outcome (\"healed\" or \"failed\"). A healed re-attach is a missed netlink event or a filter removed out-of-band.",
		}, []string{"iface_kind", "outcome"}),
		restarts: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "lachesis_netlink_subscriber_restarts_total",
			Help: "Re-subscribes after the netlink link-event subscription was lost (e.g. socket overflow under an event storm).",
		}),
	}
	for _, kind := range []string{ifaceKindTap, ifaceKindOther} {
		m.attachFailures.WithLabelValues(kind).Add(0)
		m.unattached.WithLabelValues(kind).Set(0)
		for _, outcome := range []string{outcomeHealed, outcomeFailed} {
			m.reattaches.WithLabelValues(kind, outcome).Add(0)
		}
	}
	return m
}

// Collectors returns every instrument in the bundle.
func (m *Metrics) Collectors() []prometheus.Collector {
	return []prometheus.Collector{m.attachFailures, m.attached, m.unattached, m.reattaches, m.restarts}
}

// recordAttachFailure increments the failure counter for kind.
// Nil-safe so subscriber tests can omit the dependency.
func (m *Metrics) recordAttachFailure(kind string) {
	if m == nil {
		return
	}
	m.attachFailures.WithLabelValues(kind).Inc()
}

// recordReattach counts one sweep re-attach attempt for kind with the
// given outcome. Nil-safe.
func (m *Metrics) recordReattach(kind, outcome string) {
	if m == nil {
		return
	}
	m.reattaches.WithLabelValues(kind, outcome).Inc()
}

// setUnattached publishes the last sweep's per-kind count of links it
// left unattached. Nil-safe.
func (m *Metrics) setUnattached(byKind map[string]int) {
	if m == nil {
		return
	}
	for kind, n := range byKind {
		m.unattached.WithLabelValues(kind).Set(float64(n))
	}
}

// recordRestart counts one re-subscribe. Nil-safe.
func (m *Metrics) recordRestart() {
	if m == nil {
		return
	}
	m.restarts.Inc()
}
