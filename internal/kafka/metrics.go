package kafka

import "github.com/prometheus/client_golang/prometheus"

// Metrics holds the Kafka consumer's Prometheus instruments:
//
//   - lachesis_kafka_lag_messages{topic}          gauge
//   - lachesis_kafka_consume_errors_total{topic}  counter
//   - lachesis_kafka_messages_total{topic,outcome} counter
//
// Metric catalogue: docs/architecture/metrics.md
type Metrics struct {
	lag           *prometheus.GaugeVec
	consumeErrors *prometheus.CounterVec
	messages      *prometheus.CounterVec
}

// NewMetrics constructs the bundle and seeds every series for topic, so
// they exist (at 0) before any traffic — including when the consumer is
// disabled, so dashboards read 0 rather than "No data".
func NewMetrics(topic string) *Metrics {
	m := &Metrics{
		lag: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "lachesis_kafka_lag_messages",
			Help: "Notification consumer lag (messages behind the topic head); sustained growth means the agent is falling behind live metadata updates and leaning on the periodic reconcile.",
		}, []string{labelTopic}),
		consumeErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "lachesis_kafka_consume_errors_total",
			Help: "Failed reads from Kafka (broker unreachable, fetch errors); the consumer logs and retries with backoff.",
		}, []string{labelTopic}),
		messages: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "lachesis_kafka_messages_total",
			Help: "Notifications read from Kafka, by what the consumer did with each: kicked a reconcile, ignored (not a committed Neutron metadata change), or undecodable.",
		}, []string{labelTopic, labelOutcome}),
	}
	m.lag.WithLabelValues(topic)
	m.consumeErrors.WithLabelValues(topic)
	for _, o := range []string{outcomeKicked, outcomeIgnored, outcomeUndecodable} {
		m.messages.WithLabelValues(topic, o)
	}
	return m
}

// Collectors returns the underlying prometheus.Collector values for
// registration by the agent.
func (m *Metrics) Collectors() []prometheus.Collector {
	return []prometheus.Collector{m.lag, m.consumeErrors, m.messages}
}

// SetLag records the current consumer lag for topic.
func (m *Metrics) SetLag(topic string, lag int64) {
	if m == nil {
		return
	}
	m.lag.WithLabelValues(topic).Set(float64(lag))
}

// RecordConsumeError counts one failed read from topic.
func (m *Metrics) RecordConsumeError(topic string) {
	if m == nil {
		return
	}
	m.consumeErrors.WithLabelValues(topic).Inc()
}

// RecordMessage counts one message read from topic with its outcome.
func (m *Metrics) RecordMessage(topic, outcome string) {
	if m == nil {
		return
	}
	m.messages.WithLabelValues(topic, outcome).Inc()
}
