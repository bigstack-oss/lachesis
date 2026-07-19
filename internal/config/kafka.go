package config

import "errors"

// KafkaConfig groups settings for the Kafka consumer that delivers live
// OpenStack notifications (Neutron port/subnet/router events) so the
// agent refreshes metadata within one reconcile pass instead of waiting
// for the periodic safety net (docs/architecture/trie-construction.md#incremental-updates, docs/architecture/boot-and-recovery.md#boot-sequence). CubeCOS
// publishes oslo.messaging notifications to Kafka (driver messagingv2);
// the agent consumes the committed events and kicks a reconcile.
//
// Enabled defaults to false so the agent runs without a broker
// (developer machines, or operators who rely on the 5-minute reconcile
// alone). Enabled and Brokers also bind env vars and flags for container
// deployments; Topic and GroupID are YAML-only — they have working
// defaults and rarely change.
type KafkaConfig struct {
	// Enabled gates the consumer. When false the agent relies solely on
	// the periodic Neutron reconcile for metadata freshness.
	Enabled bool `yaml:"enabled"`
	// Brokers is the bootstrap broker list (host:port). Required when
	// Enabled.
	Brokers []string `yaml:"brokers"`
	// Topic is the oslo notification topic. The CubeCOS default is
	// "notifications.info" (the INFO-priority topic oslo's Kafka driver
	// writes); override only for a non-standard notification_topics.
	Topic string `yaml:"topic"`
	// GroupID is the consumer-group PREFIX; the effective group id is
	// per-agent-unique (see [KafkaConfig.EffectiveGroupID]). The
	// notification stream is a fanout — every agent maintains its own
	// mac_tenant_map for the taps on its node and so must receive every
	// event — but Kafka delivers each message to only one member of a
	// group. A shared group therefore starves all but one agent of the
	// reconcile kick, leaving them on the periodic (5-minute) reconcile.
	// Suffixing the host keeps per-restart offset tracking while giving
	// each agent the full stream. Delivery is at-least-once, which is
	// fine: each event only triggers an (idempotent) reconcile.
	GroupID string `yaml:"group_id"`
}

// EffectiveGroupID is the consumer group the agent actually joins:
// GroupID suffixed with a per-agent token so each agent reads the whole
// notification stream instead of load-balancing it away from its peers.
// The token is the agent's hostname (preferred: stable across restarts
// so offset tracking survives, and readable on the broker). When the
// hostname is unavailable it falls back to randomFallback — never to the
// bare GroupID, since a shared group would starve peers of reconcile
// kicks and reintroduce the fanout bug.
func (c KafkaConfig) EffectiveGroupID(host, randomFallback string) string {
	suffix := host
	if suffix == "" {
		suffix = randomFallback
	}
	return c.GroupID + "-" + suffix
}

func kafkaDefaults() KafkaConfig {
	return KafkaConfig{
		Enabled: false,
		Topic:   "notifications.info",
		GroupID: "lachesis",
	}
}

// Validate requires a broker list when enabled; Topic and GroupID always
// carry defaults, so it only guards against an operator blanking them.
func (c KafkaConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if len(c.Brokers) == 0 {
		return errors.New("brokers is required when enabled")
	}
	if c.Topic == "" {
		return errors.New("topic must not be empty")
	}
	if c.GroupID == "" {
		return errors.New("group_id must not be empty")
	}
	return nil
}
