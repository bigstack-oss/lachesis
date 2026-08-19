package config

import "errors"

// KafkaConfig groups the settings for the consumer that turns
// OpenStack notifications into reconcile kicks, so metadata refreshes
// within a pass instead of waiting for the 5-minute safety net.
//
// Enabled defaults to false so the agent runs without a broker.
//
// docs/architecture/trie-construction.md#incremental-updates
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
	// GroupID is the consumer-group PREFIX — the effective id is
	// per-agent (see [KafkaConfig.EffectiveGroupID]). The stream must
	// fan out: every agent needs every event, but Kafka delivers a
	// message to only ONE group member, so a shared group starves all
	// but one agent of reconcile kicks.
	GroupID string `yaml:"group_id"`
}

// EffectiveGroupID suffixes GroupID with a per-agent token so each
// agent reads the whole stream rather than load-balancing it away from
// its peers. Prefers the hostname (stable across restarts, so offsets
// survive); never falls back to the bare GroupID, which would
// reintroduce the fanout bug.
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
