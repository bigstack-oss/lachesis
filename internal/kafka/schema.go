// schema.go collects package kafka's package-level constants: the log
// component label, the metric label key, and the oslo-notification
// vocabulary used to recognise a Neutron metadata change. The Consumer
// service lives in consumer.go, the envelope decode in envelope.go, the
// instrument bundle in metrics.go.

package kafka

import "time"

// component is the slog `component` attribute for this package's logs and
// the subsystem label the agent registers its metrics under.
const component = "kafka"

// labelTopic is the Prometheus label naming the Kafka topic on the
// consumer's metrics.
const labelTopic = "topic"

// neutronPublisherPrefix matches a Neutron notification on the shared
// notifications topic: oslo sets publisher_id to "network.<host>".
const neutronPublisherPrefix = "network"

// committedSuffix is the oslo event_type suffix for a committed change
// (e.g. "port.create.end"). The agent kicks on `.end` only — the
// matching `.start` fires pre-commit, before the Neutron API reflects the
// change, so reconciling on it would just re-read stale state.
const committedSuffix = ".end"

// metadataEventPrefixes are the oslo event_type prefixes whose committed
// events change the trie or mac_tenant_map. Restricting to these skips a
// reconcile on Neutron churn the agent does not model (floatingip,
// security_group, qos, …), which can be frequent.
var metadataEventPrefixes = []string{"port.", "subnet.", "router.", "network."}

// consumeErrorBackoff is the pause after a failed read before retrying,
// so a persistent broker outage logs and retries at ~1 Hz instead of
// hot-spinning. kafka-go also backs off internally; this is a floor.
const consumeErrorBackoff = time.Second
