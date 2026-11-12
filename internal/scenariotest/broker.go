package scenariotest

import "context"

// Broker is the Kafka surface the Kafka steps drive: a scratch topic's
// lifecycle and a publish pinned to one partition. The live
// implementation is internal/scenariotest/kafkabroker.
type Broker interface {
	// RecreateTopic deletes any topic named topic, then creates it with
	// partitions partitions, so a rerun starts from an empty topic.
	RecreateTopic(ctx context.Context, topic string, partitions int) error
	// GrowTopic raises topic's partition count to partitions.
	GrowTopic(ctx context.Context, topic string, partitions int) error
	// DeleteTopic deletes topic; a topic already gone is not an error.
	DeleteTopic(ctx context.Context, topic string) error
	// Publish writes value to one partition of topic.
	Publish(ctx context.Context, topic string, partition int, value []byte) error
}
