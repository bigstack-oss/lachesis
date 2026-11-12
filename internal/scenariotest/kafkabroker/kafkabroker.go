// Package kafkabroker is the live [scenariotest.Broker]: topic admin and
// partition-pinned publishes against the cluster's Kafka via kafka-go.
package kafkabroker

import (
	"context"
	"errors"
	"fmt"
	"time"

	kafkago "github.com/segmentio/kafka-go"
)

// recreateTimeout bounds how long RecreateTopic waits for the broker to
// finish deleting the old topic; deletion is asynchronous, so a create
// right after it reports the topic as still existing.
const recreateTimeout = 30 * time.Second

// recreatePoll is the pause between create attempts while the old topic
// is still being deleted.
const recreatePoll = time.Second

// publishTimeout bounds one partition write.
const publishTimeout = 10 * time.Second

// Broker talks to one Kafka cluster.
type Broker struct {
	brokers []string
	client  *kafkago.Client
}

// New returns a Broker for the bootstrap addresses. It dials nothing
// until the first call.
func New(brokers []string) *Broker {
	return &Broker{brokers: brokers, client: &kafkago.Client{Addr: kafkago.TCP(brokers...)}}
}

func (b *Broker) RecreateTopic(ctx context.Context, topic string, partitions int) error {
	if err := b.DeleteTopic(ctx, topic); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, recreateTimeout)
	defer cancel()
	for {
		resp, err := b.client.CreateTopics(ctx, &kafkago.CreateTopicsRequest{
			Topics: []kafkago.TopicConfig{{Topic: topic, NumPartitions: partitions, ReplicationFactor: 1}},
		})
		if err != nil {
			return fmt.Errorf("create topic %s: %w", topic, err)
		}
		err = resp.Errors[topic]
		if err == nil {
			return nil
		}
		if !errors.Is(err, kafkago.TopicAlreadyExists) {
			return fmt.Errorf("create topic %s: %w", topic, err)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("create topic %s: previous topic still being deleted: %w", topic, ctx.Err())
		case <-time.After(recreatePoll):
		}
	}
}

func (b *Broker) GrowTopic(ctx context.Context, topic string, partitions int) error {
	resp, err := b.client.CreatePartitions(ctx, &kafkago.CreatePartitionsRequest{
		Topics: []kafkago.TopicPartitionsConfig{{Name: topic, Count: int32(partitions)}},
	})
	if err != nil {
		return fmt.Errorf("grow topic %s: %w", topic, err)
	}
	if err := resp.Errors[topic]; err != nil {
		return fmt.Errorf("grow topic %s to %d partitions: %w", topic, partitions, err)
	}
	return nil
}

func (b *Broker) DeleteTopic(ctx context.Context, topic string) error {
	resp, err := b.client.DeleteTopics(ctx, &kafkago.DeleteTopicsRequest{Topics: []string{topic}})
	if err != nil {
		return fmt.Errorf("delete topic %s: %w", topic, err)
	}
	if err := resp.Errors[topic]; err != nil && !errors.Is(err, kafkago.UnknownTopicOrPartition) {
		return fmt.Errorf("delete topic %s: %w", topic, err)
	}
	return nil
}

func (b *Broker) Publish(ctx context.Context, topic string, partition int, value []byte) error {
	conn, err := kafkago.DialLeader(ctx, "tcp", b.brokers[0], topic, partition)
	if err != nil {
		return fmt.Errorf("dial leader of %s/%d: %w", topic, partition, err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetWriteDeadline(time.Now().Add(publishTimeout)); err != nil {
		return fmt.Errorf("publish to %s/%d: %w", topic, partition, err)
	}
	if _, err := conn.WriteMessages(kafkago.Message{Value: value}); err != nil {
		return fmt.Errorf("publish to %s/%d: %w", topic, partition, err)
	}
	return nil
}
