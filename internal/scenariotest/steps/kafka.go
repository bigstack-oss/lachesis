// Kafka steps: staging a scratch topic on the cluster's broker and
// publishing Neutron notifications to it, so a scenario can drive the
// agent's Kafka consumer directly instead of through Neutron.

package steps

import (
	"context"
	"fmt"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
)

// kafkaNeeds is what every Kafka step declares: a cluster without
// kafka.brokers SKIPs the scenario.
var kafkaNeeds = scenariotest.HostNeeds{Kafka: true}

// CreateTopicStep creates Topic with Partitions partitions, deleting
// any earlier topic of that name first so a rerun starts empty.
type CreateTopicStep struct {
	Topic      string
	Partitions int
}

func (CreateTopicStep) Kind() string                      { return "kafka-create-topic" }
func (CreateTopicStep) HostNeeds() scenariotest.HostNeeds { return kafkaNeeds }

func (s CreateTopicStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	b, err := broker(env)
	if err != nil {
		return err
	}
	return b.RecreateTopic(ctx, s.Topic, s.Partitions)
}

// GrowTopicStep raises Topic's partition count to Partitions, the way
// an operator's kafka-topics.sh --alter does on a live topic.
type GrowTopicStep struct {
	Topic      string
	Partitions int
}

func (GrowTopicStep) Kind() string                      { return "kafka-grow-topic" }
func (GrowTopicStep) HostNeeds() scenariotest.HostNeeds { return kafkaNeeds }

func (s GrowTopicStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	b, err := broker(env)
	if err != nil {
		return err
	}
	return b.GrowTopic(ctx, s.Topic, s.Partitions)
}

// DeleteTopicStep deletes Topic; one already gone is fine.
type DeleteTopicStep struct {
	Topic string
}

func (DeleteTopicStep) Kind() string                      { return "kafka-delete-topic" }
func (DeleteTopicStep) HostNeeds() scenariotest.HostNeeds { return kafkaNeeds }

func (s DeleteTopicStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	b, err := broker(env)
	if err != nil {
		return err
	}
	return b.DeleteTopic(ctx, s.Topic)
}

// PublishNeutronEventStep writes one committed Neutron port change to
// each of Topic's partitions 0..Partitions-1, so a consumer assigned
// only some of them kicks fewer reconciles than Partitions.
type PublishNeutronEventStep struct {
	Topic      string
	Partitions int
}

func (PublishNeutronEventStep) Kind() string                      { return "kafka-publish" }
func (PublishNeutronEventStep) HostNeeds() scenariotest.HostNeeds { return kafkaNeeds }

func (s PublishNeutronEventStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	b, err := broker(env)
	if err != nil {
		return err
	}
	for p := range s.Partitions {
		if err := b.Publish(ctx, s.Topic, p, []byte(neutronPortUpdate)); err != nil {
			return err
		}
	}
	env.Log.Info("kafka-publish", "topic", s.Topic, "partitions", s.Partitions)
	return nil
}

// neutronPortUpdate is a port.update.end notification in the
// oslo.messaging 2.0 envelope Neutron publishes: the inner message is a
// JSON string inside the outer JSON. The agent routes on event_type and
// publisher_id alone.
const neutronPortUpdate = `{"oslo.version":"2.0","oslo.message":"{\"event_type\":\"port.update.end\",\"publisher_id\":\"network.scenariotest\",\"payload\":{}}"}`

func broker(env *scenariotest.StepEnv) (scenariotest.Broker, error) {
	if env.Broker == nil {
		return nil, fmt.Errorf("no Kafka broker configured (kafka.brokers)")
	}
	return env.Broker, nil
}
