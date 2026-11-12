package scenarios

import (
	"time"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/steps"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// kafkaPartitionGrowth is the live regression for the lachesis#327 root
// cause: the notifications topic gains partitions after the agent's
// consumer joined its group. A fresh install auto-creates the topic with
// one partition and the platform widens it minutes later; a consumer
// that does not watch for partition changes keeps its join-time
// assignment and silently misses every event on the new partitions.
//
// It stages that on a scratch topic so the cluster's real notifications
// topic is never altered: node:0's agent restarts onto a one-partition
// topic, the topic grows to six, and one Neutron port event lands on
// each partition. Every one must kick a reconcile; a consumer stuck on
// partition 0 kicks one. The 600s reconcile interval keeps the
// periodic pass out of the window.
//
// SKIPs when agent_control or kafka.brokers is unconfigured —
// environment, not defect.
func kafkaPartitionGrowth() *scenariotest.Scenario {
	const (
		topic      = "lachesis-scenario-partition-growth"
		partitions = 6
		// joinWait covers the consumer joining its group after the
		// restart, so the join sees one partition, not six.
		joinWait = 30 * time.Second
		// rebalanceWait covers kafka-go's 5s partition watch plus the
		// group rebalance, so a watching consumer owns all six before
		// the publish.
		rebalanceWait = 30 * time.Second
	)
	return &scenariotest.Scenario{
		Name:    "kafka-partition-growth",
		Desc:    "Grow the agent's Kafka topic from 1 to 6 partitions after its consumer joined; an event on every partition must kick a reconcile (lachesis#327, step-scripted).",
		Builder: scenario.New(),
		Steps: []scenariotest.Step{
			steps.CreateTopicStep{Topic: topic, Partitions: 1},
			steps.RestartAgentStep{Node: "node:0", SetConfig: map[string]string{
				"kafka.enabled":      "true",
				"kafka.topic":        topic,
				"reconcile.interval": "600s",
			}},
			steps.SleepStep{Duration: joinWait},
			steps.GrowTopicStep{Topic: topic, Partitions: partitions},
			steps.SleepStep{Duration: rebalanceWait},
			steps.PublishNeutronEventStep{Topic: topic, Partitions: partitions},
			steps.KafkaKickedStep{Node: "node:0", Topic: topic, Min: partitions,
				Note: "the consumer reads every partition the topic gained after it joined"},

			steps.RestartAgentStep{Node: "node:0", RestoreConfig: true},
			steps.DeleteTopicStep{Topic: topic},
		},
	}
}
