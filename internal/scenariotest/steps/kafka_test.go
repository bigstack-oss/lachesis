package steps

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/fake"
)

func kafkaEnv(b scenariotest.Broker, m scenariotest.MetricsSource) *scenariotest.StepEnv {
	return &scenariotest.StepEnv{
		Config:  twoAgentCfg(),
		State:   &scenariotest.RunState{RunID: "r"},
		Metrics: m,
		Broker:  b,
		Log:     slog.New(slog.DiscardHandler),
		Report:  &scenariotest.AssertReport{OK: true},
	}
}

func runAll(t *testing.T, env *scenariotest.StepEnv, script ...scenariotest.Step) {
	t.Helper()
	for _, st := range script {
		if err := st.Run(context.Background(), env); err != nil {
			t.Fatalf("%s: %v", st.Kind(), err)
		}
	}
}

// After a grow, the publish reaches every partition, and each message is
// one the agent's consumer kicks on: a committed Neutron port change in
// the doubly-encoded oslo envelope.
func TestKafkaSteps_PublishReachesEveryPartitionAfterGrow(t *testing.T) {
	b := &fake.Broker{}
	runAll(t, kafkaEnv(b, nil),
		CreateTopicStep{Topic: "t", Partitions: 1},
		GrowTopicStep{Topic: "t", Partitions: 6},
		PublishNeutronEventStep{Topic: "t", Partitions: 6},
	)
	if len(b.Published) != 6 {
		t.Fatalf("published %d messages, want 6", len(b.Published))
	}
	for i, p := range b.Published {
		if p.Topic != "t" || p.Partition != i {
			t.Errorf("publish %d went to %s/%d, want t/%d", i, p.Topic, p.Partition, i)
		}
		var env struct {
			Message string `json:"oslo.message"`
		}
		var inner struct {
			EventType   string `json:"event_type"`
			PublisherID string `json:"publisher_id"`
		}
		if err := json.Unmarshal(p.Value, &env); err != nil {
			t.Fatalf("outer envelope: %v", err)
		}
		if err := json.Unmarshal([]byte(env.Message), &inner); err != nil {
			t.Fatalf("inner message: %v", err)
		}
		if inner.EventType != "port.update.end" || !strings.HasPrefix(inner.PublisherID, "network.") {
			t.Errorf("message = (%q, %q), want a committed Neutron port change", inner.EventType, inner.PublisherID)
		}
	}
}

// Rerunning against a leftover topic converges: create replaces it and
// the delete at the end leaves nothing behind.
func TestKafkaSteps_CreateReplacesLeftoverTopic(t *testing.T) {
	b := &fake.Broker{Partitions: map[string]int{"t": 6}}
	runAll(t, kafkaEnv(b, nil), CreateTopicStep{Topic: "t", Partitions: 1})
	if b.Partitions["t"] != 1 {
		t.Fatalf("partitions after create = %d, want 1", b.Partitions["t"])
	}
	runAll(t, kafkaEnv(b, nil), DeleteTopicStep{Topic: "t"})
	if _, ok := b.Partitions["t"]; ok {
		t.Fatal("topic still present after delete")
	}
}

func TestKafkaSteps_NoBrokerIsAnError(t *testing.T) {
	err := (CreateTopicStep{Topic: "t", Partitions: 1}).Run(context.Background(), kafkaEnv(nil, nil))
	if err == nil || !strings.Contains(err.Error(), "kafka.brokers") {
		t.Fatalf("want an error naming kafka.brokers, got %v", err)
	}
}

func kickedOn(node0, node1 float64) fake.PerNode {
	return fake.PerNode{ByURL: map[string]scenariotest.ScrapeResult{
		"http://compute-0:9100/metrics": {KafkaKicked: map[string]float64{"t": node0}},
		"http://compute-1:9100/metrics": {KafkaKicked: map[string]float64{"t": node1}},
	}}
}

// The row reads the targeted node alone: node:1 kicking all six does not
// pass node:0, whose consumer kicked one.
func TestKafkaKicked_ShortfallIsAFailingRowNotAnError(t *testing.T) {
	defer func(d time.Duration) { kafkaKickedPollInterval = d }(kafkaKickedPollInterval)
	kafkaKickedPollInterval = time.Millisecond
	env := kafkaEnv(nil, kickedOn(1, 6))
	err := (KafkaKickedStep{Node: "node:0", Topic: "t", Min: 6, Timeout: 20 * time.Millisecond}).Run(context.Background(), env)
	if err != nil {
		t.Fatalf("a shortfall must record a row, not error: %v", err)
	}
	if env.Report.OK || len(env.Report.Rows) != 1 {
		t.Fatalf("want one failing row, got OK=%v rows=%+v", env.Report.OK, env.Report.Rows)
	}
	if row := env.Report.Rows[0]; row.Node != "compute-0" || row.Current != 1 {
		t.Errorf("row = %+v, want compute-0 at 1", row)
	}
}

func TestKafkaKicked_FloorMetPasses(t *testing.T) {
	env := kafkaEnv(nil, kickedOn(6, 0))
	if err := (KafkaKickedStep{Node: "node:0", Topic: "t", Min: 6}).Run(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	if !env.Report.OK {
		t.Fatalf("six kicks must pass a floor of six: %+v", env.Report.Rows)
	}
}
