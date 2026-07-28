package scenariotest_test

import (
	"context"
	"testing"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/fake"
)

func TestSampleAcross_StampsNode(t *testing.T) {
	agents := []scenariotest.AgentConfig{
		{Host: "cc1", MetricsURL: "http://cc1:9100/metrics"},
		{Host: "cc2", MetricsURL: "http://cc2:9100/metrics"},
	}
	src := fake.PerNode{ByURL: map[string]scenariotest.ScrapeResult{
		agents[0].MetricsURL: {
			Bytes:   []scenariotest.BytesSample{{TenantID: "t", Zone: "same_tenant", Direction: "tx", Value: 1}},
			Servers: []scenariotest.ServerSample{{ServerID: "s", Zone: "same_tenant", Direction: "tx", Value: 1}},
		},
		agents[1].MetricsURL: {
			Bytes: []scenariotest.BytesSample{{TenantID: "t", Zone: "same_tenant", Direction: "tx", Value: 2}},
		},
	}}
	snap, err := scenariotest.SampleAcross(context.Background(), src, agents)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Bytes) != 2 || snap.Bytes[0].Node != "cc1" || snap.Bytes[1].Node != "cc2" {
		t.Errorf("bytes samples not node-stamped: %+v", snap.Bytes)
	}
	if len(snap.Servers) != 1 || snap.Servers[0].Node != "cc1" {
		t.Errorf("server samples not node-stamped: %+v", snap.Servers)
	}
}

// TestSampleAcross_AnomaliesMaxNotSum guards the aggregation of
// lachesis_neutron_anomalies: it is a topology-global gauge every agent
// derives identically from the same Neutron snapshot, so SampleAcross
// must take the MAX across agents, not the sum (which would multiply the
// count by the cluster size and make a [1,1] bound unsatisfiable on a
// multi-node cluster — lachesis#171).
func TestSampleAcross_AnomaliesMaxNotSum(t *testing.T) {
	agents := []scenariotest.AgentConfig{
		{Host: "cc1", MetricsURL: "http://cc1:9100/metrics"},
		{Host: "cc2", MetricsURL: "http://cc2:9100/metrics"},
	}
	src := fake.PerNode{ByURL: map[string]scenariotest.ScrapeResult{
		// Both agents report the same class identically...
		agents[0].MetricsURL: {Anomalies: map[string]float64{"dangling_route": 1, "cycle": 2}},
		// ...except cc2 has already resynced a fresh cycle the laggard
		// hasn't yet — max must surface the higher value.
		agents[1].MetricsURL: {Anomalies: map[string]float64{"dangling_route": 1, "cycle": 3}},
	}}
	snap, err := scenariotest.SampleAcross(context.Background(), src, agents)
	if err != nil {
		t.Fatal(err)
	}
	if got := snap.Anomalies["dangling_route"]; got != 1 {
		t.Errorf("dangling_route = %v, want 1 (max across agents, not summed to 2)", got)
	}
	if got := snap.Anomalies["cycle"]; got != 3 {
		t.Errorf("cycle = %v, want 3 (max across agents, not summed to 5)", got)
	}
}
