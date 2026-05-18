package bpf

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestMapMetrics_SetMaxAndCurrent(t *testing.T) {
	m := NewMapMetrics()
	m.SetMax(MapMacTenant, MapMacTenantMaxEntries)
	m.SetMax(MapSubnetZoneTrie, MapSubnetZoneTrieMaxEntries)
	m.SetCurrent(MapMacTenant, 17)
	m.SetCurrent(MapSubnetZoneTrie, 245)

	reg := prometheus.NewRegistry()
	for _, c := range m.Collectors() {
		reg.MustRegister(c)
	}

	const want = `
# HELP cubecos_bpf_map_current_entries Userspace-tracked entry count of each BPF map after the most recent push.
# TYPE cubecos_bpf_map_current_entries gauge
cubecos_bpf_map_current_entries{map="mac_tenant_map"} 17
cubecos_bpf_map_current_entries{map="subnet_zone_trie"} 245
# HELP cubecos_bpf_map_max_entries Compiled-in max_entries of each BPF map the agent populates.
# TYPE cubecos_bpf_map_max_entries gauge
cubecos_bpf_map_max_entries{map="mac_tenant_map"} 8192
cubecos_bpf_map_max_entries{map="subnet_zone_trie"} 16384
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want)); err != nil {
		t.Fatalf("metric mismatch:\n%v", err)
	}
}

func TestMapMetrics_NilReceiverSafe(t *testing.T) {
	var m *MapMetrics
	m.SetMax(MapMacTenant, 100)
	m.SetCurrent(MapSubnetZoneTrie, 50)
}
