package bpf

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestMetrics_SetMaxAndCurrent(t *testing.T) {
	m := NewMetrics()
	m.SetMax(MapMacTenant, MapMacTenantMaxEntries)
	m.SetMax(MapSubnetZoneTrie, MapSubnetZoneTrieMaxEntries)
	m.SetCurrent(MapMacTenant, 17)
	m.SetCurrent(MapSubnetZoneTrie, 245)

	reg := prometheus.NewRegistry()
	for _, c := range m.Collectors() {
		reg.MustRegister(c)
	}

	// lachesis_bpf_update_failures_total appears untouched: the custom
	// collector always emits every reason series, so both labels are
	// zero-seeded from the first scrape.
	const want = `
# HELP lachesis_bpf_map_current_entries Userspace-tracked entry count of each BPF map after the most recent push.
# TYPE lachesis_bpf_map_current_entries gauge
lachesis_bpf_map_current_entries{map="mac_tenant_map"} 17
lachesis_bpf_map_current_entries{map="subnet_zone_trie"} 245
# HELP lachesis_bpf_map_max_entries Compiled-in max_entries of each BPF map the agent populates.
# TYPE lachesis_bpf_map_max_entries gauge
lachesis_bpf_map_max_entries{map="mac_tenant_map"} 8192
lachesis_bpf_map_max_entries{map="subnet_zone_trie"} 16384
# HELP lachesis_bpf_update_failures_total Kernel-side cumulative count of telemetry_map inserts the kernel rejected (reason=update_failure; those flows' bytes are lost) and non-IP frames passed through uncounted (reason=skipped_ethertype), drained from the telemetry_stats BPF map each scrape.
# TYPE lachesis_bpf_update_failures_total counter
lachesis_bpf_update_failures_total{reason="skipped_ethertype"} 0
lachesis_bpf_update_failures_total{reason="update_failure"} 0
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want)); err != nil {
		t.Fatalf("metric mismatch:\n%v", err)
	}
}

func TestMetrics_SetUpdateFailures(t *testing.T) {
	m := NewMetrics()
	var counts StatCounts
	counts[StatUpdateFailure] = 42
	counts[StatSkippedEthertype] = 7
	m.SetUpdateFailures(counts)

	reg := prometheus.NewRegistry()
	for _, c := range m.Collectors() {
		reg.MustRegister(c)
	}

	const want = `
# HELP lachesis_bpf_update_failures_total Kernel-side cumulative count of telemetry_map inserts the kernel rejected (reason=update_failure; those flows' bytes are lost) and non-IP frames passed through uncounted (reason=skipped_ethertype), drained from the telemetry_stats BPF map each scrape.
# TYPE lachesis_bpf_update_failures_total counter
lachesis_bpf_update_failures_total{reason="skipped_ethertype"} 7
lachesis_bpf_update_failures_total{reason="update_failure"} 42
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want),
		"lachesis_bpf_update_failures_total"); err != nil {
		t.Fatalf("metric mismatch:\n%v", err)
	}
}

func TestMetrics_NilReceiverSafe(t *testing.T) {
	var m *Metrics
	m.SetMax(MapMacTenant, 100)
	m.SetCurrent(MapSubnetZoneTrie, 50)
	m.SetUpdateFailures(StatCounts{1, 2})
}
