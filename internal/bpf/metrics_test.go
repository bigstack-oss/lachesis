package bpf

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func gather(t *testing.T, m *MapMetrics) string {
	t.Helper()
	reg := prometheus.NewRegistry()
	for _, c := range m.Collectors() {
		if err := reg.Register(c); err != nil {
			t.Fatalf("register: %v", err)
		}
	}
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	var sb strings.Builder
	for _, mf := range mfs {
		sb.WriteString(mf.String())
		sb.WriteString("\n")
	}
	return sb.String()
}

func TestMapMetrics_SetMaxAndCurrent(t *testing.T) {
	m := NewMapMetrics()
	m.SetMax(MapMacTenant, MapMacTenantMaxEntries)
	m.SetMax(MapSubnetZoneTrie, MapSubnetZoneTrieMaxEntries)
	m.SetCurrent(MapMacTenant, 17)
	m.SetCurrent(MapSubnetZoneTrie, 245)

	dump := gather(t, m)
	for _, want := range []string{
		`name:"map" value:"mac_tenant_map"`,
		`name:"map" value:"subnet_zone_trie"`,
		`value:8192`,  // MapMacTenantMaxEntries
		`value:16384`, // MapSubnetZoneTrieMaxEntries
		`value:17`,    // current mac_tenant_map
		`value:245`,   // current subnet_zone_trie
	} {
		if !strings.Contains(dump, want) {
			t.Errorf("missing fragment %q in:\n%s", want, dump)
		}
	}
}

func TestMapMetrics_NilReceiverSafe(t *testing.T) {
	var m *MapMetrics
	m.SetMax(MapMacTenant, 100)
	m.SetCurrent(MapSubnetZoneTrie, 50)
}
