package neutron

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// newRegistry registers every Collector on m into a fresh
// prometheus.Registry, suitable for testutil.GatherAndCompare.
func newRegistry(t *testing.T, m *Metrics) *prometheus.Registry {
	t.Helper()
	reg := prometheus.NewRegistry()
	for _, c := range m.Collectors() {
		if err := reg.Register(c); err != nil {
			t.Fatalf("register: %v", err)
		}
	}
	return reg
}

func TestMetrics_SyncAgeNegativeWhenNeverSynced(t *testing.T) {
	m := NewMetrics(func() time.Time { return time.Time{} })
	if got := testutil.ToFloat64(m.syncAge); got != -1 {
		t.Fatalf("sync_age before first sync = %v, want -1", got)
	}
}

func TestMetrics_SyncAgeReadsLatestProvider(t *testing.T) {
	now := time.Now()
	m := NewMetrics(func() time.Time { return now.Add(-3 * time.Second) })
	got := testutil.ToFloat64(m.syncAge)
	if got < 2.5 || got > 3.5 {
		t.Errorf("sync_age = %v, want ~3", got)
	}
}

func TestMetrics_RecordAPIError_HTTPCode(t *testing.T) {
	m := NewMetrics(func() time.Time { return time.Time{} })
	m.RecordAPIError("ports", gophercloud.ErrUnexpectedResponseCode{Actual: 503})
	m.RecordAPIError("ports", gophercloud.ErrUnexpectedResponseCode{Actual: 503})
	m.RecordAPIError("keystone", gophercloud.ErrUnexpectedResponseCode{Actual: 401})

	const want = `
# HELP cubecos_neutron_api_errors_total Count of failed Neutron API calls by endpoint and HTTP status code ('network' for connection-level failures).
# TYPE cubecos_neutron_api_errors_total counter
cubecos_neutron_api_errors_total{code="401",endpoint="keystone"} 1
cubecos_neutron_api_errors_total{code="503",endpoint="ports"} 2
cubecos_neutron_api_errors_total{code="network",endpoint="keystone"} 0
cubecos_neutron_api_errors_total{code="network",endpoint="networks"} 0
cubecos_neutron_api_errors_total{code="network",endpoint="ports"} 0
cubecos_neutron_api_errors_total{code="network",endpoint="projects"} 0
cubecos_neutron_api_errors_total{code="network",endpoint="routers"} 0
cubecos_neutron_api_errors_total{code="network",endpoint="subnets"} 0
`
	if err := testutil.GatherAndCompare(newRegistry(t, m), strings.NewReader(want),
		"cubecos_neutron_api_errors_total"); err != nil {
		t.Fatalf("metric mismatch:\n%v", err)
	}
}

func TestMetrics_RecordAPIError_NetworkLevel(t *testing.T) {
	m := NewMetrics(func() time.Time { return time.Time{} })
	m.RecordAPIError("networks", errors.New("dial tcp: connection refused"))

	const want = `
# HELP cubecos_neutron_api_errors_total Count of failed Neutron API calls by endpoint and HTTP status code ('network' for connection-level failures).
# TYPE cubecos_neutron_api_errors_total counter
cubecos_neutron_api_errors_total{code="network",endpoint="keystone"} 0
cubecos_neutron_api_errors_total{code="network",endpoint="networks"} 1
cubecos_neutron_api_errors_total{code="network",endpoint="ports"} 0
cubecos_neutron_api_errors_total{code="network",endpoint="projects"} 0
cubecos_neutron_api_errors_total{code="network",endpoint="routers"} 0
cubecos_neutron_api_errors_total{code="network",endpoint="subnets"} 0
`
	if err := testutil.GatherAndCompare(newRegistry(t, m), strings.NewReader(want),
		"cubecos_neutron_api_errors_total"); err != nil {
		t.Fatalf("metric mismatch:\n%v", err)
	}
}

// TestMetrics_RecordAPIError_NilErrorIgnored pins that a nil error
// neither panics nor increments: the exposition stays exactly the
// NewMetrics seed (every endpoint at zero under the "network" class).
func TestMetrics_RecordAPIError_NilErrorIgnored(t *testing.T) {
	m := NewMetrics(func() time.Time { return time.Time{} })
	m.RecordAPIError("ports", nil) // should not panic, should not record

	const want = `
# HELP cubecos_neutron_api_errors_total Count of failed Neutron API calls by endpoint and HTTP status code ('network' for connection-level failures).
# TYPE cubecos_neutron_api_errors_total counter
cubecos_neutron_api_errors_total{code="network",endpoint="keystone"} 0
cubecos_neutron_api_errors_total{code="network",endpoint="networks"} 0
cubecos_neutron_api_errors_total{code="network",endpoint="ports"} 0
cubecos_neutron_api_errors_total{code="network",endpoint="projects"} 0
cubecos_neutron_api_errors_total{code="network",endpoint="routers"} 0
cubecos_neutron_api_errors_total{code="network",endpoint="subnets"} 0
`
	if err := testutil.GatherAndCompare(newRegistry(t, m), strings.NewReader(want),
		"cubecos_neutron_api_errors_total"); err != nil {
		t.Fatalf("metric mismatch:\n%v", err)
	}
}

func TestMetrics_RecordUnknownOwner(t *testing.T) {
	m := NewMetrics(func() time.Time { return time.Time{} })
	m.RecordUnknownOwner("vendor:foo")
	m.RecordUnknownOwner("vendor:foo")
	m.RecordUnknownOwner("oslo:bar")

	const want = `
# HELP cubecos_neutron_unknown_device_owner_total Count of port admissions to mac_tenant_map under device_owner values outside the IsKnownVMOwner allowlist.
# TYPE cubecos_neutron_unknown_device_owner_total counter
cubecos_neutron_unknown_device_owner_total{owner="oslo:bar"} 1
cubecos_neutron_unknown_device_owner_total{owner="vendor:foo"} 2
`
	if err := testutil.GatherAndCompare(newRegistry(t, m), strings.NewReader(want),
		"cubecos_neutron_unknown_device_owner_total"); err != nil {
		t.Fatalf("metric mismatch:\n%v", err)
	}
}

// TestMetrics_SetAnomalies pins the seed (all five classes at zero)
// and gauge semantics: a second SetAnomalies call replaces the
// previous counts rather than accumulating.
func TestMetrics_SetAnomalies(t *testing.T) {
	m := NewMetrics(func() time.Time { return time.Time{} })
	m.SetAnomalies(Anomalies{
		Cycles:          []CycleHit{{}, {}},
		DanglingRoutes:  []DanglingRoute{{}},
		ZeroTrieTenants: []ZeroTrieTenant{{}, {}, {}},
	})
	m.SetAnomalies(Anomalies{
		Cycles: []CycleHit{{}},
	})

	const want = `
# HELP cubecos_neutron_anomalies Count of topology anomalies by class detected at the last Neutron cold-start or resync.
# TYPE cubecos_neutron_anomalies gauge
cubecos_neutron_anomalies{class="ambiguity"} 0
cubecos_neutron_anomalies{class="cycle"} 1
cubecos_neutron_anomalies{class="dangling_route"} 0
cubecos_neutron_anomalies{class="duplicate_router_mac"} 0
cubecos_neutron_anomalies{class="zero_trie_tenant"} 0
`
	if err := testutil.GatherAndCompare(newRegistry(t, m), strings.NewReader(want),
		"cubecos_neutron_anomalies"); err != nil {
		t.Fatalf("metric mismatch:\n%v", err)
	}
}

// TestMetrics_SetTrunkSubports pins the seed (a plain gauge reads 0
// before the first sync) and gauge semantics: a second
// SetTrunkSubports call replaces the previous count rather than
// accumulating.
func TestMetrics_SetTrunkSubports(t *testing.T) {
	m := NewMetrics(func() time.Time { return time.Time{} })
	m.SetTrunkSubports(3)
	m.SetTrunkSubports(2)

	const want = `
# HELP cubecos_neutron_trunk_subports Count of trunk subport MACs admitted to mac_tenant_map at the last Neutron cold-start or resync; nonzero means 802.1Q-tagged subport traffic passes the data plane uncounted (DESIGN §8).
# TYPE cubecos_neutron_trunk_subports gauge
cubecos_neutron_trunk_subports 2
`
	if err := testutil.GatherAndCompare(newRegistry(t, m), strings.NewReader(want),
		"cubecos_neutron_trunk_subports"); err != nil {
		t.Fatalf("metric mismatch:\n%v", err)
	}
}

func TestMetrics_NilReceiverSafe(t *testing.T) {
	var m *Metrics
	// Nil receivers must not panic — defensive against forgotten
	// construction in test paths.
	m.RecordAPIError("ports", errors.New("x"))
	m.RecordUnknownOwner("vendor:y")
	m.ObserveBuilderStep("1_catchall", 0)
	m.SetAnomalies(Anomalies{})
	m.SetTrunkSubports(1)
}

func TestMetrics_ObserveBuilderStepEmitsHistogram(t *testing.T) {
	m := NewMetrics(func() time.Time { return time.Time{} })
	m.ObserveBuilderStep("1_catchall", 100*time.Microsecond)
	m.ObserveBuilderStep("2_owned", 250*time.Microsecond)
	// Each step labels its own series. Five labels are wired by
	// BuildTrie but only two have observations here.
	reg := newRegistry(t, m)
	if got := testutil.CollectAndCount(reg, "cubecos_neutron_builder_step_duration_seconds"); got != 2 {
		t.Fatalf("histogram series count = %d, want 2", got)
	}
}
