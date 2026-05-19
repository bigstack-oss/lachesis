package neutron

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// scrape registers the metrics in a fresh registry, gathers the
// exposition, and returns it as a string. Used by the nil-error
// absence check, which asserts a metric family does NOT carry
// counter entries — robust regardless of proto-text spacing.
func scrape(t *testing.T, m *Metrics) string {
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
		fmt.Fprintln(&sb, mf.String())
	}
	return sb.String()
}

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
cubecos_neutron_api_errors_total{code="network",endpoint="networks"} 1
`
	if err := testutil.GatherAndCompare(newRegistry(t, m), strings.NewReader(want),
		"cubecos_neutron_api_errors_total"); err != nil {
		t.Fatalf("metric mismatch:\n%v", err)
	}
}

func TestMetrics_RecordAPIError_NilErrorIgnored(t *testing.T) {
	m := NewMetrics(func() time.Time { return time.Time{} })
	m.RecordAPIError("ports", nil) // should not panic, should not record
	dump := scrape(t, m)
	if strings.Contains(dump, "cubecos_neutron_api_errors_total") &&
		strings.Contains(dump, "counter:") {
		// CounterVec emits nothing until first Inc; if it appears,
		// the recorder added a series for nil.
		t.Errorf("nil error should not record a metric:\n%s", dump)
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

func TestMetrics_NilReceiverSafe(t *testing.T) {
	var m *Metrics
	// Nil receivers must not panic — defensive against forgotten
	// construction in test paths.
	m.RecordAPIError("ports", errors.New("x"))
	m.RecordUnknownOwner("vendor:y")
	m.ObserveBuilderStep("1_catchall", 0)
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
