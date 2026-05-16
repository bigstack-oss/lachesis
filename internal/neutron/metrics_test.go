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
// exposition, and returns it as a string. Useful for asserting
// label sets without round-tripping through the text format.
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

	dump := scrape(t, m)
	for _, want := range []string{
		`name:"endpoint" value:"ports"`, `name:"code" value:"503"`,
		`name:"endpoint" value:"keystone"`, `name:"code" value:"401"`,
	} {
		if !strings.Contains(dump, want) {
			t.Errorf("missing label fragment %q in:\n%s", want, dump)
		}
	}
}

func TestMetrics_RecordAPIError_NetworkLevel(t *testing.T) {
	m := NewMetrics(func() time.Time { return time.Time{} })
	m.RecordAPIError("networks", errors.New("dial tcp: connection refused"))
	dump := scrape(t, m)
	if !strings.Contains(dump, `name:"code" value:"network"`) {
		t.Errorf("non-HTTP error should record code='network':\n%s", dump)
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
	dump := scrape(t, m)
	for _, want := range []string{`name:"owner" value:"vendor:foo"`, `name:"owner" value:"oslo:bar"`} {
		if !strings.Contains(dump, want) {
			t.Errorf("missing %q in:\n%s", want, dump)
		}
	}
}

func TestMetrics_NilReceiverSafe(t *testing.T) {
	var m *Metrics
	// Nil receivers must not panic — defensive against forgotten
	// construction in test paths.
	m.RecordAPIError("ports", errors.New("x"))
	m.RecordUnknownOwner("vendor:y")
}
