package neutron

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

const (
	tenantInfoHeader = `# HELP lachesis_tenant_info Identity mapping for a tenant: value is always 1, joined onto the billing families by tenant_id (group_left) to render name(id). One series per known Keystone project.
# TYPE lachesis_tenant_info gauge
`
	serverInfoHeader = `# HELP lachesis_server_info Identity mapping for a server: value is always 1, joined onto the per-server family by server_id (group_left) to render name(id). One series per known Nova server; absent when the Nova fetch fails.
# TYPE lachesis_server_info gauge
`
)

// snapFunc returns a snapshot accessor over a fixed value, mimicking
// [Neutron.Snapshot]'s atomic-pointer read.
func snapFunc(s *Snapshot) func() *Snapshot { return func() *Snapshot { return s } }

func TestInfoCollector_EmitsBothFamilies(t *testing.T) {
	c := NewInfoCollector(snapFunc(&Snapshot{
		Projects: []Project{{ID: "proj-1", Name: "alpha"}, {ID: "proj-2", Name: "beta"}},
		Servers: []Server{
			{ID: "srv-1", Name: "web-0", ProjectID: "proj-1"},
			{ID: "srv-2", Name: "db-0", ProjectID: "proj-2"},
		},
	}))

	expected := tenantInfoHeader +
		`lachesis_tenant_info{name="alpha",tenant_id="proj-1"} 1
lachesis_tenant_info{name="beta",tenant_id="proj-2"} 1
` + serverInfoHeader +
		`lachesis_server_info{name="web-0",server_id="srv-1",tenant_id="proj-1"} 1
lachesis_server_info{name="db-0",server_id="srv-2",tenant_id="proj-2"} 1
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected),
		"lachesis_tenant_info", "lachesis_server_info"); err != nil {
		t.Errorf("CollectAndCompare: %v", err)
	}
}

// TestInfoCollector_NilSnapshotEmitsNothing pins the never-synced path:
// before the first commit the accessor returns nil and the collector
// emits no series (graceful — dashboards fall back to bare ids).
func TestInfoCollector_NilSnapshotEmitsNothing(t *testing.T) {
	c := NewInfoCollector(snapFunc(nil))
	if n := testutil.CollectAndCount(c); n != 0 {
		t.Errorf("nil snapshot emitted %d series, want 0", n)
	}
}

// TestInfoCollector_NovaDegradedOmitsServerFamily is the graceful-
// degradation contract: a snapshot whose Servers is empty (Nova fetch
// failed) still emits lachesis_tenant_info but no lachesis_server_info.
func TestInfoCollector_NovaDegradedOmitsServerFamily(t *testing.T) {
	c := NewInfoCollector(snapFunc(&Snapshot{
		Projects: []Project{{ID: "proj-1", Name: "alpha"}},
	}))

	expected := tenantInfoHeader + `lachesis_tenant_info{name="alpha",tenant_id="proj-1"} 1
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected),
		"lachesis_tenant_info"); err != nil {
		t.Errorf("tenant_info: %v", err)
	}
	if n := testutil.CollectAndCount(c, "lachesis_server_info"); n != 0 {
		t.Errorf("server_info emitted %d series with no servers, want 0", n)
	}
}

// TestInfoCollector_SkipsEmptyIDsAndDuplicates guards Collect against a
// malformed upstream list: entries with an empty id are skipped, and a
// repeated id is emitted once — a duplicate label set would otherwise
// fail the whole scrape's Gather.
func TestInfoCollector_SkipsEmptyIDsAndDuplicates(t *testing.T) {
	c := NewInfoCollector(snapFunc(&Snapshot{
		Projects: []Project{
			{ID: "proj-1", Name: "alpha"},
			{ID: "", Name: "no-id"},     // skipped
			{ID: "proj-1", Name: "dup"}, // deduped (first wins)
		},
		Servers: []Server{
			{ID: "srv-1", Name: "web-0", ProjectID: "proj-1"},
			{ID: "", Name: "no-id", ProjectID: "proj-1"}, // skipped
		},
	}))

	expected := tenantInfoHeader + `lachesis_tenant_info{name="alpha",tenant_id="proj-1"} 1
` + serverInfoHeader + `lachesis_server_info{name="web-0",server_id="srv-1",tenant_id="proj-1"} 1
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected),
		"lachesis_tenant_info", "lachesis_server_info"); err != nil {
		t.Errorf("CollectAndCompare: %v", err)
	}
}
