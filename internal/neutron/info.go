// info.go implements the identity info-metric families that let
// dashboards render human names next to UUIDs — the kube-state-metrics
// kube_pod_info pattern (an additive `<entity>_info{id, name} 1` series
// joined onto the billing families with group_left). See docs/DESIGN.md
// §11.4.

package neutron

import "github.com/prometheus/client_golang/prometheus"

// InfoCollector emits two additive info-metric families from the most
// recently committed [Snapshot], read lock-free at scrape time:
//
//   - lachesis_tenant_info{tenant_id, name} 1 — one series per Keystone
//     project (docs/DESIGN.md §11.4). Free: the project list is already
//     fetched for the /debug pages.
//   - lachesis_server_info{server_id, name, tenant_id} 1 — one series per
//     Nova server, from the best-effort server list.
//
// Both are separate from the billing Collector by design: the billing
// families must stay byte-identical, and names live only as info series
// so historical joins show the name an entity held at that time. Because
// each Collect re-emits from the current snapshot, a series disappears
// the sync after its entity leaves the snapshot — the mortal lifecycle a
// GaugeVec could not give without leaking deleted-entity series.
type InfoCollector struct {
	// snapshot returns the most recently committed snapshot, or nil
	// before the first commit (Neutron disabled or not yet synced).
	// Wired to [Neutron.Snapshot] — an atomic pointer load, so Collect
	// never contends with a running sync.
	snapshot func() *Snapshot

	tenantInfo *prometheus.Desc
	serverInfo *prometheus.Desc
}

// NewInfoCollector constructs the collector over a committed-snapshot
// accessor. Mirrors [NewMetrics]'s lastSync-accessor shape.
func NewInfoCollector(snapshot func() *Snapshot) *InfoCollector {
	return &InfoCollector{
		snapshot: snapshot,
		tenantInfo: prometheus.NewDesc(
			"lachesis_tenant_info",
			"Identity mapping for a tenant: value is always 1, joined onto the billing families by tenant_id (group_left) to render name(id). One series per known Keystone project.",
			[]string{"tenant_id", "name"}, nil,
		),
		serverInfo: prometheus.NewDesc(
			"lachesis_server_info",
			"Identity mapping for a server: value is always 1, joined onto the per-server family by server_id (group_left) to render name(id). One series per known Nova server; absent when the Nova fetch fails.",
			[]string{"server_id", "name", "tenant_id"}, nil,
		),
	}
}

// Describe implements [prometheus.Collector].
func (c *InfoCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.tenantInfo
	ch <- c.serverInfo
}

// Collect implements [prometheus.Collector]. It reads the committed
// snapshot and emits one value-1 series per project and per server. A
// nil snapshot (never synced) emits nothing — the graceful-degradation
// contract dashboards rely on. Entries with an empty id are skipped, and
// a per-scrape seen-set drops duplicate ids so a malformed upstream list
// can never turn into a Gather error that fails the whole scrape.
func (c *InfoCollector) Collect(ch chan<- prometheus.Metric) {
	snap := c.snapshot()
	if snap == nil {
		return
	}

	seenTenant := make(map[string]struct{}, len(snap.Projects))
	for _, p := range snap.Projects {
		if p.ID == "" {
			continue
		}
		if _, dup := seenTenant[p.ID]; dup {
			continue
		}
		seenTenant[p.ID] = struct{}{}
		ch <- prometheus.MustNewConstMetric(c.tenantInfo, prometheus.GaugeValue, 1, p.ID, p.Name)
	}

	seenServer := make(map[string]struct{}, len(snap.Servers))
	for _, s := range snap.Servers {
		if s.ID == "" {
			continue
		}
		if _, dup := seenServer[s.ID]; dup {
			continue
		}
		seenServer[s.ID] = struct{}{}
		ch <- prometheus.MustNewConstMetric(c.serverInfo, prometheus.GaugeValue, 1, s.ID, s.Name, s.ProjectID)
	}
}
