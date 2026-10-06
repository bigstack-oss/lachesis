// info.go implements the identity info-metric families that let
// dashboards render human names next to UUIDs — the kube-state-metrics
// kube_pod_info pattern (an additive `<entity>_info{id, name} 1` series
// joined onto the billing families with group_left).
//
// Full rationale: docs/architecture/metrics.md

package neutron

import (
	"sort"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

// InfoCollector emits the additive lachesis_tenant_info,
// lachesis_server_info and lachesis_port_info families from the last committed snapshot, read
// lock-free at scrape time.
//
// Kept separate from the billing Collector by design: the billing
// families must stay byte-identical, and names live only as info series
// so a historical join shows the name an entity held then. Re-emitting
// from the current snapshot each Collect gives them a mortal lifecycle
// a GaugeVec could not, which would leak deleted-entity series.
//
// docs/architecture/metrics.md
type InfoCollector struct {
	// snapshot returns the most recently committed snapshot, or nil
	// before the first commit (Neutron disabled or not yet synced).
	// Wired to [Neutron.Snapshot] — an atomic pointer load, so Collect
	// never contends with a running sync.
	snapshot func() *Snapshot

	tenantInfo *prometheus.Desc
	serverInfo *prometheus.Desc
	portInfo   *prometheus.Desc
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
		portInfo: prometheus.NewDesc(
			"lachesis_port_info",
			"Identity mapping for a VM port: value is always 1, joined onto the per-port family by port_id (group_left) to render its MAC and fixed IPs. One series per VM port; ips is the sorted, comma-joined fixed-IP list.",
			[]string{"port_id", "server_id", "tenant_id", "mac", "ips"}, nil,
		),
	}
}

// Describe implements [prometheus.Collector].
func (c *InfoCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.tenantInfo
	ch <- c.serverInfo
	ch <- c.portInfo
}

// Collect implements [prometheus.Collector]. It reads the committed
// snapshot and emits one value-1 series per project, per server and per
// VM port. A
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

	seenPort := make(map[string]struct{}, len(snap.Ports))
	for _, p := range snap.Ports {
		if !isInfoPort(p) {
			continue
		}
		if _, dup := seenPort[p.ID]; dup {
			continue
		}
		seenPort[p.ID] = struct{}{}
		ch <- prometheus.MustNewConstMetric(c.portInfo, prometheus.GaugeValue, 1,
			p.ID, p.DeviceID, p.ProjectID, p.MACAddress, joinFixedIPs(p.FixedIPs))
	}
}

// isInfoPort reports whether p gets a lachesis_port_info series: the
// same predicate that admits a port's MAC into mac_tenant_map, so every
// port_id the per-port billing family can carry has an info series to
// join, and router/DHCP ports stay out.
func isInfoPort(p Port) bool {
	return p.ID != "" && IsVMPort(p.DeviceOwner) && p.ProjectID != "" && p.MACAddress != ""
}

// joinFixedIPs renders a port's fixed IPs as one sorted, comma-joined
// label value. One series per port (not per IP) keeps the group_left
// join 1:1 — a per-IP series would duplicate billing rows on join.
// Sorting makes the value stable across Neutron list orderings, so an
// unchanged port never churns into a new series.
func joinFixedIPs(ips []FixedIP) string {
	addrs := make([]string, 0, len(ips))
	for _, ip := range ips {
		if ip.IPAddress != "" {
			addrs = append(addrs, ip.IPAddress)
		}
	}
	sort.Strings(addrs)
	return strings.Join(addrs, ",")
}
