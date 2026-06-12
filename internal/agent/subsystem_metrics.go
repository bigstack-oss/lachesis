// subsystem_metrics.go defines [subsystemMetrics], the bundle of
// per-subsystem Prometheus instruments the [Agent] registers alongside
// its custom Collector, and the registration list that fixes their
// order. The bundle is a distinct responsibility from the Agent
// lifecycle, so it lives apart from agent.go.

package agent

import (
	"log/slog"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	cnetlink "github.com/bigstack-oss/cube-cos-network-telemetry/internal/netlink"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/neutron"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/scraper"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/wal"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/zombie"
)

// subsystemMetrics bundles the per-subsystem Prometheus instrument
// sets the agent registers alongside its custom Collector, plus the
// netlink Interface Registry shared with the
// cubecos_attached_interfaces gauge. The registry is owned by the
// netlink subscriber (when non-nil) but also read by the netlink
// metrics for its current-size gauge.
type subsystemMetrics struct {
	wal      *wal.Metrics
	neutron  *neutron.Metrics
	bpf      *bpf.Metrics
	zombie   *zombie.Metrics
	netlink  *cnetlink.Metrics
	registry *cnetlink.Registry
}

// newSubsystemMetrics constructs every subsystem's instrument bundle.
// neutronMx is the exception: that bundle is owned by the agent's
// [neutron.Neutron] (which feeds its own sync-age gauge), so it is
// passed in rather than constructed here. The BPF map gauges are
// seeded here: max from the Go-side MaxEntries constants, current at
// 0 until the first cold-start push (mac_tenant_map,
// subnet_zone_trie) or the first scrape drain (telemetry_map, via
// [telemetryFillReader]) overwrites it.
func newSubsystemMetrics(neutronMx *neutron.Metrics) subsystemMetrics {
	nlReg := cnetlink.NewRegistry()

	bpfMx := bpf.NewMetrics()
	bpfMx.SetMax(bpf.MapMacTenant, float64(bpf.MapMacTenantMaxEntries))
	bpfMx.SetMax(bpf.MapSubnetZoneTrie, float64(bpf.MapSubnetZoneTrieMaxEntries))
	bpfMx.SetMax(bpf.MapTelemetry, float64(bpf.MapTelemetryMaxEntries))
	bpfMx.SetCurrent(bpf.MapMacTenant, 0)
	bpfMx.SetCurrent(bpf.MapSubnetZoneTrie, 0)
	bpfMx.SetCurrent(bpf.MapTelemetry, 0)

	return subsystemMetrics{
		wal:      wal.NewMetrics(),
		neutron:  neutronMx,
		bpf:      bpfMx,
		zombie:   zombie.NewMetrics(),
		netlink:  cnetlink.NewMetrics(nlReg.Len),
		registry: nlReg,
	}
}

// telemetryFillReader decorates the scraper's [scraper.MapReader] so
// every successful drain records the kernel telemetry_map entry count
// into the cubecos_bpf_map_current_entries{map="telemetry_map"} gauge.
// The drained key set IS the kernel map's current population
// (read-don't-clear; only GC evicts), so len(dst) after a full
// BatchLookup is the fill numerator the pressure-relief threshold
// (docs/DESIGN.md §3.1, >80%) is defined against. Errors skip the
// gauge update — a partial drain would understate fill.
//
// The same successful drain also reads the kernel telemetry_stats
// counters (when stats is wired) into
// cubecos_bpf_update_failures_total{reason}, keeping the loss counters
// on the same cadence as the fill gauge they explain.
type telemetryFillReader struct {
	inner scraper.MapReader
	// stats is nil when the telemetry_stats map isn't wired (darwin,
	// unit tests); see [Options.Stats].
	stats *bpf.StatsReader
	mx    *bpf.Metrics
}

// BatchLookup implements [scraper.MapReader].
func (r telemetryFillReader) BatchLookup(dst map[bpf.FlowKey]bpf.FlowMetrics) error {
	if err := r.inner.BatchLookup(dst); err != nil {
		return err
	}
	r.mx.SetCurrent(bpf.MapTelemetry, float64(len(dst)))
	if r.stats != nil {
		counts, err := r.stats.Read()
		if err != nil {
			// Never fail the tick — the billing drain above already
			// succeeded. Logged (not silent) and retried next tick;
			// the exported counters just stay one interval stale.
			slog.Warn("telemetry_stats drain failed; cubecos_bpf_update_failures_total is stale",
				"component", componentBPF, "err", err)
			return nil
		}
		r.mx.SetUpdateFailures(counts)
	}
	return nil
}

// registrations returns every subsystem's instruments in a stable
// order. The fixed order keeps a duplicate-registration error naming
// the same subsystem on every run, and makes adding a subsystem a
// one-line change here. Labels reuse the component* vocabulary
// (schema.go) so a registration error and the subsystem's log lines
// name it identically.
func (m subsystemMetrics) registrations() []labelledCollectors {
	return []labelledCollectors{
		{componentWAL, m.wal.Collectors()},
		{componentNeutron, m.neutron.Collectors()},
		{componentBPF, m.bpf.Collectors()},
		{componentZombie, m.zombie.Collectors()},
		{componentNetlink, m.netlink.Collectors()},
	}
}
