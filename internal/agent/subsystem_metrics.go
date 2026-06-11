// subsystem_metrics.go defines [subsystemMetrics], the bundle of
// per-subsystem Prometheus instruments the [Agent] registers alongside
// its custom Collector, and the registration list that fixes their
// order. The bundle is a distinct responsibility from the Agent
// lifecycle, so it lives apart from agent.go.

package agent

import (
	"time"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	cnetlink "github.com/bigstack-oss/cube-cos-network-telemetry/internal/netlink"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/neutron"
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
// syncTime feeds the neutron sync-age gauge; [New] passes the agent's
// lastNeutronSyncTime so the gauge reads the live timestamp at scrape
// time. The BPF map gauges are seeded here: max from the Go-side
// MaxEntries constants, current at 0 until the first cold-start push
// overwrites it.
func newSubsystemMetrics(syncTime func() time.Time) subsystemMetrics {
	nlReg := cnetlink.NewRegistry()

	bpfMx := bpf.NewMetrics()
	bpfMx.SetMax(bpf.MapMacTenant, float64(bpf.MapMacTenantMaxEntries))
	bpfMx.SetMax(bpf.MapSubnetZoneTrie, float64(bpf.MapSubnetZoneTrieMaxEntries))
	bpfMx.SetCurrent(bpf.MapMacTenant, 0)
	bpfMx.SetCurrent(bpf.MapSubnetZoneTrie, 0)

	return subsystemMetrics{
		wal:      wal.NewMetrics(),
		neutron:  neutron.NewMetrics(syncTime),
		bpf:      bpfMx,
		zombie:   zombie.NewMetrics(),
		netlink:  cnetlink.NewMetrics(nlReg.Len),
		registry: nlReg,
	}
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
