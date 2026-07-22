//go:build linux

package agent

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/cilium/ebpf"

	"github.com/bigstack-oss/lachesis/internal/bpf"
	"github.com/bigstack-oss/lachesis/internal/config"
	"github.com/bigstack-oss/lachesis/internal/kernelwriter"
	"github.com/bigstack-oss/lachesis/internal/metadata"
	"github.com/bigstack-oss/lachesis/internal/neutron"
)

// populateStats summarises what [populateMetadataFromPorts]
// admitted, skipped, or flagged. Surfaced in the final cold-start
// log so an operator can spot drift at a glance.
type populateStats struct {
	inserted      int // MACs written into the userspace map
	skipped       int // device-owner-eligible ports with an unparseable MAC
	unknownOwners int // admitted by IsVMPort but absent from IsKnownVMOwner
}

// coldStartNeutron orchestrates the cold-start sequence: run a full
// [neutron.Neutron.Sync] (with retry), populate userspace metadata,
// push into the kernel maps, then commit the sync outputs so the
// /debug pages and sync-age gauge see them. Must run BEFORE TC
// attach so the very first packet sees a populated trie
// (docs/architecture/boot-and-recovery.md#boot-sequence step 3 → 4).
//
// When `cfg.Enabled == false` it is a no-op — every flow's
// `tenant_id` label resolves to "unknown" until an operator enables
// Neutron and restarts.
//
// Non-retryable Sync errors (401/403/404/400) surface immediately so
// an operator notices a typo'd auth URL or bad credentials instead
// of the agent spinning forever; see [isRetryableNeutronErr].
func coldStartNeutron(ctx context.Context, cfg config.NeutronConfig, ag *Agent, coll *ebpf.Collection) error {
	if !cfg.Enabled {
		slog.Info("neutron disabled; agent boots without metadata",
			"component", componentNeutron)
		return nil
	}
	var result neutron.SyncResult
	err := retryWithBackoff(ctx, neutronBackoffInitial, neutronBackoffMax,
		func(ctx context.Context) error {
			r, err := ag.neutron.Sync(ctx)
			if err != nil {
				return err
			}
			result = r
			return nil
		})
	if err != nil {
		return err
	}
	stats := populateMetadataFromPorts(ag.meta, &result.Snapshot, ag.mx.neutron)
	// Seed the per-flow router map in the same before-any-packet step:
	// the Resolver reads it from the first scrape (docs/architecture/billing.md).
	ag.routers.Replace(neutron.RouterExtMACs(&result.Snapshot))
	nMac, nTrie, err := pushToKernel(ag, coll, result.Entries)
	if err != nil {
		return err
	}
	if err := enforceAmbiguityPolicy(cfg, result.Ambiguities); err != nil {
		return err
	}
	ag.mx.bpf.SetCurrent(bpf.MapMacTenant, float64(nMac))
	ag.mx.bpf.SetCurrent(bpf.MapSubnetZoneTrie, float64(nTrie))
	ag.neutron.Commit(result, time.Now())
	slog.Info("neutron cold-start complete",
		"component", componentNeutron,
		"endpoint", ag.neutron.EndpointURL(),
		"ports_admitted", stats.inserted,
		"macs_written", nMac,
		"trie_entries_written", nTrie,
		"tenants_interned", ag.interner.Len(),
		"ports_skipped", stats.skipped,
		"unknown_owners_admitted", stats.unknownOwners,
	)
	return nil
}

// populateMetadataFromPorts walks the snapshot's ports, applies the
// IsVMPort blacklist, parses MACs, and inserts (mac → *TenantMeta) into
// the userspace shard map — each entry carrying the port's full
// attribution (project, server_id, external_network) for the metric
// labels and per-server export (docs/architecture/billing.md). Logs every port
// admitted with an unknown device_owner (the IsKnownVMOwner allowlist
// miss) so operators notice when a vendor / plugin string slipped past
// the broad blacklist, and emits one summary warning when the snapshot
// contains trunk subports — their MACs admit here but the data plane
// passes 802.1Q-tagged frames uncounted (docs/architecture/edge-cases.md#tier-1--hard-limits).
func populateMetadataFromPorts(meta *metadata.ShardedMetadataMap, snap *neutron.Snapshot, mx *neutron.Metrics) populateStats {
	var s populateStats
	trunkSubports := 0
	extByPort := neutron.ExternalNetworkByPort(snap)
	for _, p := range snap.Ports {
		if !neutron.IsVMPort(p.DeviceOwner) || p.ProjectID == "" || p.MACAddress == "" {
			continue
		}
		hw, err := net.ParseMAC(p.MACAddress)
		if err != nil || len(hw) != 6 {
			slog.Warn("invalid port MAC; skipped",
				"component", componentNeutron,
				"port_id", p.ID, "mac", p.MACAddress, "err", err)
			s.skipped++
			continue
		}
		if !neutron.IsKnownVMOwner(p.DeviceOwner) {
			slog.Warn("unknown device_owner admitted to mac_tenant_map",
				"component", componentNeutron,
				"port_id", p.ID,
				"device_owner", p.DeviceOwner,
				"project_id", p.ProjectID)
			mx.RecordUnknownOwner(p.DeviceOwner)
			s.unknownOwners++
		}
		if neutron.IsTrunkSubport(p.DeviceOwner) {
			trunkSubports++
		}
		var key [6]uint8
		copy(key[:], hw)
		meta.Insert(bpf.MACKey(key), &metadata.TenantMeta{
			ProjectID:       p.ProjectID,
			ServerID:        p.DeviceID,
			PortID:          p.ID,
			ExternalNetwork: extByPort[p.ID],
		})
		s.inserted++
	}
	if trunkSubports > 0 {
		slog.Warn("trunk subports present; 802.1Q-tagged traffic on trunk parents is not counted (docs/architecture/edge-cases.md)",
			"component", componentNeutron,
			"trunk_subports", trunkSubports)
	}
	mx.SetTrunkSubports(trunkSubports)
	return s
}

// pushToKernel writes the userspace metadata map and the built trie
// entries into the kernel maps. Single-shot — no retry. Map updates
// can fail with EINVAL (bad key) or ENOSPC (map full); both indicate
// a real bug or a sizing regression and retrying would just paper
// over the cause.
func pushToKernel(ag *Agent, coll *ebpf.Collection, entries []neutron.TrieEntry) (nMac, nTrie int, err error) {
	macMap := coll.Maps[bpf.MapMacTenant]
	if macMap == nil {
		return 0, 0, fmt.Errorf("%s map missing from collection", bpf.MapMacTenant)
	}
	trieMap := coll.Maps[bpf.MapSubnetZoneTrie]
	if trieMap == nil {
		return 0, 0, fmt.Errorf("%s map missing from collection", bpf.MapSubnetZoneTrie)
	}
	nMac, err = kernelwriter.WriteMacTenantMap(macMap, ag.meta, ag.interner)
	if err != nil {
		return nMac, 0, fmt.Errorf("write mac_tenant_map (wrote %d): %w", nMac, err)
	}
	nTrie, err = kernelwriter.WriteSubnetZoneTrie(trieMap, entries, ag.interner)
	if err != nil {
		return nMac, nTrie, fmt.Errorf("write subnet_zone_trie (wrote %d): %w", nTrie, err)
	}
	return nMac, nTrie, nil
}

// enforceAmbiguityPolicy applies the static-route ambiguity policy to
// the resolver's hits: in strict mode (the default) any ambiguity
// aborts the cold start; under `neutron.unsafe_allow_ambiguous_routes`
// the hits are accepted with EXTERNAL fallback and logged instead.
func enforceAmbiguityPolicy(cfg config.NeutronConfig, ambiguities []neutron.AmbiguityHit) error {
	if len(ambiguities) == 0 {
		return nil
	}
	if !cfg.UnsafeAllowAmbiguousRoutes {
		return fmt.Errorf("static-route ambiguity in strict mode (%d hits, first=%+v); "+
			"set neutron.unsafe_allow_ambiguous_routes=true to accept EXTERNAL fallback and continue",
			len(ambiguities), ambiguities[0])
	}
	slog.Warn("static-route ambiguities accepted under unsafe mode",
		"component", componentNeutron,
		"count", len(ambiguities))
	// One detail entry per hit so operators don't have to grep for
	// individual routers / destinations — `grep -c "ambiguity hit"`
	// is the count, and each line carries the (source_tenant,
	// router, destination, owners) tuple needed to investigate.
	for _, hit := range ambiguities {
		slog.Warn("static-route ambiguity hit",
			"component", componentNeutron,
			"source_tenant", hit.SourceTenant,
			"router", hit.RouterID,
			"destination", hit.Destination.String(),
			"owners", hit.Owners)
	}
	return nil
}
