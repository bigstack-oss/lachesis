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
	"github.com/bigstack-oss/lachesis/internal/reconcile"
)

// populateStats summarises what [populateMetadataFromPorts]
// admitted, skipped, or flagged. Surfaced in the final cold-start
// log so an operator can spot drift at a glance.
type populateStats struct {
	inserted      int // MACs written into the userspace map
	skipped       int // device-owner-eligible ports with an unparseable MAC
	unknownOwners int // admitted by IsVMPort but absent from IsKnownVMOwner
	amphoraPorts  int // re-attributed from the service project to an LB owner
}

// coldStartNeutron syncs Neutron, populates userspace metadata, pushes
// the kernel maps, then commits. Must run BEFORE TC attach so the first
// packet sees a populated trie. A no-op when Neutron is disabled: every
// flow then labels "unknown".
//
// Non-retryable auth errors surface immediately, so a typo'd URL fails
// loudly instead of spinning forever.
//
// docs/architecture/boot-and-recovery.md#boot-sequence
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
	// the Resolver reads it from the first scrape.
	//
	// Billing tiers: docs/architecture/billing.md
	ag.routers.Replace(neutron.RouterExtMACs(&result.Snapshot))
	nMac, nTrie, err := pushToKernel(ag, coll, &result)
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
		"amphora_ports_reattributed", stats.amphoraPorts,
	)
	return nil
}

// populateMetadataFromPorts publishes [reconcile.DesiredMACs] into the
// userspace map. The attribution is deliberately NOT computed here —
// cold start and the reconciler must agree exactly, so both read the one
// definition. What belongs to cold start alone is [auditPorts]: the
// boot-time logging an operator wants once, not every pass.
func populateMetadataFromPorts(meta *metadata.ShardedMetadataMap, snap *neutron.Snapshot, mx *neutron.Metrics) populateStats {
	desired := reconcile.DesiredMACs(snap)
	var s populateStats
	for mac, want := range desired {
		m := want // fresh copy per insert; the map owns the pointer
		meta.Insert(mac, &m)
		s.inserted++
		if m.IsAmphora {
			s.amphoraPorts++
		}
	}
	auditPorts(snap, desired, mx, &s)
	mx.SetAmphoraPorts(s.amphoraPorts)
	return s
}

// auditPorts walks the snapshot for the conditions an operator should
// see once, at boot, and records them on `s` and the Neutron metrics
// bundle:
//
//   - a port the admission gate accepted whose MAC will not parse (it is
//     absent from the metadata map, so its traffic bills "unknown");
//   - a device_owner outside the IsKnownVMOwner allowlist, so a vendor or
//     plugin string that slipped past the broad blacklist is visible;
//   - trunk subports, whose MACs admit but whose 802.1Q-tagged frames the
//     data plane passes uncounted (docs/architecture/edge-cases.md#tier-1--hard-limits);
//   - each Amphora port whose billing identity was rewritten, with both
//     the service project it left and the LB owner it joined.
//
// It is diagnostics only — it produces no attribution, so a drift
// between its gate and [reconcile.DesiredMACs] can misreport a count but
// can never mis-bill. That is why the duplicated admission conditions
// here are acceptable and the attribution is not.
func auditPorts(snap *neutron.Snapshot, desired map[uint64]metadata.TenantMeta, mx *neutron.Metrics, s *populateStats) {
	trunkSubports := 0
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
		if m, ok := desired[bpf.MACKey(key)]; ok && m.IsAmphora {
			slog.Info("Amphora port re-attributed to its load balancer's owner",
				"component", componentNeutron,
				"port_id", p.ID,
				"service_project", p.ProjectID,
				"lb_owner", m.ProjectID)
		}
	}
	if trunkSubports > 0 {
		slog.Warn("trunk subports present; 802.1Q-tagged traffic on trunk parents is not counted (docs/architecture/edge-cases.md)",
			"component", componentNeutron,
			"trunk_subports", trunkSubports)
	}
	mx.SetTrunkSubports(trunkSubports)
}

// pushToKernel writes the userspace metadata map, the built trie
// entries, and the Octavia Amphora base-address set into the kernel
// maps. Single-shot — no retry. Map updates can fail with EINVAL (bad
// key) or ENOSPC (map full); both indicate a real bug or a sizing
// regression and retrying would just paper over the cause.
func pushToKernel(ag *Agent, coll *ebpf.Collection, result *neutron.SyncResult) (nMac, nTrie int, err error) {
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
	nTrie, err = kernelwriter.WriteSubnetZoneTrie(trieMap, result.Entries, ag.interner)
	if err != nil {
		return nMac, nTrie, fmt.Errorf("write subnet_zone_trie (wrote %d): %w", nTrie, err)
	}
	amphoraMap := coll.Maps[bpf.MapAmphoraBaseIP]
	if amphoraMap == nil {
		return nMac, nTrie, fmt.Errorf("%s map missing from collection", bpf.MapAmphoraBaseIP)
	}
	nAmp, err := kernelwriter.WriteAmphoraBaseIPs(amphoraMap,
		neutron.AmphoraBaseIPs(&result.Snapshot), ag.interner)
	if err != nil {
		return nMac, nTrie, fmt.Errorf("write amphora_base_ip (wrote %d): %w", nAmp, err)
	}
	ag.mx.bpf.SetCurrent(bpf.MapAmphoraBaseIP, float64(nAmp))
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
