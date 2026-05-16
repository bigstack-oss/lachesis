//go:build linux

package agent

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/cilium/ebpf"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/config"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/kernelwriter"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/metadata"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/neutron"
)

// populateStats summarises what [populateMetadataFromPorts]
// admitted, skipped, or flagged. Surfaced in the final cold-start
// log so an operator can spot drift at a glance.
type populateStats struct {
	inserted      int // MACs written into the userspace map
	skipped       int // device-owner-eligible ports with an unparseable MAC
	unknownOwners int // admitted by IsVMPort but absent from IsKnownVMOwner
}

// coldStartNeutron orchestrates the cold-start sequence: fetch the
// Neutron snapshot (with retry), populate userspace metadata, push
// into the kernel maps. Must run BEFORE TC attach so the very first
// packet sees a populated trie (docs/DESIGN.md §9 step 3 → 4).
//
// When `cfg.Enabled == false` it is a no-op — every flow's
// `tenant_id` label resolves to "unknown" until an operator enables
// Neutron and restarts.
func coldStartNeutron(ctx context.Context, cfg config.NeutronConfig, ag *Agent, coll *ebpf.Collection) error {
	if !cfg.Enabled {
		slog.Info("neutron disabled; agent boots without metadata",
			"component", componentNeutron)
		return nil
	}
	creds, err := neutron.FromConfig(cfg)
	if err != nil {
		return fmt.Errorf("credentials: %w", err)
	}
	client, snap, err := fetchNeutronSnapshot(ctx, creds)
	if err != nil {
		return err
	}
	stats := populateMetadataFromPorts(ag.Metadata(), snap.Ports)
	nMac, nTrie, err := pushSnapshotToKernel(ag, coll, snap)
	if err != nil {
		return err
	}
	slog.Info("neutron cold-start complete",
		"component", componentNeutron,
		"endpoint", client.EndpointURL(),
		"macs_written", nMac,
		"trie_entries_written", nTrie,
		"tenants_interned", ag.Interner().Len(),
		"ports_skipped", stats.skipped,
		"unknown_owners_admitted", stats.unknownOwners,
	)
	return nil
}

// fetchNeutronSnapshot authenticates against Keystone and pulls the
// four Neutron resource lists, retrying transient failures via
// [retryWithBackoff]. The client is created lazily inside the retry
// closure and cached across iterations so a successful auth survives
// a transient fetch failure.
//
// Non-retryable errors (401/403/404/400) surface immediately so an
// operator notices a typo'd auth URL or bad credentials instead of
// the agent spinning forever.
func fetchNeutronSnapshot(ctx context.Context, creds neutron.Credentials) (*neutron.Client, neutron.Snapshot, error) {
	var client *neutron.Client
	var snap neutron.Snapshot
	err := retryWithBackoff(ctx, neutronBackoffInitial, neutronBackoffMax,
		func(ctx context.Context) error {
			if client == nil {
				c, err := neutron.NewClient(ctx, creds)
				if err != nil {
					return fmt.Errorf("keystone auth: %w", err)
				}
				client = c
			}
			var ferr error
			snap, ferr = neutron.FetchSnapshot(ctx, client)
			return ferr
		})
	return client, snap, err
}

// populateMetadataFromPorts walks ports, applies the IsVMPort
// blacklist, parses MACs, and inserts (mac → *TenantMeta) into the
// userspace shard map. Logs every port admitted with an unknown
// device_owner (the IsKnownVMOwner allowlist miss) so operators
// notice when a vendor / plugin string slipped past the broad
// blacklist.
func populateMetadataFromPorts(meta *metadata.ShardedMetadataMap, ports []neutron.Port) populateStats {
	var s populateStats
	for _, p := range ports {
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
			s.unknownOwners++
		}
		var key [6]uint8
		copy(key[:], hw)
		meta.Insert(bpf.MACKey(key), &metadata.TenantMeta{ProjectID: p.ProjectID})
		s.inserted++
	}
	return s
}

// pushSnapshotToKernel builds the LPM trie entries from snap and
// pushes both maps into the kernel. Single-shot — no retry. Map
// updates can fail with EINVAL (bad key) or ENOSPC (map full); both
// indicate a real bug or a sizing regression and retrying would
// just paper over the cause.
func pushSnapshotToKernel(ag *Agent, coll *ebpf.Collection, snap neutron.Snapshot) (nMac, nTrie int, err error) {
	macMap := coll.Maps[bpf.MapMacTenant]
	if macMap == nil {
		return 0, 0, fmt.Errorf("%s map missing from collection", bpf.MapMacTenant)
	}
	trieMap := coll.Maps[bpf.MapSubnetZoneTrie]
	if trieMap == nil {
		return 0, 0, fmt.Errorf("%s map missing from collection", bpf.MapSubnetZoneTrie)
	}
	entries := neutron.BuildTrie(snap.Networks, snap.Subnets, snap.Ports, snap.Routers)
	nMac, err = kernelwriter.WriteMacTenantMap(macMap, ag.Metadata(), ag.Interner())
	if err != nil {
		return nMac, 0, fmt.Errorf("write mac_tenant_map (wrote %d): %w", nMac, err)
	}
	nTrie, err = kernelwriter.WriteSubnetZoneTrie(trieMap, entries, ag.Interner())
	if err != nil {
		return nMac, nTrie, fmt.Errorf("write subnet_zone_trie (wrote %d): %w", nTrie, err)
	}
	return nMac, nTrie, nil
}
