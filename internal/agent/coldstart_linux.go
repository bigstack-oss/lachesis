//go:build linux

package agent

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

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
	client, snap, err := fetchNeutronSnapshot(ctx, creds, ag.mx.neutron)
	if err != nil {
		return err
	}
	stats := populateMetadataFromPorts(ag.meta, snap.Ports, ag.mx.neutron)
	nMac, nTrie, entries, ambiguities, cycles, err := pushSnapshotToKernel(ag, coll, snap)
	if err != nil {
		return err
	}
	if len(ambiguities) > 0 {
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
	}
	ag.mx.bpf.SetCurrent(bpf.MapMacTenant, float64(nMac))
	ag.mx.bpf.SetCurrent(bpf.MapSubnetZoneTrie, float64(nTrie))
	anomalies := neutron.DetectAnomalies(snap, entries, cycles, ambiguities)
	ag.mx.neutron.SetAnomalies(anomalies)
	ag.markNeutronSync(time.Now())
	slog.Info("neutron cold-start complete",
		"component", componentNeutron,
		"endpoint", client.EndpointURL(),
		"ports_admitted", stats.inserted,
		"macs_written", nMac,
		"trie_entries_written", nTrie,
		"tenants_interned", ag.interner.Len(),
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
func fetchNeutronSnapshot(ctx context.Context, creds neutron.Credentials, mx *neutron.Metrics) (*neutron.Client, neutron.Snapshot, error) {
	var client *neutron.Client
	var snap neutron.Snapshot
	err := retryWithBackoff(ctx, neutronBackoffInitial, neutronBackoffMax,
		func(ctx context.Context) error {
			if client == nil {
				c, err := neutron.NewClient(ctx, creds)
				if err != nil {
					mx.RecordAPIError(neutron.EndpointKeystone, err)
					return fmt.Errorf("keystone auth: %w", err)
				}
				client = c
			}
			s, ferr := fetchAllWithMetrics(ctx, client, mx)
			if ferr != nil {
				return ferr
			}
			snap = s
			return nil
		})
	return client, snap, err
}

// fetchAllWithMetrics issues the list calls in sequence and records
// per-endpoint API errors via mx. The endpoint label is the resource
// name; on the kernel side this corresponds 1:1 to the Neutron URL
// path. The Keystone project list rides along so downstream
// consumers (/debug pages, log enrichment) can resolve project IDs
// to names.
func fetchAllWithMetrics(ctx context.Context, client *neutron.Client, mx *neutron.Metrics) (neutron.Snapshot, error) {
	var s neutron.Snapshot
	var err error
	if s.Networks, err = client.ListNetworks(ctx); err != nil {
		mx.RecordAPIError(neutron.EndpointNetworks, err)
		return s, fmt.Errorf("list networks: %w", err)
	}
	if s.Subnets, err = client.ListSubnets(ctx); err != nil {
		mx.RecordAPIError(neutron.EndpointSubnets, err)
		return s, fmt.Errorf("list subnets: %w", err)
	}
	if s.Ports, err = client.ListPorts(ctx); err != nil {
		mx.RecordAPIError(neutron.EndpointPorts, err)
		return s, fmt.Errorf("list ports: %w", err)
	}
	if s.Routers, err = client.ListRouters(ctx); err != nil {
		mx.RecordAPIError(neutron.EndpointRouters, err)
		return s, fmt.Errorf("list routers: %w", err)
	}
	if s.Projects, err = client.ListProjects(ctx); err != nil {
		mx.RecordAPIError(neutron.EndpointProjects, err)
		return s, fmt.Errorf("list projects: %w", err)
	}
	return s, nil
}

// populateMetadataFromPorts walks ports, applies the IsVMPort
// blacklist, parses MACs, and inserts (mac → *TenantMeta) into the
// userspace shard map. Logs every port admitted with an unknown
// device_owner (the IsKnownVMOwner allowlist miss) so operators
// notice when a vendor / plugin string slipped past the broad
// blacklist.
func populateMetadataFromPorts(meta *metadata.ShardedMetadataMap, ports []neutron.Port, mx *neutron.Metrics) populateStats {
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
			mx.RecordUnknownOwner(p.DeviceOwner)
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
//
// The built entries plus the resolver's ambiguity/cycle hits are
// returned alongside the write counts so the caller can run
// [neutron.DetectAnomalies] over exactly what the kernel received.
func pushSnapshotToKernel(ag *Agent, coll *ebpf.Collection, snap neutron.Snapshot) (nMac, nTrie int, entries []neutron.TrieEntry, ambiguities []neutron.AmbiguityHit, cycles []neutron.CycleHit, err error) {
	macMap := coll.Maps[bpf.MapMacTenant]
	if macMap == nil {
		return 0, 0, nil, nil, nil, fmt.Errorf("%s map missing from collection", bpf.MapMacTenant)
	}
	trieMap := coll.Maps[bpf.MapSubnetZoneTrie]
	if trieMap == nil {
		return 0, 0, nil, nil, nil, fmt.Errorf("%s map missing from collection", bpf.MapSubnetZoneTrie)
	}
	entries, ambiguities, cycles = neutron.BuildTrie(snap, neutron.WithMetrics(ag.mx.neutron))
	nMac, err = kernelwriter.WriteMacTenantMap(macMap, ag.meta, ag.interner)
	if err != nil {
		return nMac, 0, entries, ambiguities, cycles, fmt.Errorf("write mac_tenant_map (wrote %d): %w", nMac, err)
	}
	nTrie, err = kernelwriter.WriteSubnetZoneTrie(trieMap, entries, ag.interner)
	if err != nil {
		return nMac, nTrie, entries, ambiguities, cycles, fmt.Errorf("write subnet_zone_trie (wrote %d): %w", nTrie, err)
	}
	return nMac, nTrie, entries, ambiguities, cycles, nil
}
