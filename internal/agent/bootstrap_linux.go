//go:build linux

package agent

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/config"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/kernelwriter"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/logging"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/metadata"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/neutron"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/wal"
)

// componentNeutron is the slog `component` attribute for log calls
// emitted from the Neutron cold-start phase of Bootstrap. Mirrors
// the constant of the same name in internal/neutron; redeclared
// here because Go won't let bootstrap_linux.go reach across the
// package boundary for an unexported identifier.
const componentNeutron = "neutron"

// Bootstrap is the agent's single startup sequence: parse args,
// initialise logging, lift the memlock rlimit, load BPF, populate
// the kernel maps from Neutron, attach TC, then build the [Agent].
// It returns the Agent plus an [io.Closer] that releases the BPF
// collection — call its Close after [Agent.Run] returns.
//
// Order (docs/DESIGN.md §9):
//
//  1. Load BPF collection (with map-size parity check)
//  2. Construct Agent (empty metadata + interner)
//  3. Neutron cold-start: populate ag.Metadata() + push kernel maps
//  4. Attach TC clsact (only now do packets start classifying)
//  5. WAL restore — GlobalState filled before the scraper goroutine
//     starts in Agent.Run
//
// Neutron is fetched BEFORE TC attach so the very first packet sees
// a populated trie; mis-classified flows become permanent entries
// in telemetry_map because dst_zone is part of FlowKey.
//
// ctx propagates through the Neutron HTTP calls — a SIGINT during
// cold-start aborts the boot.
//
// Bootstrap is Linux-only because the BPF lifecycle is. The
// cross-platform path used by unit tests constructs [Agent] directly
// via [New] with a synthetic [scraper.MapReader].
//
// Errors are wrapped with the phase they failed in so the caller
// need not understand the internals to print a useful message.
func Bootstrap(ctx context.Context, args []string) (*Agent, io.Closer, error) {
	cfg, err := config.Load(config.Options{}, args)
	if err != nil {
		return nil, nil, err
	}
	log, err := logging.Init(cfg.Logging, os.Stderr)
	if err != nil {
		return nil, nil, fmt.Errorf("init logging: %w", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, nil, fmt.Errorf("remove memlock rlimit: %w", err)
	}

	coll, err := loadCollection()
	if err != nil {
		return nil, nil, err
	}
	closer := collectionCloser{coll}

	reader, err := readerFromCollection(coll)
	if err != nil {
		closer.Close()
		return nil, nil, err
	}

	ag, err := New(Options{
		Config:     cfg,
		ConfigPath: config.FindConfigPath(config.Options{}, args),
		Reader:     reader,
		Log:        log,
	})
	if err != nil {
		closer.Close()
		return nil, nil, err
	}

	if err := coldStartNeutron(ctx, cfg.Neutron, ag, coll); err != nil {
		closer.Close()
		return nil, nil, fmt.Errorf("neutron cold-start: %w", err)
	}

	if err := attachIfRequested(cfg.BPF.AttachInterface, coll); err != nil {
		closer.Close()
		return nil, nil, err
	}

	if err := restoreFromWAL(ag, cfg.WAL); err != nil {
		// WAL restore failure is non-fatal — the design says "if
		// both fail, start empty and log the loss" (§3.2).
		// Surfacing as an error would block startup even though
		// the agent can run correctly with a fresh state.
		slog.Warn("restore failed; agent will start with empty state",
			"component", componentWAL, "err", err)
	}

	return ag, closer, nil
}

// coldStartNeutron fetches the Neutron snapshot, populates the
// userspace [metadata.ShardedMetadataMap], builds the trie via
// [neutron.BuildTrie], and pushes both into the kernel `mac_tenant_map`
// and `subnet_zone_trie` via [kernelwriter]. Must run BEFORE TC
// attach (docs/DESIGN.md §9 step 3 → 4).
//
// When `cfg.Enabled == false` the function is a no-op and the agent
// boots with empty metadata — every flow's `tenant_id` label
// resolves to "unknown" until an operator enables Neutron and
// restarts.
//
// Sprint 4a.7 layers exponential-backoff retry on top of this naive
// call sequence; today a single failure aborts boot.
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
	client, err := neutron.NewClient(ctx, creds)
	if err != nil {
		return fmt.Errorf("client: %w", err)
	}

	networks, err := client.ListNetworks(ctx)
	if err != nil {
		return fmt.Errorf("list networks: %w", err)
	}
	subnets, err := client.ListSubnets(ctx)
	if err != nil {
		return fmt.Errorf("list subnets: %w", err)
	}
	ports, err := client.ListPorts(ctx)
	if err != nil {
		return fmt.Errorf("list ports: %w", err)
	}
	routers, err := client.ListRouters(ctx)
	if err != nil {
		return fmt.Errorf("list routers: %w", err)
	}

	meta := ag.Metadata()
	skipped := 0
	unknownOwner := 0
	for _, p := range ports {
		if !neutron.IsVMPort(p.DeviceOwner) || p.ProjectID == "" || p.MACAddress == "" {
			continue
		}
		hw, err := net.ParseMAC(p.MACAddress)
		if err != nil || len(hw) != 6 {
			slog.Warn("invalid port MAC; skipped",
				"component", componentNeutron,
				"port_id", p.ID, "mac", p.MACAddress, "err", err)
			skipped++
			continue
		}
		if !neutron.IsKnownVMOwner(p.DeviceOwner) {
			// IsVMPort admitted this MAC under the conservative
			// blacklist; flag for operator visibility so a new
			// vendor / plugin owner doesn't silently shape billing.
			slog.Warn("unknown device_owner admitted to mac_tenant_map",
				"component", componentNeutron,
				"port_id", p.ID,
				"device_owner", p.DeviceOwner,
				"project_id", p.ProjectID)
			unknownOwner++
		}
		var key [6]uint8
		copy(key[:], hw)
		meta.Insert(bpf.MACKey(key), &metadata.TenantMeta{ProjectID: p.ProjectID})
	}

	entries := neutron.BuildTrie(networks, subnets, ports, routers)

	macMap := coll.Maps[bpf.MapMacTenant]
	if macMap == nil {
		return fmt.Errorf("%s map missing from collection", bpf.MapMacTenant)
	}
	trieMap := coll.Maps[bpf.MapSubnetZoneTrie]
	if trieMap == nil {
		return fmt.Errorf("%s map missing from collection", bpf.MapSubnetZoneTrie)
	}

	nMac, err := kernelwriter.WriteMacTenantMap(macMap, meta, ag.Interner())
	if err != nil {
		return fmt.Errorf("write mac_tenant_map (wrote %d): %w", nMac, err)
	}
	nTrie, err := kernelwriter.WriteSubnetZoneTrie(trieMap, entries, ag.Interner())
	if err != nil {
		return fmt.Errorf("write subnet_zone_trie (wrote %d): %w", nTrie, err)
	}

	slog.Info("neutron cold-start complete",
		"component", componentNeutron,
		"endpoint", client.EndpointURL(),
		"macs_written", nMac,
		"trie_entries_written", nTrie,
		"tenants_interned", ag.Interner().Len(),
		"ports_skipped", skipped,
		"unknown_owners_admitted", unknownOwner,
	)
	return nil
}

// restoreFromWAL reads the on-disk snapshot (if enabled) and seeds
// the agent's GlobalState. Runs BEFORE the scraper goroutine starts,
// so the first ApplyDelta computes deltas against restored
// LastEbpfRaw values rather than re-baselining.
//
// Load fallbacks (bak or empty) are recorded on the agent's WAL
// metrics so an operator can grep cubecos_wal_load_fallback_total
// to spot a corrupt primary or a first-boot.
func restoreFromWAL(ag *Agent, cfg config.WALConfig) error {
	if !cfg.Enabled {
		slog.Info("disabled; starting with empty state", "component", componentWAL)
		return nil
	}
	res, err := wal.Load(cfg.Path)
	if err != nil {
		return err
	}
	switch res.Source {
	case wal.LoadFromPrimary:
		slog.Info("restored from primary",
			"component", componentWAL,
			"path", cfg.Path, "records", len(res.Records))
	case wal.LoadFromBackup:
		slog.Warn("primary unusable; restored from backup",
			"component", componentWAL,
			"path", cfg.Path+wal.BackupSuffix, "records", len(res.Records))
		ag.WALMetrics().RecordLoadFallback(wal.LoadFallbackBak)
	case wal.LoadEmpty:
		slog.Info("no prior snapshot; starting empty",
			"component", componentWAL,
			"path", cfg.Path)
		ag.WALMetrics().RecordLoadFallback(wal.LoadFallbackEmpty)
	}
	if len(res.Records) > 0 {
		ag.SeedState(res.Records)
	}
	return nil
}

// loadCollection compiles the embedded BPF spec into a kernel-loaded
// [*ebpf.Collection]. The caller owns Close on the returned value.
//
// Before loading, the spec is checked against [bpf.ValidateMapSizes]
// — a drift between the compiled `.o` and the Go-side `MaxEntries`
// constants is treated as boot-fatal so an operator who forgot to
// run `task generate` after a size bump sees an explicit error
// instead of silently shipping with stale capacity.
func loadCollection() (*ebpf.Collection, error) {
	spec, err := bpf.LoadTelemetry()
	if err != nil {
		return nil, fmt.Errorf("load BPF spec: %w", err)
	}
	if err := bpf.ValidateMapSizes(spec); err != nil {
		return nil, fmt.Errorf("BPF spec validation: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load BPF collection: %w", err)
	}
	return coll, nil
}

// readerFromCollection wires a [BPFMapReader] over [bpf.MapTelemetry]
// inside coll. Returns an error if the map is missing — that is
// always a build-time problem, never a runtime one.
func readerFromCollection(coll *ebpf.Collection) (*BPFMapReader, error) {
	m := coll.Maps[bpf.MapTelemetry]
	if m == nil {
		return nil, fmt.Errorf("%s not present in BPF collection", bpf.MapTelemetry)
	}
	return NewBPFMapReader(m)
}

// attachIfRequested installs the telemetry programs on iface via TC
// clsact when iface is set, otherwise logs that attach was deferred
// to an out-of-band actor. The latter is the normal mode for the
// integration test (testenv attaches its own copy).
func attachIfRequested(iface string, coll *ebpf.Collection) error {
	if iface == "" {
		slog.Info("no attach interface configured; assuming external attach",
			"component", componentAgent)
		return nil
	}
	ingress := coll.Programs[bpf.ProgramIngress]
	egress := coll.Programs[bpf.ProgramEgress]
	if ingress == nil || egress == nil {
		return fmt.Errorf("%s / %s not present in BPF collection",
			bpf.ProgramIngress, bpf.ProgramEgress)
	}
	if err := AttachClsact(iface, ingress, egress); err != nil {
		return fmt.Errorf("attach clsact: %w", err)
	}
	slog.Info("attached telemetry programs", "component", componentAgent, "interface", iface)
	return nil
}

// collectionCloser adapts [*ebpf.Collection] to [io.Closer]. The
// underlying Close has no return value, so we swallow nothing.
type collectionCloser struct{ c *ebpf.Collection }

// Close releases the wrapped BPF collection. Always returns nil.
func (cc collectionCloser) Close() error {
	cc.c.Close()
	return nil
}
