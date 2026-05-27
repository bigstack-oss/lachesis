//go:build linux

package agent

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/boot"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/config"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/logging"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/wal"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/zombie"
)

const componentZombie = "zombie"

// Bootstrap is the agent's single startup sequence: parse args,
// initialise logging, lift the memlock rlimit, load BPF, populate
// the kernel maps from Neutron, attach TC, then build the [Agent].
// It returns the Agent plus an [io.Closer] that releases the BPF
// collection — call its Close after [Agent.Run] returns.
//
// Phases (see [boot.Phase] and docs/DESIGN.md §9):
//
//  1. [boot.PhaseBPFLoaded]      — collection loaded + map-size validated
//  2. [boot.PhaseMetadataReady]  — Neutron cold-start populated the
//     LPM trie and mac_tenant_map
//  3. [boot.PhaseAttached]       — TC clsact attached; packets begin
//     classifying against the populated trie
//  4. [boot.PhaseStateRestored]  — WAL load complete; GlobalState
//     seeded so the first scrape computes deltas correctly
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

	seq := boot.New()

	zombiesCleaned, zerr := zombie.Hunt()
	switch {
	case zerr != nil:
		slog.Warn("hunt encountered errors; continuing with partial cleanup",
			"component", componentZombie, "cleaned", zombiesCleaned, "err", zerr)
	case zombiesCleaned > 0:
		slog.Info("removed orphan filters from a previous run",
			"component", componentZombie, "cleaned", zombiesCleaned)
	}

	coll, err := loadCollection()
	if err != nil {
		return nil, nil, err
	}
	closer := collectionCloser{coll}
	if err := seq.Advance(boot.PhaseBPFLoaded); err != nil {
		closer.Close()
		return nil, nil, err
	}

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
	ag.ZombieMetrics().RecordCleaned(zombiesCleaned)

	if err := coldStartNeutron(ctx, cfg.Neutron, ag, coll); err != nil {
		closer.Close()
		return nil, nil, fmt.Errorf("neutron cold-start: %w", err)
	}
	if err := seq.Advance(boot.PhaseMetadataReady); err != nil {
		closer.Close()
		return nil, nil, err
	}

	if err := attachIfRequested(cfg.BPF.AttachInterface, coll); err != nil {
		closer.Close()
		return nil, nil, err
	}
	if err := seq.Advance(boot.PhaseAttached); err != nil {
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
	if err := seq.Advance(boot.PhaseStateRestored); err != nil {
		closer.Close()
		return nil, nil, err
	}

	return ag, closer, nil
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
