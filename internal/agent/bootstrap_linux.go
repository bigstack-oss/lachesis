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
	cnetlink "github.com/bigstack-oss/cube-cos-network-telemetry/internal/netlink"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/tcattach"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/wal"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/zombie"
)

// Bootstrap runs the agent's startup sequence and returns a ready
// [Agent] plus an [io.Closer] that releases the BPF collection — call
// its Close after [Agent.Run] returns.
//
// The body is a flat, ordered list of named steps executed by
// [bootstrapper.run]; each step does one part of the sequence and
// advances the [boot.Sequencer] to the phase it establishes. Read the
// list here for the order; read the individual step methods for what
// each one guarantees.
//
// Phases (see [boot.Phase] and docs/DESIGN.md §9):
//
//  1. [boot.PhaseBPFLoaded]      — collection loaded + map-size validated
//  2. [boot.PhaseMetadataReady]  — Neutron cold-start populated the
//     LPM trie and mac_tenant_map
//  3. [boot.PhaseAttached]       — netlink subscriber wired; the TC
//     attach itself happens dynamically once [Agent.Run] starts it
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
// Errors are wrapped with the step they failed in so the caller need
// not understand the internals to print a useful message.
func Bootstrap(ctx context.Context, args []string) (*Agent, io.Closer, error) {
	b := &bootstrapper{ctx: ctx, args: args, seq: boot.New()}
	return b.run([]step{
		{"prepare process", b.prepareProcess},
		{"hunt zombies", b.huntZombies},
		{"load BPF collection", b.loadBPF},
		{"build agent", b.buildAgent},
		{"cold-start Neutron", b.coldStart},
		{"subscribe netlink", b.subscribeNetlink},
		{"prepare WAL directory", b.prepareWALDir},
		{"restore WAL", b.restoreWAL},
	})
}

// step is one named entry in the [Bootstrap] sequence. name labels a
// failure; fn does the work and advances the [boot.Sequencer] when it
// establishes a phase.
type step struct {
	name string
	fn   func() error
}

// bootstrapper carries the state shared across the [Bootstrap] steps.
// Each step reads what earlier steps stored and writes what later
// steps need; the step list in [Bootstrap] is the authoritative
// order. It exists so every step can be a uniform func() error and
// Bootstrap can stay a flat list rather than a thread of locals.
type bootstrapper struct {
	ctx  context.Context
	args []string

	seq  *boot.Sequencer
	cfg  config.Config
	log  *logging.Handle
	coll *ebpf.Collection
	ag   *Agent

	zombiesCleaned int
}

// run executes steps in order, stopping at the first failure. On any
// error it releases the BPF collection — a no-op until [loadBPF]
// stores one, so an early failure is safe — and wraps the error with
// the failing step's name. On success it hands the live collection to
// the caller as an [io.Closer] to close after [Agent.Run] returns.
func (b *bootstrapper) run(steps []step) (*Agent, io.Closer, error) {
	for _, s := range steps {
		if err := s.fn(); err != nil {
			b.closeCollection()
			return nil, nil, fmt.Errorf("bootstrap: %s: %w", s.name, err)
		}
	}
	return b.ag, collectionCloser{b.coll}, nil
}

// prepareProcess parses configuration, initialises logging, and lifts
// the memlock rlimit so the kernel will accept the BPF maps. These are
// process-wide prerequisites, independent of the agent's data plane.
func (b *bootstrapper) prepareProcess() error {
	cfg, err := config.Load(config.Options{}, b.args)
	if err != nil {
		return err
	}
	log, err := logging.Init(cfg.Logging, os.Stderr)
	if err != nil {
		return fmt.Errorf("init logging: %w", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock rlimit: %w", err)
	}
	b.cfg, b.log = cfg, log
	return nil
}

// huntZombies removes TC filters orphaned by a previous crash, before
// any program is loaded (docs/DESIGN.md §9 step 1). Hunt errors are
// non-fatal — a partial cleanup still leaves a working agent — so the
// count is stashed for [buildAgent] to record once the metrics exist.
func (b *bootstrapper) huntZombies() error {
	cleaned, err := zombie.Hunt()
	switch {
	case err != nil:
		slog.Warn("hunt encountered errors; continuing with partial cleanup",
			"component", componentZombie, "cleaned", cleaned, "err", err)
	case cleaned > 0:
		slog.Info("removed orphan filters from a previous run",
			"component", componentZombie, "cleaned", cleaned)
	}
	b.zombiesCleaned = cleaned
	return nil
}

// loadBPF loads and validates the embedded BPF collection, then
// advances to [boot.PhaseBPFLoaded].
func (b *bootstrapper) loadBPF() error {
	coll, err := loadCollection()
	if err != nil {
		return err
	}
	b.coll = coll
	return b.seq.Advance(boot.PhaseBPFLoaded)
}

// buildAgent wires the map reader over the loaded collection and
// constructs the [Agent], then records the orphan-filter count
// [huntZombies] found on the agent's zombie metrics.
func (b *bootstrapper) buildAgent() error {
	reader, err := readerFromCollection(b.coll)
	if err != nil {
		return err
	}
	ag, err := New(Options{
		Config:     b.cfg,
		ConfigPath: config.FindConfigPath(config.Options{}, b.args),
		Reader:     reader,
		Log:        b.log,
	})
	if err != nil {
		return err
	}
	ag.mx.zombie.RecordCleaned(b.zombiesCleaned)
	b.ag = ag
	return nil
}

// coldStart fetches the Neutron snapshot and pushes it into the kernel
// maps, then advances to [boot.PhaseMetadataReady]. Runs before attach
// so the first packet classifies against a populated trie.
func (b *bootstrapper) coldStart() error {
	if err := coldStartNeutron(b.ctx, b.cfg.Neutron, b.ag, b.coll); err != nil {
		return err
	}
	return b.seq.Advance(boot.PhaseMetadataReady)
}

// subscribeNetlink builds the RTM_NEWLINK/DELLINK subscriber (when an
// attach allowlist is configured) and hands it to the agent, then
// advances to [boot.PhaseAttached]. The subscriber is only started
// later by [Agent.Run]; this step just wires it.
func (b *bootstrapper) subscribeNetlink() error {
	sub, err := buildNetlinkSubscriber(b.ag, b.cfg.BPF, b.coll)
	if err != nil {
		return err
	}
	if sub != nil {
		b.ag.netlinkSubscriber = sub
	}
	return b.seq.Advance(boot.PhaseAttached)
}

// prepareWALDir creates the WAL directory if missing and probes it
// for writability via [wal.EnsureDir]. Boot-fatal — unlike a restore
// failure, an unusable directory means every future flush would fail
// and the agent would run with zero crash durability while looking
// healthy. Runs before [bootstrapper.restoreWAL] so Load never
// mistakes a missing directory for a first boot.
func (b *bootstrapper) prepareWALDir() error {
	if !b.cfg.WAL.Enabled {
		return nil
	}
	return wal.EnsureDir(b.cfg.WAL.Path)
}

// restoreWAL seeds GlobalState from the on-disk snapshot and advances
// to [boot.PhaseStateRestored]. Most restore failures are handled
// inside restoreFromWAL (warn, quarantine the unreadable primary,
// start empty); the one fatal class — a snapshot written by a newer
// build — propagates here and aborts the boot (docs/DESIGN.md §3.2
// migration policy).
func (b *bootstrapper) restoreWAL() error {
	if err := restoreFromWAL(b.ag, b.cfg.WAL); err != nil {
		return err
	}
	return b.seq.Advance(boot.PhaseStateRestored)
}

// closeCollection releases the BPF collection if [loadBPF] stored one.
// Safe before loadBPF runs (coll is nil) and on any error path.
func (b *bootstrapper) closeCollection() {
	if b.coll != nil {
		b.coll.Close()
	}
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

// buildNetlinkSubscriber constructs the RTM_NEWLINK/DELLINK
// subscriber when the BPFConfig allowlist is non-empty. Returns a
// nil Subscriber (no error) when both lists are empty — that means
// the operator opted out of dynamic discovery and attach is managed
// out-of-band (e.g. the integration tests attach their own filters).
func buildNetlinkSubscriber(ag *Agent, bpfCfg config.BPFConfig, coll *ebpf.Collection) (cnetlink.Subscriber, error) {
	if len(bpfCfg.AttachPrefixes) == 0 && len(bpfCfg.AttachInterfaces) == 0 {
		slog.Info("no allowlist configured; subscriber disabled",
			"component", componentNetlink)
		return nil, nil
	}
	ingress := coll.Programs[bpf.ProgramIngress]
	egress := coll.Programs[bpf.ProgramEgress]
	if ingress == nil || egress == nil {
		return nil, fmt.Errorf("netlink subscriber: %s / %s not present in BPF collection",
			bpf.ProgramIngress, bpf.ProgramEgress)
	}
	sub, err := cnetlink.New(cnetlink.Options{
		Attacher: tcattach.NewLinkAttacher(ingress, egress),
		Prefixes: bpfCfg.AttachPrefixes,
		Explicit: bpfCfg.AttachInterfaces,
		Registry: ag.mx.registry,
		Metrics:  ag.mx.netlink,
	})
	if err != nil {
		return nil, fmt.Errorf("netlink subscriber: %w", err)
	}
	return sub, nil
}

// collectionCloser adapts [*ebpf.Collection] to [io.Closer]. The
// underlying Close has no return value, so we swallow nothing.
type collectionCloser struct{ c *ebpf.Collection }

// Close releases the wrapped BPF collection. Always returns nil.
func (cc collectionCloser) Close() error {
	cc.c.Close()
	return nil
}
