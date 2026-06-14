// Package scraper drives BPF telemetry-map collection. A single
// goroutine periodically calls [MapReader.BatchLookup] to drain the
// kernel hash map, then folds each raw reading into the
// [state.GlobalState] via ApplyDelta.
//
// The [MapReader] interface lets unit tests and benchmarks substitute
// a synthetic reader without loading eBPF. The production
// implementation — a thin wrapper over cilium/ebpf BatchLookup —
// lives in the agent package alongside cmd/agent.
package scraper

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/state"
)

// MapReader is the kernel-side data source drained on every tick.
// The dst map is caller-owned and reused across ticks; implementations
// must clear it before populating to avoid stale entries leaking from
// the previous tick.
//
// PERCPU_HASH values must be aggregated across CPUs before they are
// stored in dst — the scraper expects one [bpf.FlowMetrics] per
// [bpf.FlowKey].
type MapReader interface {
	BatchLookup(dst map[bpf.FlowKey]bpf.FlowMetrics) error
}

// Evictor relieves kernel telemetry_map pressure. [Scraper.Tick] calls
// Relieve once per tick, after the drained readings have been applied
// to GlobalState — so every byte is accounted before any kernel entry
// is removed (docs/DESIGN.md §3.1). The argument is the scraper's
// just-drained buffer: its key count is the current kernel population
// and each value's LastSeenNs is the eviction key. Implementations must
// only read it. nil (the default) disables pressure relief, which is
// the case off-Linux and in unit tests that don't wire one.
type Evictor interface {
	Relieve(drained map[bpf.FlowKey]bpf.FlowMetrics)
}

// Scraper periodically drains a [MapReader] and updates a
// [state.GlobalState]. Construct one with [New], then call [Scraper.Run]
// on a long-lived goroutine.
type Scraper struct {
	reader   MapReader
	state    *state.GlobalState
	interval time.Duration

	// buf is reused across ticks so steady-state BatchLookup does no
	// allocation on the scraper side. The MapReader is expected to
	// clear and repopulate.
	buf map[bpf.FlowKey]bpf.FlowMetrics

	// evictor, when set, relieves telemetry_map pressure at the end of
	// each tick. Wired once by Bootstrap before Run starts the scrape
	// goroutine (it needs the kernel map handle); nil otherwise. Read
	// only from the single scrape goroutine, so it needs no lock.
	evictor Evictor

	errors atomic.Uint64
	lastOK atomic.Int64 // unix seconds; 0 = never succeeded
}

// New constructs a Scraper. interval must be ≥1s; callers are
// expected to have run [config.ScrapeConfig.Validate] first.
func New(reader MapReader, st *state.GlobalState, interval time.Duration) *Scraper {
	return &Scraper{
		reader:   reader,
		state:    st,
		interval: interval,
		buf:      make(map[bpf.FlowKey]bpf.FlowMetrics, initialBufCap),
	}
}

// SetEvictor wires the pressure-relief evictor. Call once before [Run]
// starts the scrape goroutine — Bootstrap does so after it has the
// kernel telemetry_map handle. Passing nil leaves pressure relief
// disabled.
func (s *Scraper) SetEvictor(e Evictor) { s.evictor = e }

// Run drives the scrape loop until ctx is cancelled. The first tick
// fires immediately so /metrics has data within one interval of
// startup; subsequent ticks fire on the configured cadence.
//
// On cancellation Run performs one final Tick before returning, so
// deltas the kernel accumulated since the last periodic tick are
// drained into state. Without it a graceful shutdown loses up to one
// scrape interval of billing data — the maps die with the TC filters
// on the next boot. Callers must keep the BPF collection open until
// Run returns.
func (s *Scraper) Run(ctx context.Context) {
	if err := s.Tick(); err != nil {
		slog.Warn("initial tick failed", "component", componentScraper, "err", err)
	}
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			if err := s.Tick(); err != nil {
				slog.Warn("final tick failed", "component", componentScraper, "err", err)
			}
			return
		case <-t.C:
			if err := s.Tick(); err != nil {
				slog.Warn("tick failed", "component", componentScraper, "err", err)
			}
		}
	}
}

// Tick performs a single drain+integrate pass. Exposed for tests and
// for the loadtest harness; the production path is [Scraper.Run].
func (s *Scraper) Tick() error {
	clear(s.buf)
	if err := s.reader.BatchLookup(s.buf); err != nil {
		s.errors.Add(1)
		return err
	}
	for k, v := range s.buf {
		s.state.ApplyDelta(k, v)
	}
	s.lastOK.Store(time.Now().Unix())
	// Relieve telemetry_map pressure after the flush: every byte in buf
	// is now in GlobalState, so evicting the oldest kernel entries loses
	// nothing (docs/DESIGN.md §3.1).
	if s.evictor != nil {
		s.evictor.Relieve(s.buf)
	}
	return nil
}

// ErrorCount returns the cumulative count of failed ticks since
// process start. Exposed via Prometheus by the metrics package.
func (s *Scraper) ErrorCount() uint64 { return s.errors.Load() }

// LastSuccessUnix returns the unix-second timestamp of the most
// recent successful tick, or 0 if none has succeeded.
func (s *Scraper) LastSuccessUnix() int64 { return s.lastOK.Load() }
