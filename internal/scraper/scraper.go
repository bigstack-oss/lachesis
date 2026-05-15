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
		buf:      make(map[bpf.FlowKey]bpf.FlowMetrics, 1024),
	}
}

// Run drives the scrape loop until ctx is cancelled. The first tick
// fires immediately so /metrics has data within one interval of
// startup; subsequent ticks fire on the configured cadence.
func (s *Scraper) Run(ctx context.Context) {
	if err := s.Tick(); err != nil {
		slog.Warn("scraper: initial tick failed", "err", err)
	}
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.Tick(); err != nil {
				slog.Warn("scraper: tick failed", "err", err)
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
	return nil
}

// ErrorCount returns the cumulative count of failed ticks since
// process start. Exposed via Prometheus by the metrics package.
func (s *Scraper) ErrorCount() uint64 { return s.errors.Load() }

// LastSuccessUnix returns the unix-second timestamp of the most
// recent successful tick, or 0 if none has succeeded.
func (s *Scraper) LastSuccessUnix() int64 { return s.lastOK.Load() }
