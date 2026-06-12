// walflush.go owns the agent's WAL-flush slice: the periodic flush
// goroutine (a worker.go row), the snapshot writer, and the
// WALMetrics accessor. The Agent type and its construction live in
// agent.go.

package agent

import (
	"context"
	"log/slog"
	"time"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/wal"
)

// WALMetrics returns the WAL instrument bundle the agent registered
// with its prometheus.Registry. The boot path reads a.mx.wal
// directly; this accessor exists for the package's external tests,
// which record load-fallback observations on the same Metrics that
// the periodic flush contributes timings to.
func (a *Agent) WALMetrics() *wal.Metrics { return a.mx.wal }

// walFlushLoop drains [state.GlobalState] to disk on the configured
// cadence. On ctx cancellation it runs one final flush before
// returning. Its context is cancelled by [Agent.drainWorkers] only
// after the scraper has exited — its final tick already applied —
// so the final flush snapshots every delta the scraper drained
// before the SIGINT/SIGTERM. That makes a clean shutdown lossless.
func (a *Agent) walFlushLoop(ctx context.Context) {
	t := time.NewTicker(a.cfg.WAL.FlushInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			if err := a.flushWAL(); err != nil {
				slog.Warn("final flush failed", "component", componentWAL, "err", err)
				return
			}
			slog.Info("final flush ok", "component", componentWAL, "records", len(a.walRecBuf))
			return
		case <-t.C:
			if err := a.flushWAL(); err != nil {
				slog.Warn("periodic flush failed", "component", componentWAL, "err", err)
			}
		}
	}
}

// flushWAL snapshots GlobalState and writes it via [wal.Save]. The
// snapshot uses a reused buffer; steady-state flushes do not
// allocate beyond the JSON marshal that wal.Save performs. The
// copy-under-lock duration is recorded here because only this
// function sees the RLock window; marshal + write+fsync+rename
// timings are recorded inside Save.
func (a *Agent) flushWAL() error {
	copyStart := time.Now()
	a.walRecBuf = a.state.SnapshotForWAL(a.walRecBuf[:0])
	a.mx.wal.ObserveCopy(time.Since(copyStart))
	return wal.Save(a.cfg.WAL.Path, "", a.walRecBuf, a.mx.wal)
}
