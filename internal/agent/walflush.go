// walflush.go owns the agent's WAL slice: the boot-time restore, the
// periodic flush goroutine (a worker.go row), the snapshot writer,
// the build identity stamped into each snapshot, and the WALMetrics
// accessor. The Agent type and its construction live in agent.go.

package agent

import (
	"context"
	"errors"
	"log/slog"
	"runtime/debug"
	"time"

	"github.com/bigstack-oss/lachesis/internal/config"
	"github.com/bigstack-oss/lachesis/internal/wal"
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
	cur := a.tun.Get().WALFlushInterval
	t := time.NewTicker(cur)
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
			if next := a.tun.Get().WALFlushInterval; next != cur {
				t.Reset(next)
				cur = next
			}
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
	a.walRecBuf, a.walSettledBuf = a.state.SnapshotForWAL(a.walRecBuf[:0], a.walSettledBuf[:0])
	a.mx.wal.ObserveCopy(time.Since(copyStart))
	return wal.Save(a.cfg.WAL.Path, a.buildID, a.walRecBuf, a.walSettledBuf, a.mx.wal)
}

// restoreFromWAL reads the on-disk snapshot (if enabled) and seeds
// the agent's GlobalState. Runs BEFORE the scraper goroutine starts,
// so the first ApplyDelta computes deltas against restored
// LastEbpfRaw values rather than re-baselining.
//
// Load failures split into two classes (docs/DESIGN.md §3.2):
//
//   - A snapshot from a newer build ([wal.ErrSchemaNewer]) is
//     returned so boot refuses to start. Starting anyway would let
//     the flush rotation destroy the only forward snapshot within
//     two flushes.
//   - Anything else means both files are unreadable: the agent
//     starts empty, but the primary is quarantined first so the
//     flush rotation cannot destroy the evidence.
//
// Load fallbacks (bak or empty) are recorded on the agent's WAL
// metrics so an operator can grep lachesis_wal_load_fallback_total
// to spot a corrupt primary or a first-boot.
func restoreFromWAL(ag *Agent, cfg config.WALConfig) error {
	if !cfg.Enabled {
		slog.Info("disabled; starting with empty state", "component", componentWAL)
		return nil
	}
	res, err := wal.Load(cfg.Path)
	switch {
	case errors.Is(err, wal.ErrSchemaNewer):
		return err
	case err != nil:
		slog.Warn("restore failed; agent will start with empty state",
			"component", componentWAL, "err", err)
		quarantineWAL(cfg.Path)
		return nil
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
		ag.mx.wal.RecordLoadFallback(wal.LoadFallbackBak)
		quarantineWAL(cfg.Path)
	case wal.LoadEmpty:
		slog.Info("no prior snapshot; starting empty",
			"component", componentWAL,
			"path", cfg.Path)
		ag.mx.wal.RecordLoadFallback(wal.LoadFallbackEmpty)
	}
	if len(res.Records) > 0 {
		ag.SeedState(res.Records)
	}
	if len(res.Settled) > 0 {
		ag.SeedSettled(res.Settled)
	}
	return nil
}

// quarantineWAL moves the unreadable primary snapshot out of the
// flush rotation's reach via [wal.Quarantine]. Only the primary is
// quarantined: when the .bak is the unreadable file, it is an older
// generation of the same data superseded by whatever the primary
// held, so a second quarantine slot would add bookkeeping without
// preserving anything new. Failures are logged, not returned — the
// agent can still start empty; only the forensic copy is at risk.
func quarantineWAL(path string) {
	moved, err := wal.Quarantine(path)
	switch {
	case err != nil:
		slog.Warn("quarantine failed; the next flush may destroy the unreadable snapshot",
			"component", componentWAL, "path", path, "err", err)
	case moved:
		slog.Warn("unreadable snapshot quarantined",
			"component", componentWAL, "path", path+wal.QuarantineSuffix)
	}
}

// agentBuildID identifies the running build for the WAL envelope's
// agent_build field (informational; correlates a snapshot with build
// logs during incident forensics). The build embeds no ldflags
// version variable, so the VCS revision recorded by the Go toolchain
// is the identity. Binaries built without VCS stamping — including
// test binaries — yield "".
func agentBuildID() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	return buildIDFrom(bi)
}

// buildIDFrom extracts the short (12-character, matching git's
// abbreviated object names) vcs.revision from bi. Split from
// agentBuildID so the extraction is testable against a synthetic
// [debug.BuildInfo].
func buildIDFrom(bi *debug.BuildInfo) string {
	for _, s := range bi.Settings {
		if s.Key == "vcs.revision" {
			if len(s.Value) > 12 {
				return s.Value[:12]
			}
			return s.Value
		}
	}
	return ""
}
