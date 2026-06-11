// worker.go defines the [worker] table — the single source of truth
// for [Agent.Run]'s long-lived goroutines — and the machinery that
// spawns and drains it. Run orchestrates; this file owns what runs,
// in what order, and how it stops.

package agent

import (
	"context"
	"log/slog"
	"time"
)

// worker is one long-lived goroutine of [Agent.Run]: a name for the
// shutdown logs, an enable condition evaluated at startup, and a
// blocking run function that must return promptly once its ctx is
// cancelled.
type worker struct {
	name    string
	enabled bool
	run     func(context.Context)
}

// workers returns the agent's long-lived goroutines in DRAIN order:
// netlink first (stop attaching while tearing down), then scraper
// before wal so the final deltas land in GlobalState before the WAL
// final flush captures them.
//
// This list is the single source of truth for Run's goroutines:
// [startWorkers] spawns every enabled row and both shutdown paths
// drain exactly this list. Adding a goroutine to Run means adding a
// row here — the goleak checks in the package tests fail on
// stragglers spawned outside the list.
func (a *Agent) workers() []worker {
	return []worker{
		{"netlink subscriber", a.netlinkSubscriber != nil, a.runNetlink},
		{"scraper", true, a.scraper.Run},
		{"wal", a.cfg.WAL.Enabled, a.walFlushLoop},
	}
}

// runNetlink runs the netlink subscriber until ctx is cancelled. A
// subscriber failure is logged rather than propagated — the agent
// keeps serving the interfaces it already attached. Only invoked
// when a subscriber is wired (the workers() enable condition).
func (a *Agent) runNetlink(ctx context.Context) {
	if err := a.netlinkSubscriber.Run(ctx); err != nil {
		slog.Error("subscriber exited", "component", componentNetlink, "err", err)
	}
}

// startWorkers spawns every enabled worker and returns one done
// channel per row, index-aligned with ws. Disabled rows get an
// already-closed channel so [Agent.drainWorkers] can range the same
// list without special cases.
func startWorkers(ctx context.Context, ws []worker) []chan struct{} {
	done := make([]chan struct{}, len(ws))
	for i, w := range ws {
		ch := make(chan struct{})
		done[i] = ch
		if !w.enabled {
			close(ch)
			continue
		}
		go func() {
			defer close(ch)
			w.run(ctx)
		}()
	}
	return done
}

// drainWorkers waits for every [Agent.workers] goroutine to exit, in
// the list's order — the drain ordering lives on the list, not here.
// Used by both shutdown paths (caller-ctx cancel and HTTP server
// failure), so the goroutine teardown and final flush are identical
// regardless of why the agent is stopping. The caller must have
// cancelled the workers' context first.
func (a *Agent) drainWorkers(ws []worker, done []chan struct{}) {
	for i, w := range ws {
		a.await(w.name, done[i])
	}
	slog.Info("shutdown complete", "component", componentAgent)
}

// await blocks until done is closed or shutdownTimeout elapses,
// logging which goroutine stopped or timed out. drainWorkers calls it
// once per workers() row so a slow HTTP drain never leaves a goroutine
// holding a BPF map read while the caller closes the collection. A
// WAL-flush timeout is the design's stated worst case: the last
// ≤flush_interval of in-memory deltas are lost.
func (a *Agent) await(name string, done <-chan struct{}) {
	select {
	case <-done:
		slog.Info(name+" stopped", "component", componentAgent)
	case <-time.After(shutdownTimeout):
		slog.Warn(name+" did not exit within shutdown budget",
			"component", componentAgent,
			"budget", shutdownTimeout)
	}
}
