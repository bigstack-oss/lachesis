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
// netlink first (stop attaching while tearing down), then the ghost
// sweeper, then the kafka consumer before the reconciler (so it stops
// kicking before its target drains), then the reconciler (metadata
// maintenance, no ordering constraint with the billing drain — cancelling
// it also aborts any in-flight Neutron fetch via its ctx), then scraper
// before wal so the scraper's final tick lands its deltas in GlobalState
// before the WAL final flush snapshots them.
// The order is enforced structurally: [Agent.drainWorkers] cancels each
// row's own context and awaits its exit before moving to the next row,
// so the WAL flusher's final flush cannot start until the scraper has
// returned.
//
// This list is the single source of truth for Run's goroutines:
// [startWorkers] spawns every enabled row and both shutdown paths
// drain exactly this list. Adding a goroutine to Run means adding a
// row here — the goleak checks in the package tests fail on
// stragglers spawned outside the list.
func (a *Agent) workers() []worker {
	return []worker{
		{"netlink subscriber", a.netlinkSubscriber != nil, a.runNetlink},
		{"ghost sweeper", a.ghostSweeper != nil, a.ghostSweeper.Run},
		{"kafka consumer", a.kafkaConsumer != nil, a.kafkaConsumer.Run},
		{"reconciler", a.reconciler != nil, a.reconciler.Run},
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

// startWorkers spawns every enabled worker on its own context and
// returns one cancel func and one done channel per row, index-aligned
// with ws. The contexts deliberately do not derive from the caller's:
// a worker stops only when [Agent.drainWorkers] cancels its row, so
// the list's drain order is also the cancellation order — that is
// what guarantees the scraper's final tick completes before the WAL
// flusher sees its own cancellation. Disabled rows get a no-op cancel
// and an already-closed channel so drainWorkers can range the same
// list without special cases.
func startWorkers(ws []worker) ([]context.CancelFunc, []chan struct{}) {
	cancels := make([]context.CancelFunc, len(ws))
	done := make([]chan struct{}, len(ws))
	for i, w := range ws {
		ch := make(chan struct{})
		done[i] = ch
		if !w.enabled {
			cancels[i] = func() {}
			close(ch)
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancels[i] = cancel
		go func() {
			defer close(ch)
			w.run(ctx)
		}()
	}
	return cancels, done
}

// drainWorkers stops every [Agent.workers] goroutine in the list's
// order — the drain ordering lives on the list, not here. Each row is
// cancelled and then awaited before the next row is cancelled, so a
// later worker's shutdown work (the WAL final flush, say) cannot
// start until every earlier worker (the scraper's final tick) has
// exited. Used by both shutdown paths (caller-ctx cancel and HTTP
// server failure), so the goroutine teardown and final flush are
// identical regardless of why the agent is stopping.
func (a *Agent) drainWorkers(ws []worker, cancels []context.CancelFunc, done []chan struct{}) {
	for i, w := range ws {
		cancels[i]()
		a.await(w.name, done[i])
	}
	slog.Info("shutdown complete", "component", componentAgent)
}

// await blocks until done is closed or shutdownTimeout elapses,
// logging which goroutine stopped or timed out. drainWorkers calls it
// once per workers() row so a slow HTTP drain never leaves a goroutine
// holding a BPF map read while the caller closes the collection. A
// timeout also forfeits the drain ordering for the rows after the
// stuck one — a scraper stuck past the budget means the WAL final
// flush runs without the final tick's deltas. A WAL-flush timeout is
// the design's stated worst case: the last ≤flush_interval of
// in-memory deltas are lost.
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
