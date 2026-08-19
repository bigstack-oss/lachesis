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

// workers returns the agent's long-lived goroutines in DRAIN order.
// Two orderings are load-bearing: kafka before reconcile, so it stops
// kicking before its target drains; and scraper before wal, so the
// final tick lands its deltas before the final flush snapshots them.
//
// This list is the single source of truth for Run's goroutines — the
// goleak checks fail on any spawned outside it.
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

// startWorkers spawns every enabled worker on its OWN context, index-
// aligned with ws. The contexts deliberately do not derive from the
// caller's: a worker stops only when its row is cancelled, which is what
// makes the list's order the cancellation order. Disabled rows get a
// no-op cancel and a closed channel so drainWorkers needs no special
// case.
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

// drainWorkers stops every worker in the list's order — the ordering
// lives on the list, not here. Each row is cancelled AND awaited before
// the next, so the WAL's final flush cannot start until the scraper's
// final tick has exited. Both shutdown paths use it.
func (a *Agent) drainWorkers(ws []worker, cancels []context.CancelFunc, done []chan struct{}) {
	for i, w := range ws {
		cancels[i]()
		a.await(w.name, done[i])
	}
	slog.Info("shutdown complete", "component", componentAgent)
}

// await blocks until done closes or shutdownTimeout elapses. A timeout
// forfeits the drain ordering for every row after the stuck one — a
// stuck scraper means the WAL flush runs without the final tick's
// deltas, losing up to one flush interval. That is the design's stated
// worst case.
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
