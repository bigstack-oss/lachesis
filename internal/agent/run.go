// run.go owns the agent's lifecycle: Run starts the worker
// goroutines (worker.go) and the HTTP server, and the two shutdown
// paths drain them. The Agent type and its construction live in
// agent.go.

package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
)

// Run starts the worker goroutines listed in [Agent.workers] (netlink
// subscriber, scraper, WAL flush — as enabled) and the HTTP server.
// Blocks until ctx is cancelled or the server fails.
//
// The workers list is the single source of truth: Run spawns from it
// and both shutdown paths drain exactly it. A new long-lived
// goroutine means a new row there, nothing else.
//
// On graceful shutdown it stops accepting new HTTP requests, then
// cancels and awaits each worker in [Agent.workers] order: netlink
// first, then the scraper — which runs one final Tick on
// cancellation, draining the last kernel deltas into GlobalState —
// and only after the scraper has exited, the WAL flusher, whose
// final flush therefore snapshots those deltas. The sequencing means
// callers can safely release BPF resources once Run returns, and a
// clean shutdown loses no billing data. The same drain runs if the
// HTTP server itself fails, so a server crash never leaks the worker
// goroutines or skips the final WAL flush.
//
// TC programs are not detached on shutdown — the qdisc and filter
// outlive the process. The next agent start replaces them via
// netlink's idempotent QdiscReplace / FilterReplace. A clean detach
// + a recovery path for filters orphaned by crashes are planned.
func (a *Agent) Run(ctx context.Context) error {
	// runCtx bounds the SIGHUP reload goroutine to this Run call. The
	// workers do NOT run on it — startWorkers gives each its own
	// context so drainWorkers can cancel them one at a time in drain
	// order; a shared context cancelled by the caller would stop the
	// scraper and the WAL flusher simultaneously, letting the final
	// flush race the scraper's final tick.
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// SIGHUP reload lives on runCtx, not ctx: on the server-error exit
	// path the caller never cancels, and a ctx-bound reload goroutine
	// would outlive Run forever (the package's goleak tests catch this).
	a.runtime.InstallSIGHUP(runCtx)

	workers := a.workers()
	cancels, done := startWorkers(workers)

	srvErr := make(chan error, 1)
	go func() {
		if err := a.server.Serve(a.listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			srvErr <- err
			return
		}
		srvErr <- nil
	}()

	slog.Info("serving",
		"component", componentAgent,
		"addr", a.Addr(),
		"scrape_interval", a.cfg.Scrape.Interval,
		"wal_enabled", a.cfg.WAL.Enabled,
	)

	select {
	case <-ctx.Done():
		return a.shutdown(srvErr, workers, cancels, done)
	case err := <-srvErr:
		// The HTTP server failed on its own (the listener died, say).
		// srvErr is already drained, so we can't route through the full
		// shutdown (which reads it). Drain the workers directly — the
		// same cancel-and-await sequence, including the WAL final flush
		// — so a server crash doesn't leak goroutines or lose the last
		// deltas. The deferred cancel stops the SIGHUP goroutine.
		slog.Info("shutdown initiated by server error", "component", componentAgent)
		a.drainWorkers(workers, cancels, done)
		return err
	}
}

// shutdown drains the HTTP server, then cancels and awaits the
// workers one row at a time via [Agent.drainWorkers]. Returns an
// error only if HTTP shutdown itself fails — scraper / WAL timeouts
// are logged but not promoted to errors, because by then the agent's
// job is done.
//
// Drain order matters: the scraper is cancelled and awaited before
// the WAL flusher, so its final tick's deltas land in state before
// the final flush snapshots them — the order is encoded once, in
// [Agent.workers], and enforced by drainWorkers' cancel-then-await
// sequencing. The drain is deferred so it runs even on an HTTP
// shutdown error (otherwise the BPF-collection close in main could
// race the kernel-map read, and the latest in-memory state could be
// lost).
func (a *Agent) shutdown(srvErr <-chan error, ws []worker, cancels []context.CancelFunc, done []chan struct{}) error {
	slog.Info("shutdown initiated", "component", componentAgent)
	defer a.drainWorkers(ws, cancels, done)

	httpCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := a.server.Shutdown(httpCtx); err != nil {
		return fmt.Errorf("agent: http shutdown: %w", err)
	}
	<-srvErr
	slog.Info("http server stopped", "component", componentAgent)
	return nil
}
