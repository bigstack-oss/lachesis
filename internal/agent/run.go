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
// On graceful shutdown it stops accepting new HTTP requests, drains
// in-flight scrapes, waits for the scraper goroutine to finish its
// current Tick (so callers can safely release BPF resources without
// racing the kernel-map read), then lets the WAL flush goroutine
// run its final flush. The same drain runs if the HTTP server itself
// fails, so a server crash never leaks the worker goroutines or skips
// the final WAL flush.
//
// TC programs are not detached on shutdown — the qdisc and filter
// outlive the process. The next agent start replaces them via
// netlink's idempotent QdiscReplace / FilterReplace. A clean detach
// + a recovery path for filters orphaned by crashes are planned.
func (a *Agent) Run(ctx context.Context) error {
	// runCtx derives from the caller's ctx so that an HTTP server
	// failure can tear down the scraper, WAL, and netlink goroutines
	// the same way a caller cancellation does. Without it, the srvErr
	// exit path below would return while those goroutines run on against
	// a live context — leaking them and skipping the WAL final flush.
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// SIGHUP reload lives on runCtx, not ctx: on the server-error exit
	// path the caller never cancels, and a ctx-bound reload goroutine
	// would outlive Run forever (the package's goleak tests catch this).
	a.runtime.InstallSIGHUP(runCtx)

	workers := a.workers()
	done := startWorkers(runCtx, workers)

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
		return a.shutdown(srvErr, workers, done)
	case err := <-srvErr:
		// The HTTP server failed on its own (the listener died, say).
		// srvErr is already drained, so we can't route through the full
		// shutdown (which reads it). Cancel the workers and drain them
		// directly — including the WAL final flush — so a server crash
		// doesn't leak goroutines or lose the last deltas.
		slog.Info("shutdown initiated by server error", "component", componentAgent)
		cancel()
		a.drainWorkers(workers, done)
		return err
	}
}

// shutdown drains the HTTP server, awaits the scraper, then awaits
// the WAL flush goroutine's final flush. Returns an error only if
// HTTP shutdown itself fails — scraper / WAL timeouts are logged
// but not promoted to errors, because by then the agent's job is
// done.
//
// Drain order matters: scraper drains first so the latest deltas
// land in state, then the WAL final flush captures them — the order
// is encoded once, in [Agent.workers]. The drain is deferred so it
// runs even on an HTTP shutdown error (otherwise the BPF-collection
// close in main could race the kernel-map read, and the latest
// in-memory state could be lost).
func (a *Agent) shutdown(srvErr <-chan error, ws []worker, done []chan struct{}) error {
	slog.Info("shutdown initiated", "component", componentAgent)
	defer a.drainWorkers(ws, done)

	httpCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := a.server.Shutdown(httpCtx); err != nil {
		return fmt.Errorf("agent: http shutdown: %w", err)
	}
	<-srvErr
	slog.Info("http server stopped", "component", componentAgent)
	return nil
}
