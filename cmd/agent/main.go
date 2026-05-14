//go:build linux

// Command agent runs the CubeCOS network-telemetry data-plane reader.
//
// On startup it loads the embedded BPF collection, optionally attaches
// the ingress/egress programs to a host interface via TC clsact, then
// spins up the scraper goroutine and an HTTP server serving /metrics
// and /debug. SIGHUP triggers a config reload via the [runtime.Manager].
//
// Configuration is layered as described in [config.LoadWith]:
// defaults → YAML file → env vars → CLI flags. All wiring lives in
// [agent.Bootstrap]; main is signal handling and exit codes.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/agent"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	app, closer, err := agent.Bootstrap(os.Args[1:])
	if err != nil {
		fail(err)
	}
	defer closer.Close()

	if err := app.Run(ctx); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "agent: %v\n", err)
	os.Exit(1)
}
