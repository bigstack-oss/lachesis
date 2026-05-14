//go:build linux

// Command agent runs the CubeCOS network-telemetry data-plane reader.
//
// On startup it loads the embedded BPF collection, optionally attaches
// the ingress/egress programs to a host interface via TC clsact, then
// spins up the scraper goroutine and an HTTP server serving /metrics
// and /debug. SIGHUP triggers a config reload via the [runtime.Manager].
//
// Configuration is layered as described in [config.LoadWith]:
// defaults → YAML file → env vars → CLI flags.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/agent"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/config"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/logging"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "agent: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(os.Args[1:])
	if err != nil {
		return err
	}
	log, err := logging.Init(cfg.Logging, os.Stderr)
	if err != nil {
		return fmt.Errorf("init logging: %w", err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock rlimit: %w", err)
	}

	spec, err := bpf.LoadTelemetry()
	if err != nil {
		return fmt.Errorf("load BPF spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load BPF collection: %w", err)
	}
	defer coll.Close()

	telemetryMap := coll.Maps["telemetry_map"]
	if telemetryMap == nil {
		return errors.New("telemetry_map not present in BPF collection")
	}
	reader, err := agent.NewBPFMapReader(telemetryMap)
	if err != nil {
		return fmt.Errorf("build map reader: %w", err)
	}

	if iface := cfg.BPF.AttachInterface; iface != "" {
		ingress := coll.Programs["tc_telemetry_in"]
		egress := coll.Programs["tc_telemetry_out"]
		if ingress == nil || egress == nil {
			return errors.New("tc_telemetry_in / tc_telemetry_out not present in BPF collection")
		}
		if err := agent.AttachClsact(iface, ingress, egress); err != nil {
			return fmt.Errorf("attach clsact: %w", err)
		}
		slog.Info("attached telemetry programs", "interface", iface)
	} else {
		slog.Info("no attach interface configured; assuming external attach")
	}

	app, err := agent.New(agent.Options{
		Config:     cfg,
		ConfigPath: config.FindConfigPath(os.Args[1:], config.Options{}),
		Reader:     reader,
		Log:        log,
	})
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	return app.Run(ctx)
}
