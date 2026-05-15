//go:build linux

package agent

import (
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/config"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/logging"
)

// Bootstrap is the agent's single startup sequence: parse args,
// initialise logging, lift the memlock rlimit, load and (optionally)
// attach the BPF programs, then build the [Agent]. It returns the Agent
// plus an [io.Closer] that releases the BPF collection — call its
// Close after [Agent.Run] returns.
//
// Bootstrap is Linux-only because the BPF lifecycle is. The
// cross-platform path used by unit tests constructs [Agent] directly
// via [New] with a synthetic [scraper.MapReader].
//
// Errors are wrapped with the phase they failed in so the caller need
// not understand the internals to print a useful message.
func Bootstrap(args []string) (*Agent, io.Closer, error) {
	cfg, err := config.Load(config.Options{}, args)
	if err != nil {
		return nil, nil, err
	}
	log, err := logging.Init(cfg.Logging, os.Stderr)
	if err != nil {
		return nil, nil, fmt.Errorf("init logging: %w", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, nil, fmt.Errorf("remove memlock rlimit: %w", err)
	}

	coll, err := loadCollection()
	if err != nil {
		return nil, nil, err
	}
	closer := collectionCloser{coll}

	reader, err := readerFromCollection(coll)
	if err != nil {
		closer.Close()
		return nil, nil, err
	}

	if err := attachIfRequested(cfg.BPF.AttachInterface, coll); err != nil {
		closer.Close()
		return nil, nil, err
	}

	ag, err := New(Options{
		Config:     cfg,
		ConfigPath: config.FindConfigPath(config.Options{}, args),
		Reader:     reader,
		Log:        log,
	})
	if err != nil {
		closer.Close()
		return nil, nil, err
	}
	return ag, closer, nil
}

// loadCollection compiles the embedded BPF spec into a kernel-loaded
// [*ebpf.Collection]. The caller owns Close on the returned value.
func loadCollection() (*ebpf.Collection, error) {
	spec, err := bpf.LoadTelemetry()
	if err != nil {
		return nil, fmt.Errorf("load BPF spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load BPF collection: %w", err)
	}
	return coll, nil
}

// readerFromCollection wires a [BPFMapReader] over [bpf.MapTelemetry]
// inside coll. Returns an error if the map is missing — that is
// always a build-time problem, never a runtime one.
func readerFromCollection(coll *ebpf.Collection) (*BPFMapReader, error) {
	m := coll.Maps[bpf.MapTelemetry]
	if m == nil {
		return nil, fmt.Errorf("%s not present in BPF collection", bpf.MapTelemetry)
	}
	return NewBPFMapReader(m)
}

// attachIfRequested installs the telemetry programs on iface via TC
// clsact when iface is set, otherwise logs that attach was deferred
// to an out-of-band actor. The latter is the normal mode for the
// integration test (testenv attaches its own copy).
func attachIfRequested(iface string, coll *ebpf.Collection) error {
	if iface == "" {
		slog.Info("no attach interface configured; assuming external attach")
		return nil
	}
	ingress := coll.Programs[bpf.ProgramIngress]
	egress := coll.Programs[bpf.ProgramEgress]
	if ingress == nil || egress == nil {
		return fmt.Errorf("%s / %s not present in BPF collection",
			bpf.ProgramIngress, bpf.ProgramEgress)
	}
	if err := AttachClsact(iface, ingress, egress); err != nil {
		return fmt.Errorf("attach clsact: %w", err)
	}
	slog.Info("attached telemetry programs", "interface", iface)
	return nil
}

// collectionCloser adapts [*ebpf.Collection] to [io.Closer]. The
// underlying Close has no return value, so we swallow nothing.
type collectionCloser struct{ c *ebpf.Collection }

// Close releases the wrapped BPF collection. Always returns nil.
func (cc collectionCloser) Close() error {
	cc.c.Close()
	return nil
}
