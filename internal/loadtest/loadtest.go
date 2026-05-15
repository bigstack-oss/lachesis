//go:build linux

// Package loadtest implements the CubeCOS network-telemetry resource
// budget test: spawn the agent as a subprocess, drive sustained TCP
// traffic through a netns + veth, and verify the agent stays inside
// configured RSS and CPU thresholds while actually observing the
// load on its BPF data plane.
//
// The cmd/loadtest binary is a flag-parsing shim over [Run]; the
// staging is [setupEnv] → [driveLoad] → [report] with an [env]
// struct bundling the agent subprocess plus its surrounding
// plumbing for orderly cleanup.
package loadtest

import (
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf/rlimit"
)

// Config bundles the inputs the harness needs. cmd/loadtest fills
// each field from a CLI flag of the same purpose.
type Config struct {
	// AgentBin is the path to the agent binary the harness will fork.
	AgentBin string
	// Duration is how long sustained traffic runs and /proc is sampled.
	Duration time.Duration
	// Workers is the number of concurrent long-lived TCP streams.
	Workers int
	// RSSLimitMB and CPULimitPct are the upper bounds the agent must
	// stay under; the harness exits non-zero if either is exceeded.
	RSSLimitMB  uint64
	CPULimitPct float64
	// HTTPAddr is where the agent's /metrics endpoint will be reachable.
	HTTPAddr string
}

// Run executes the full harness once and returns nil on PASS, an
// error on FAIL or on setup/measurement failure.
func Run(cfg Config) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	e, err := setupEnv(cfg)
	if err != nil {
		return err
	}
	defer e.Close()

	if err := waitForAgent(cfg.HTTPAddr, agentReadyTimeout); err != nil {
		return fmt.Errorf("agent did not become ready: %w", err)
	}
	fmt.Printf("loadtest: agent pid=%d, http=%s\n", e.agent.Process.Pid, cfg.HTTPAddr)

	r, err := driveLoad(cfg, e)
	if err != nil {
		return err
	}
	return report(cfg, r)
}

// agentReadyTimeout bounds how long Run will wait for the freshly
// spawned agent's /metrics endpoint to answer. Generous enough to
// cover a cold Docker layer cache, tight enough that a wedged agent
// fails the harness fast.
const agentReadyTimeout = 10 * time.Second

// minBytes is the liveness floor on the agent's observed traffic.
// Below this the BPF program likely never fired (broken attach,
// kernel path skipped clsact) and the resource budget is meaningless.
const minBytes uint64 = 1 << 20

// Result is what driveLoad measures across one window.
type Result struct {
	RSSPeakKB uint64
	CPUAvgPct float64
	BytesObs  uint64
}

// report prints the verdict and returns a non-nil error if any
// threshold was exceeded.
func report(cfg Config, r Result) error {
	rssPeakMB := r.RSSPeakKB / 1024
	pass := rssPeakMB < cfg.RSSLimitMB && r.CPUAvgPct < cfg.CPULimitPct && r.BytesObs >= minBytes
	verdict := "PASS"
	if !pass {
		verdict = "FAIL"
	}

	fmt.Printf("\nloadtest: %s\n", verdict)
	fmt.Printf("  duration:        %s\n", cfg.Duration)
	fmt.Printf("  workers:         %d\n", cfg.Workers)
	fmt.Printf("  RSS peak:        %d MB (limit %d MB)\n", rssPeakMB, cfg.RSSLimitMB)
	fmt.Printf("  CPU avg:         %.2f%% (limit %.2f%%)\n", r.CPUAvgPct, cfg.CPULimitPct)
	fmt.Printf("  bytes observed:  %s (min %s)\n", humanBytes(r.BytesObs), humanBytes(minBytes))

	if !pass {
		return errors.New("loadtest assertions failed")
	}
	return nil
}

// humanBytes formats n with a binary unit prefix (KiB/MiB/GiB/TiB)
// for terminal output. Binary rather than decimal because the
// counter is exact bytes and we already report RSS in MiB. Two
// decimal places matches the precision of the input ratio.
func humanBytes(n uint64) string {
	const (
		KiB = 1 << 10
		MiB = 1 << 20
		GiB = 1 << 30
		TiB = 1 << 40
	)
	switch {
	case n >= TiB:
		return fmt.Sprintf("%.2f TiB", float64(n)/TiB)
	case n >= GiB:
		return fmt.Sprintf("%.2f GiB", float64(n)/GiB)
	case n >= MiB:
		return fmt.Sprintf("%.2f MiB", float64(n)/MiB)
	case n >= KiB:
		return fmt.Sprintf("%.2f KiB", float64(n)/KiB)
	default:
		return fmt.Sprintf("%d B", n)
	}
}
