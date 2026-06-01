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

	"github.com/cilium/ebpf/rlimit"
)

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
	fmt.Printf("  RSS peak:        %d MiB (limit %d MiB)\n", rssPeakMB, cfg.RSSLimitMB)
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
