//go:build linux

// schema.go gathers package loadtest's data types and tuning constants:
// the harness Config and Result, the agent-readiness and worker timeouts,
// the traffic chunk size, the liveness floor, and the clock-tick constant.
// All loadtest sources are //go:build linux, so this file carries the tag
// too. The harness staging (Run, setupEnv, driveLoad, report, /proc
// sampling) lives in the sibling files.

package loadtest

import "time"

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

// Result is what driveLoad measures across one window.
type Result struct {
	RSSPeakKB uint64
	CPUAvgPct float64
	BytesObs  uint64
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

// agentTermGrace is how long stopAgent waits between SIGTERM and
// SIGKILL. The agent's own shutdown budget is bounded by its
// internal HTTP + scraper drain (~5s in production); this gives it
// a bit longer to exit cleanly before we kill the process group.
const agentTermGrace = 3 * time.Second

// agentReadyPoll is the inter-poll sleep waitForAgent uses while
// the /metrics endpoint is still warming up. Short enough that the
// harness's effective startup latency is sub-second.
const agentReadyPoll = 100 * time.Millisecond

// workerChunkSize is the per-write payload for each TCP worker.
// Large enough that the kernel can push it as a single packet on a
// loopback or veth path, small enough that we cycle through the
// write loop frequently and surface backpressure quickly.
const workerChunkSize = 64 * 1024

// workerDialTimeout bounds how long a worker waits to establish its
// long-lived TCP connection to the sink. The sink is in-process so
// healthy dials complete instantly; this is a hung-stack guard.
const workerDialTimeout = 5 * time.Second

// clkTck is the sysconf(_SC_CLK_TCK) value: jiffies per second.
// Hard-coded to 100, which is the kernel default and what every
// glibc on every distribution we ship to reports. If we ever land
// on a kernel where CONFIG_HZ ≠ 100, this becomes a cgo call.
const clkTck = 100
