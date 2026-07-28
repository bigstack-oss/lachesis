package scenariotest

import "time"

// Harness-wide wait budgets. These are shared by more than one phase —
// the attach gate is used by both realize and the boot/attach steps,
// the SSH-ready gate by both drive and the in-guest steps — so they
// live with the core rather than being duplicated per package or
// reached across a package boundary. Budgets used by exactly one phase
// stay in that phase.
const (
	// DefaultAttachTimeout bounds how long a caller waits for the agents
	// to report the expected number of attached taps.
	DefaultAttachTimeout = 90 * time.Second
	// AttachPollInterval is how often the attach gate re-scrapes.
	AttachPollInterval = 2 * time.Second
	// ServerActiveTimeout bounds one server's boot wait. Without it a
	// server stuck in BUILD would hang the run indefinitely.
	ServerActiveTimeout = 5 * time.Minute
	// DefaultAgentReadyTimeout bounds an agent restart's wait for the
	// agent to answer /metrics and re-attach its taps.
	DefaultAgentReadyTimeout = 90 * time.Second
	// ReadyPollInterval is the pause between SSH-readiness probes.
	ReadyPollInterval = 5 * time.Second
	// DefaultReadyTimeout bounds how long a caller waits for a VM to
	// answer SSH. Nova ACTIVE races cloud-init by tens of seconds, so
	// anything that execs in a guest right after boot must gate on this.
	DefaultReadyTimeout = 120 * time.Second
)
