// Package boot tracks the agent's startup phases as a single
// monotonically advancing sequence. Sprint 5a establishes the
// machinery; Sprint 6 will add Await/Fail so consumer goroutines
// (GC, Kafka) can block on a named phase instead of relying on
// undocumented startup ordering.
//
// The phases formalise docs/DESIGN.md §9: BPF loaded, Neutron
// metadata pushed to the kernel maps, TC clsact attached, WAL
// restored. Each phase records that an externally observable
// guarantee now holds — once [Sequencer.Advance] returns, the
// previous phase's invariant is established and code paths that
// depend on it may proceed.
package boot

import (
	"fmt"
	"log/slog"
	"sync"
)

const component = "boot"

// Phase identifies a named milestone in the agent's startup
// sequence. Phases advance monotonically from [PhaseInit] through
// [PhaseStateRestored]; skipping or rewinding is a programmer error.
type Phase int

const (
	// PhaseInit is the implicit starting phase: the sequencer
	// has been constructed but no milestone has been reached.
	PhaseInit Phase = iota

	// PhaseBPFLoaded marks the BPF collection as loaded and
	// validated against the Go-side max-entries constants.
	PhaseBPFLoaded

	// PhaseMetadataReady marks the Neutron cold-start as
	// complete: the LPM trie and mac_tenant_map reflect the
	// cluster's current state and the first packet through the
	// kernel hot path will classify against a populated trie.
	PhaseMetadataReady

	// PhaseAttached marks the TC clsact qdisc and ingress/egress
	// programs as installed. Packets begin classifying after
	// this phase, never before — see docs/DESIGN.md §9.
	PhaseAttached

	// PhaseStateRestored marks the WAL load as complete:
	// GlobalState's LastEbpfRaw values are seeded so the first
	// scrape computes deltas correctly. Safe to start the
	// scraper, the WAL flush goroutine, and /metrics after this.
	PhaseStateRestored
)

// String returns the snake-case phase name, suitable for log
// attributes and (eventually) Prometheus label values.
func (p Phase) String() string {
	switch p {
	case PhaseInit:
		return "init"
	case PhaseBPFLoaded:
		return "bpf_loaded"
	case PhaseMetadataReady:
		return "metadata_ready"
	case PhaseAttached:
		return "attached"
	case PhaseStateRestored:
		return "state_restored"
	default:
		return fmt.Sprintf("phase(%d)", int(p))
	}
}

// Sequencer tracks the current boot phase. Construct with [New];
// the zero value is not usable.
type Sequencer struct {
	mu      sync.RWMutex
	current Phase
}

// New returns a sequencer at [PhaseInit]. Phase-advance events log
// to [slog.Default], which the runtime package configures via
// logging.Init before Bootstrap runs.
func New() *Sequencer {
	return &Sequencer{current: PhaseInit}
}

// Advance moves the sequencer from its current phase to next. next
// must be exactly one greater than the current phase; any other
// value (including the current phase itself) is rejected as a
// programmer error. The strict step-by-one rule keeps the phase
// list honest — if an additional phase is needed, add it to the
// enum rather than letting callers skip ahead.
func (s *Sequencer) Advance(next Phase) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if next != s.current+1 {
		return fmt.Errorf("boot: cannot advance from %s to %s (must be the next phase)", s.current, next)
	}
	s.current = next
	slog.Info("phase advanced", "component", component, "phase", next.String())
	return nil
}

// Current returns the most recently advanced phase. Safe to call
// from any goroutine.
func (s *Sequencer) Current() Phase {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}
