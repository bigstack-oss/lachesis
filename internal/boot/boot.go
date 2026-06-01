// Package boot tracks the agent's startup phases as a single
// monotonically advancing sequence. The phases formalise
// docs/DESIGN.md §9: BPF loaded, Neutron metadata pushed to the
// kernel maps, TC clsact attached, WAL restored. Each phase records
// that an externally observable guarantee now holds — once
// [Sequencer.Advance] returns, the previous phase's invariant is
// established and code paths that depend on it may proceed.
//
// The sequencer currently records and validates phase transitions;
// it is not yet a cross-goroutine barrier. Today the boot ordering
// is guaranteed structurally: Bootstrap advances every phase inline
// in a single goroutine and returns before Run spawns the scraper,
// WAL flush, and netlink goroutines, so none of them can observe an
// out-of-order phase. A future change may add Await/Fail backed by
// per-phase channels so consumer goroutines block on a named phase
// directly rather than relying on that straight-line execution order.
package boot

import (
	"fmt"
	"log/slog"
	"sync"
)

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
