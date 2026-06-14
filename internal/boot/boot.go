// Package boot tracks the agent's startup phases as a single
// monotonically advancing sequence. The phases formalise
// docs/DESIGN.md §9: BPF loaded, Neutron metadata pushed to the
// kernel maps, TC clsact attached, WAL restored. Each phase records
// that an externally observable guarantee now holds — once
// [Sequencer.Advance] returns, the previous phase's invariant is
// established and code paths that depend on it may proceed.
//
// The sequencer both records phase transitions and acts as a
// cross-goroutine barrier. Today the straight-line Bootstrap still
// advances every phase inline before Run spawns any worker, so the
// ordering would hold structurally even without the barrier; the
// barrier makes the dependency explicit instead of latent. A consumer
// goroutine calls [Sequencer.Await] to block until a named phase is
// reached — the GC's ghost sweep, for instance, awaits
// [PhaseStateRestored] so it never evicts before the WAL deltas have
// merged. If Bootstrap aborts, [Sequencer.Fail] releases every blocked
// awaiter with the failing phase's error rather than leaving them
// parked forever.
package boot

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
)

// Sequencer tracks the current boot phase and lets other goroutines
// block until a phase is reached. Construct with [New]; the zero
// value is not usable.
type Sequencer struct {
	mu      sync.Mutex
	current Phase
	// reached[p] is closed once phase p has been advanced to. Indexed
	// by Phase; reached[PhaseInit] is closed at construction.
	reached [phaseCount]chan struct{}
	// failCh is closed once, by the first [Sequencer.Fail] call, after
	// failErr is set. Awaiters select on it to wake on a boot abort.
	failCh  chan struct{}
	failErr error
}

// New returns a sequencer at [PhaseInit]. Phase-advance events log
// to [slog.Default], which the runtime package configures via
// logging.Init before Bootstrap runs.
func New() *Sequencer {
	s := &Sequencer{current: PhaseInit, failCh: make(chan struct{})}
	for i := range s.reached {
		s.reached[i] = make(chan struct{})
	}
	close(s.reached[PhaseInit])
	return s
}

// Advance moves the sequencer from its current phase to next. next
// must be exactly one greater than the current phase; any other
// value (including the current phase itself) is rejected as a
// programmer error. The strict step-by-one rule keeps the phase
// list honest — if an additional phase is needed, add it to the
// enum rather than letting callers skip ahead. Advancing to next
// closes its reached channel, releasing any [Sequencer.Await] callers
// waiting on it.
func (s *Sequencer) Advance(next Phase) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if next != s.current+1 {
		return fmt.Errorf("boot: cannot advance from %s to %s (must be the next phase)", s.current, next)
	}
	s.current = next
	close(s.reached[next])
	slog.Info("phase advanced", "component", component, "phase", next.String())
	return nil
}

// Await blocks until phase p has been reached, ctx is cancelled, or a
// [Sequencer.Fail] aborts the boot. It returns nil once p is reached
// (even if a later phase subsequently fails — p's guarantee already
// holds), ctx.Err() on cancellation, or the Fail error if the boot
// aborts before p. An out-of-range phase is a programmer error and
// returns immediately.
func (s *Sequencer) Await(ctx context.Context, p Phase) error {
	if int(p) < 0 || int(p) >= phaseCount {
		return fmt.Errorf("boot: await invalid phase %s", p)
	}
	// Prefer a reached phase over a concurrent failure: if p is already
	// established, its invariant holds regardless of a later abort.
	select {
	case <-s.reached[p]:
		return nil
	default:
	}
	select {
	case <-s.reached[p]:
		return nil
	case <-s.failCh:
		s.mu.Lock()
		err := s.failErr
		s.mu.Unlock()
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Fail records that the boot aborted at phase p with err and releases
// every goroutine blocked in [Sequencer.Await] for a not-yet-reached
// phase. Only the first call takes effect; later calls are no-ops, so
// the earliest (root) failure is the one reported. Safe to call from
// any goroutine.
func (s *Sequencer) Fail(p Phase, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.failCh:
		return
	default:
		s.failErr = fmt.Errorf("boot: aborted at phase %s: %w", p, err)
		close(s.failCh)
		slog.Error("boot aborted", "component", component, "phase", p.String(), "err", err)
	}
}

// Current returns the most recently advanced phase. Safe to call
// from any goroutine.
func (s *Sequencer) Current() Phase {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current
}
