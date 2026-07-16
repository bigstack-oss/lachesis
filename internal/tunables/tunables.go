// Package tunables holds the agent's hot-reloadable operational knobs
// behind one atomic snapshot: the runtime Manager swaps a whole
// [Values] on each successful SIGHUP reload, and every consumer reads
// the current snapshot at its own use site — a tick boundary, a
// ghost-mark, a buffer admission. Pull, not push: no consumer needs
// reload plumbing beyond holding the store, and a cadence change simply
// takes effect at the loop's next tick.
//
// None of these values are read on the packet path or per Collect row;
// the hottest reader is the scrape loop at one Load per pass, so the
// snapshot costs nothing measurable.
//
// What belongs here: pure cadences, grace windows, and bounded-buffer
// thresholds — values whose change needs no resource re-binding.
// What never belongs here: listen addresses, file paths, credentials,
// BPF map sizes, or anything that is a DESIGN §13.1 contract.
//
// The Store is a REQUIRED dependency of every consumer — never nil, no
// per-package fallback values (the Archaius/dynamic-property rule:
// the handle always exists). Defaults live in exactly one place
// (config.Defaults), hotness is declared in exactly one place
// (config.Config.Tunables), and the developer rule is one sentence:
// wiring config arrives via constructor Options and is read once;
// operational knobs are read from this store at the use site.
package tunables

import (
	"sync/atomic"
	"time"
)

// Values is one immutable snapshot of every hot-reloadable knob. The
// zero value is NOT usable — construct from config
// (config.Config.Tunables) so validated defaults always apply.
type Values struct {
	// GhostGrace is the Lingering-Ghost TTL: how long a deleted port's
	// metadata survives so dying FIN/RST packets still attribute
	// (docs/DESIGN.md §3.4). Applies to ghosts marked AFTER a change;
	// in-flight ghosts keep the deadline they were marked with.
	GhostGrace time.Duration
	// GhostSweepInterval is the ghost-sweep cadence.
	GhostSweepInterval time.Duration
	// ReconcileInterval is the periodic full-reconcile cadence — the
	// metadata-freshness ceiling when Kafka is down. The /debug
	// sync-stale badge derives from it.
	ReconcileInterval time.Duration
	// ScrapeInterval is the kernel-drain cadence. Safe to retune live:
	// the delta math is interval-agnostic by design.
	ScrapeInterval time.Duration
	// WALFlushInterval bounds the crash-loss window (§3.2).
	WALFlushInterval time.Duration
	// UnresolvedTTL is the late-binding window before buffered
	// unknown-MAC flows fold to the "unknown" tenant.
	UnresolvedTTL time.Duration
	// UnresolvedCap bounds the UnresolvedBuffer (DESIGN Contract 1 —
	// the cap's existence is a contract; only its value is tunable).
	UnresolvedCap int
	// Pressure* are the pressure-relief GC thresholds (§3.6).
	PressureHighWatermark float64
	PressureLowWatermark  float64
	PressureMaxPerPass    int
}

// Store is the shared holder. One owner (the runtime Manager) replaces
// the snapshot; any number of readers Get it lock-free.
type Store struct {
	v atomic.Pointer[Values]
}

// New returns a Store seeded with initial.
func New(initial Values) *Store {
	s := &Store{}
	s.v.Store(&initial)
	return s
}

// Get returns the current snapshot by value.
func (s *Store) Get() Values {
	return *s.v.Load()
}

// Replace swaps the whole snapshot in. Values are assumed
// pre-validated (config.Config.Validate runs before any reload apply).
func (s *Store) Replace(v Values) {
	s.v.Store(&v)
}
