package config

import (
	"fmt"
	"time"
)

// ReconcileConfig tunes the metadata reconcile loop. Hot-reloadable on
// SIGHUP: the loop reads it through the tunables snapshot, so an
// operator can tighten the no-Kafka freshness ceiling live — e.g.
// during a Kafka outage, when the periodic pass is the only thing
// bounding how long a new port's traffic misclassifies as `miss`.
type ReconcileConfig struct {
	// Interval is the periodic full-reconcile cadence — the ceiling on
	// metadata staleness when Kafka is down (Kafka kicks reconcile
	// within seconds when healthy). The /debug sync-stale badge derives
	// from this value. Takes effect at the loop's next tick.
	Interval time.Duration `yaml:"interval"`
	// KickDebounce is how long a Kafka kick waits for the event burst
	// to go quiet before its reconcile pass starts; each further kick
	// restarts the wait, up to a fixed cap from the first kick. 0
	// disables it: every kick reconciles at once. The wait is extra
	// delay before a new port's MAC is learned, so keep it short.
	KickDebounce time.Duration `yaml:"kick_debounce"`
}

// reconcileDefaults returns the 5-minute baseline documented as the
// no-Kafka staleness ceiling.
//
// Full rationale: docs/architecture/boot-and-recovery.md
func reconcileDefaults() ReconcileConfig {
	return ReconcileConfig{Interval: 5 * time.Minute, KickDebounce: time.Second}
}

// Validate bounds the cadence: sub-second periodic full Neutron syncs
// would hammer the API for no attribution benefit.
func (c ReconcileConfig) Validate() error {
	if c.Interval < time.Second {
		return fmt.Errorf("reconcile interval %v must be >= 1s", c.Interval)
	}
	if c.KickDebounce < 0 {
		return fmt.Errorf("reconcile kick_debounce %v must be >= 0", c.KickDebounce)
	}
	return nil
}
