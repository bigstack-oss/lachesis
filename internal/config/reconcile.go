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
}

// reconcileDefaults returns the 5-minute baseline documented as the
// no-Kafka staleness ceiling.
//
// Full rationale: docs/architecture/boot-and-recovery.md
func reconcileDefaults() ReconcileConfig {
	return ReconcileConfig{Interval: 5 * time.Minute}
}

// Validate bounds the cadence: sub-second periodic full Neutron syncs
// would hammer the API for no attribution benefit.
func (c ReconcileConfig) Validate() error {
	if c.Interval < time.Second {
		return fmt.Errorf("reconcile interval %v must be >= 1s", c.Interval)
	}
	return nil
}
