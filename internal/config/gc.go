package config

import (
	"fmt"
	"time"
)

// GCConfig groups the tunables for pressure-relief eviction of the
// kernel telemetry_map. All three are hot-reloadable on SIGHUP: the GC
// reads them through an atomic snapshot, so an operator can retune
// eviction without an agent restart (a restart briefly stops counting
// and re-derives the kernel maps).
//
// Kernel maps: docs/architecture/data-structures.md#kernel-side-bpf-maps
//
// They are deliberately YAML-only — no env var or CLI flag. Env and
// flags are resolved once at boot and cannot hot-reload, so binding
// these there would imply a liveness those sources can't deliver.
type GCConfig struct {
	// PressureHighWatermark is the telemetry_map fill ratio that starts
	// a relief cycle. Must be < 1.0: relief has to begin before the map
	// is full, because a full PERCPU_HASH makes the kernel drop counter
	// updates on its own — the silent byte loss pressure-relief exists
	// to prevent.
	PressureHighWatermark float64 `yaml:"pressure_high_watermark"`
	// PressureLowWatermark is the fill ratio that ends a relief cycle.
	// Eviction continues every scrape until fill falls below it, so the
	// map settles near this mark rather than oscillating around the high
	// one. Must satisfy 0 < low < high.
	PressureLowWatermark float64 `yaml:"pressure_low_watermark"`
	// PressureMaxPerPass caps how many entries a single scrape evicts.
	// It bounds the worst-case per-scrape stall — roughly 50 µs per
	// kernel delete, so the default 1000 is about 50 ms — which is why
	// draining from the high watermark down to the low one takes a few
	// successive scrapes rather than one long pause. Raising it drains
	// faster at the cost of a longer stall on each scrape that evicts.
	PressureMaxPerPass int `yaml:"pressure_max_per_pass"`
	// GhostGrace is the Lingering-Ghost TTL: how long a deleted port's
	// metadata survives so dying FIN/RST packets
	// still attribute. Shorter = less MAC-reuse exposure; longer =
	// better teardown-tail attribution. Hot-reloadable; applies to
	// ghosts marked after the change.
	GhostGrace time.Duration `yaml:"ghost_grace"`
	// GhostSweepInterval is the ghost-sweep cadence. Hot-reloadable
	// (takes effect at the sweeper's next tick).
	GhostSweepInterval time.Duration `yaml:"ghost_sweep_interval"`
}

// gcDefaults returns the documented pressure-relief baseline: trigger
// at 80% fill, drain to the 75% floor, 1000 entries per pass (≈50 ms
// stall). This package is the single source of truth for those default
// values.
//
// Kernel maps: docs/architecture/data-structures.md#kernel-side-bpf-maps
func gcDefaults() GCConfig {
	return GCConfig{
		PressureHighWatermark: 0.80,
		PressureLowWatermark:  0.75,
		PressureMaxPerPass:    1000,
		GhostGrace:            60 * time.Second,
		GhostSweepInterval:    60 * time.Second,
	}
}

// Validate enforces the ordering the eviction hysteresis depends on and
// the bound that keeps relief from ever disabling itself. A reload that
// fails here is rejected and the running config is kept (see
// runtime.Manager.Reload), so a bad edit can never silently switch
// pressure relief off.
func (c GCConfig) Validate() error {
	if c.PressureHighWatermark <= 0 || c.PressureHighWatermark >= 1 {
		return fmt.Errorf("pressure_high_watermark %v must be in (0, 1) — at 1.0 the map fills and the kernel drops counters", c.PressureHighWatermark)
	}
	if c.PressureLowWatermark <= 0 || c.PressureLowWatermark >= c.PressureHighWatermark {
		return fmt.Errorf("pressure_low_watermark %v must be in (0, pressure_high_watermark=%v)", c.PressureLowWatermark, c.PressureHighWatermark)
	}
	if c.GhostGrace <= 0 {
		return fmt.Errorf("ghost_grace %v must be > 0 — zero grace kills dying-flow attribution (docs/architecture/data-structures.md#map-lifecycle-invariants)", c.GhostGrace)
	}
	if c.GhostSweepInterval <= 0 {
		return fmt.Errorf("ghost_sweep_interval %v must be > 0", c.GhostSweepInterval)
	}
	if c.PressureMaxPerPass < 1 {
		return fmt.Errorf("pressure_max_per_pass %d must be >= 1", c.PressureMaxPerPass)
	}
	return nil
}
