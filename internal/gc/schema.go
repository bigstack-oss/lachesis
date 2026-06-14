// schema.go gathers package gc's package-level constants: the slog
// component label, the metric label keys and their enumerated values,
// and the lingering-ghost sweep cadence. The behavioural types — the
// GhostSweeper service (ghost.go) and the Metrics bundle (metrics.go) —
// live alongside their logic.

package gc

import "time"

// component is the value of the "component" slog attribute for logs
// originating in this package. The GC owns both the lingering-ghost
// sweep and (via the scraper) pressure-relief eviction, so both tag
// "gc" regardless of which goroutine emits them.
const component = "gc"

// ghostSweepInterval is the cadence of the lingering-ghost sweep. It
// matches the 60 s grace window (docs/DESIGN.md §3.3): an entry marked
// for deletion is swept on the first tick after its DeleteAt elapses,
// so the effective grace is between 60 s and 120 s. A fixed constant,
// not config — the value is load-bearing against the FIN/RST tail that
// the grace window exists to catch, not an operator-tunable knob.
const ghostSweepInterval = 60 * time.Second

// labelReason is the Prometheus label key naming the eviction cause on
// cubecos_gc_evictions_total.
const labelReason = "reason"

// reasonTTL and reasonPressureRelief are the two values of the
// [labelReason] label. ttl is a lingering-ghost expiry deleting a MAC
// from mac_tenant_map; pressure_relief is an oldest-flow eviction from
// telemetry_map when it crosses the configured fill high watermark
// (docs/DESIGN.md §3.1). Both are seeded at zero so the series exist
// from the first scrape.
const (
	reasonTTL            = "ttl"
	reasonPressureRelief = "pressure_relief"
)

// The pressure-relief bounds (fill watermarks and per-pass cap) are not
// constants here: they are operator-tunable and hot-reloadable, supplied
// via [PressureOptions] and swapped atomically by
// [PressureReliever.SetPressureParams]. Their defaults and the rationale
// for each live in config.GCConfig (the single source of truth for the
// default values).
