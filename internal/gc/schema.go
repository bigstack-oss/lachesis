// schema.go gathers package gc's package-level constants: the slog
// component label, the metric label keys and their enumerated values,
// and the lingering-ghost sweep cadence. The behavioural types — the
// GhostSweeper service (ghost.go) and the Metrics bundle (metrics.go) —
// live alongside their logic.

package gc

// component is the value of the "component" slog attribute for logs
// originating in this package. The GC owns both the lingering-ghost
// sweep and (via the scraper) pressure-relief eviction, so both tag
// "gc" regardless of which goroutine emits them.
const component = "gc"

// labelReason is the Prometheus label key naming the eviction cause on
// lachesis_gc_evictions_total.
const labelReason = "reason"

// reason* are the values of the [labelReason] label. ttl is a
// lingering-ghost expiry deleting a MAC from mac_tenant_map;
// pressure_relief is an oldest-flow eviction from telemetry_map when it
// crosses the configured fill high watermark; ghost_residual_flow is a
// telemetry_map flow deleted because its VM's MAC was swept from
// mac_tenant_map — the residual counter that would otherwise be
// re-drained as "unknown". All are seeded at zero so the series exist
// from the first scrape.
//
// # References
//
//   - Kernel maps: docs/architecture/data-structures.md#kernel-side-bpf-maps
//   - Lingering Ghost: docs/architecture/data-structures.md#lingering-ghost
const (
	reasonTTL               = "ttl"
	reasonPressureRelief    = "pressure_relief"
	reasonGhostResidualFlow = "ghost_residual_flow"
)

// The pressure-relief bounds (fill watermarks and per-pass cap) are not
// constants here: they are operator-tunable and hot-reloadable, supplied
// via [PressureOptions] and swapped atomically by
// [PressureReliever.SetPressureParams]. Their defaults and the rationale
// for each live in config.GCConfig (the single source of truth for the
// default values).
