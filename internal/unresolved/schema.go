// schema.go gathers package unresolved's package-level constants: the
// slog component label and the eviction-reason label vocabulary. The
// buffer bounds (cap, TTL) are live tunables (internal/tunables), not
// constants. The behavioural types — the Buffer
// (buffer.go), the Classifier scraper seam (classifier.go), and the
// Metrics bundle (metrics.go) — live alongside their logic.

package unresolved

// component is the value of the "component" slog attribute for logs
// originating in this package.
const component = "unresolved"

// labelReason is the Prometheus label key naming why an entry left the
// buffer on lachesis_unresolved_buffer_evictions_total.
const labelReason = "reason"

// reasonLRU and reasonExpired are the two values of [labelReason]. lru
// = evicted to stay under the cap; expired = the TTL elapsed without
// resolution. Either way the entry's accumulated bytes are folded to
// "unknown" — never dropped. Both are seeded at zero.
const (
	reasonLRU     = "lru"
	reasonExpired = "expired"
)
