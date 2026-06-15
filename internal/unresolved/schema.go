// schema.go gathers package unresolved's package-level constants: the
// slog component label, the buffer's default cap and TTL, and the
// eviction-reason label vocabulary. The behavioural types — the Buffer
// (buffer.go), the Classifier scraper seam (classifier.go), and the
// Metrics bundle (metrics.go) — live alongside their logic.

package unresolved

import "time"

// component is the value of the "component" slog attribute for logs
// originating in this package.
const component = "unresolved"

// defaultCap and defaultTTL are the production buffer bounds
// (docs/DESIGN.md §3.2). The cap closes Implementation Contract #1 — a
// hard ceiling so a Kafka outage (or a no-Neutron deployment) cannot
// grow the buffer until OOM. The TTL is the late-binding window: how
// long a brand-new VM's MAC may stay unresolved before its traffic is
// charged to "unknown" (the resolution itself lands with the Kafka
// consumer in a later sprint).
const (
	defaultCap = 10_000
	defaultTTL = 60 * time.Second
)

// labelReason is the Prometheus label key naming why an entry left the
// buffer on cubecos_unresolved_buffer_evictions_total.
const labelReason = "reason"

// reasonLRU and reasonExpired are the two values of [labelReason]. lru
// = evicted to stay under the cap; expired = the TTL elapsed without
// resolution. Either way the entry's accumulated bytes are folded to
// "unknown" — never dropped. Both are seeded at zero.
const (
	reasonLRU     = "lru"
	reasonExpired = "expired"
)
