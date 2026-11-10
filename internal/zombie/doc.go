// Package zombie removes orphan TC telemetry filters left by a previous
// agent run that exited without unloading them.
//
// The dangerous case is an orphan nothing ever replaces: one on an
// interface the new agent does not attach to, or one outside the
// canonical slot (an older build's priority), which the attach's
// FilterReplace does not touch. The old program keeps running and
// double-counts the same traffic.
//
// [Hunt] therefore runs early in Bootstrap, before any new program is
// loaded, so the orphan's reference is dropped first.
//
// Hunt spares a filter the new agent will replace in place: one in the
// canonical slot on a link the agent attaches to. Deleting it would
// leave that link uncounted until the attach, seconds into boot; left
// alone, the old program keeps counting into the pinned telemetry_map
// until the attach swaps the program atomically.
//
// Boot sequence: docs/architecture/boot-and-recovery.md#boot-sequence
package zombie
