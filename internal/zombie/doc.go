// Package zombie removes orphan TC telemetry filters left by a previous
// agent run that exited without unloading them.
//
// The dangerous case is an orphan on a DIFFERENT interface than the new
// agent attaches to: nothing ever replaces that filter, so the old
// program keeps running and double-counts the same traffic. (On the
// same interface the kernel happens to re-use the slot and free the old
// program, but that is not guaranteed.)
//
// [Hunt] therefore runs early in Bootstrap, before any new program is
// loaded, so the orphan's reference is dropped first.
package zombie
