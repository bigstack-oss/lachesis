package scenariotest

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// Mangle returns the live-resource name for a DSL id under a run:
// "<prefix>-<runID>-<dslID>". Every Neutron/Nova resource `up`
// creates is named this way so a reuse-or-create lookup can find it
// again and `down` can recognise what this run owns. Projects use
// the same scheme (see [MangleProject]).
func Mangle(prefix, runID, dslID string) string {
	return fmt.Sprintf("%s-%s-%s", prefix, runID, dslID)
}

// MangleProject returns the project name for a DSL project id. It is
// deliberately run-id-free: projects are reused across runs and never
// torn down, so their names must be stable ("<prefix>-<dslID>")
// rather than per-run.
func MangleProject(prefix, dslID string) string {
	return fmt.Sprintf("%s-%s", prefix, dslID)
}

// NewRunID returns a short random run identifier (6 hex chars). It
// tags every resource a single `up` invocation creates so concurrent
// or repeated runs don't collide.
func NewRunID() (string, error) {
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("run id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
