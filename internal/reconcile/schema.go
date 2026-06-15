// schema.go collects package reconcile's package-level constants: the
// log component label, the default sweep cadence, and the metric label
// vocabulary. Behavioural types live in reconcile.go; the instrument
// bundle in metrics.go.

package reconcile

import "time"

// component is the slog `component` attribute for every log this
// package emits, and the subsystem label the agent registers its
// metrics under. One vocabulary so a log line and a /metrics
// registration error name the subsystem identically.
const component = "reconcile"

// defaultInterval is the periodic full-reconcile cadence
// (docs/DESIGN.md §9 Kafka-outage safety net). A full Neutron snapshot
// is fetched and diffed against current state every interval, bounding
// metadata staleness to this window regardless of Kafka availability.
// Five minutes balances staleness against Neutron API load; [Options]
// overrides it (tests use a short interval).
const defaultInterval = 5 * time.Minute

// labelResult is the label on cubecos_reconcile_runs_total; its values
// are the result* constants below.
const labelResult = "result"

// result* are the cubecos_reconcile_runs_total{result} label values —
// one terminal outcome per reconcile pass. [NewMetrics] seeds all three
// at zero so a healthy agent reads 0 rather than "No data".
const (
	// resultOK: snapshot fetched, trie delta applied, state committed.
	resultOK = "ok"
	// resultSyncError: the Neutron snapshot fetch failed; nothing was
	// applied or committed, and metadata staleness grows until the next
	// pass succeeds.
	resultSyncError = "sync_error"
	// resultApplyError: a kernel trie write failed mid-apply; state is
	// deliberately NOT committed so the next pass re-diffs against the
	// same prior state and retries (including any skipped deletes).
	resultApplyError = "apply_error"
)
