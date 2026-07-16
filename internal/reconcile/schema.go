// schema.go collects package reconcile's package-level constants: the
// log component label and the metric label vocabulary. The reconcile
// cadence is a live tunable (internal/tunables), not a constant.
// Behavioural types live in reconcile.go; the instrument bundle in
// metrics.go.

package reconcile

// component is the slog `component` attribute for every log this
// package emits, and the subsystem label the agent registers its
// metrics under. One vocabulary so a log line and a /metrics
// registration error name the subsystem identically.
const component = "reconcile"

// labelResult is the label on lachesis_reconcile_runs_total; its values
// are the result* constants below.
const labelResult = "result"

// result* are the lachesis_reconcile_runs_total{result} label values —
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
