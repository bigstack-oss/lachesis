// schema.go holds package boot's vocabulary: the slog component label
// and the Phase enum (its values and their string names). The Sequencer
// that advances through these phases lives in boot.go.

package boot

import "fmt"

const component = "boot"

// Phase identifies a named milestone in the agent's startup
// sequence. Phases advance monotonically from [PhaseInit] through
// [PhaseStateRestored]; skipping or rewinding is a programmer error.
type Phase int

const (
	// PhaseInit is the implicit starting phase: the sequencer
	// has been constructed but no milestone has been reached.
	PhaseInit Phase = iota

	// PhaseBPFLoaded marks the BPF collection as loaded and
	// validated against the Go-side max-entries constants.
	PhaseBPFLoaded

	// PhaseMetadataReady marks the Neutron cold-start as
	// complete: the LPM trie and mac_tenant_map reflect the
	// cluster's current state and the first packet through the
	// kernel hot path will classify against a populated trie.
	PhaseMetadataReady

	// PhaseAttached marks the TC clsact qdisc and ingress/egress
	// programs as installed. Packets begin classifying after
	// this phase, never before — see docs/DESIGN.md §9.
	PhaseAttached

	// PhaseStateRestored marks the WAL load as complete:
	// GlobalState's LastEbpfRaw values are seeded so the first
	// scrape computes deltas correctly. Safe to start the
	// scraper, the WAL flush goroutine, and /metrics after this.
	PhaseStateRestored
)

// String returns the snake-case phase name, suitable for log
// attributes and (eventually) Prometheus label values.
func (p Phase) String() string {
	switch p {
	case PhaseInit:
		return "init"
	case PhaseBPFLoaded:
		return "bpf_loaded"
	case PhaseMetadataReady:
		return "metadata_ready"
	case PhaseAttached:
		return "attached"
	case PhaseStateRestored:
		return "state_restored"
	default:
		return fmt.Sprintf("phase(%d)", int(p))
	}
}
