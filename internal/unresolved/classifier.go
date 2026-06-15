package unresolved

import (
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/metadata"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/state"
)

// Classifier routes each drained reading by whether its VM-side MAC is
// known: known flows (including lingering ghosts, which are still in the
// metadata map until the GC sweeps them — so a dying VM's tail traffic
// never lands in the buffer) go straight to GlobalState; unknown flows
// divert into the [Buffer]. It satisfies the scraper's FlowSink seam.
//
// Ghost precedence over the UnresolvedBuffer (docs/DESIGN.md §3.3) is
// exactly this Lookup-first ordering: a ghosted MAC is a hit, so Absorb
// takes the GlobalState branch and never the buffer. The ordering is
// pinned by a test that fails if the branches are inverted.
type Classifier struct {
	state  *state.GlobalState
	meta   *metadata.ShardedMetadataMap
	buffer *Buffer
}

// NewClassifier wires the routing seam over the agent's GlobalState,
// metadata map, and unresolved buffer.
func NewClassifier(st *state.GlobalState, meta *metadata.ShardedMetadataMap, buf *Buffer) *Classifier {
	return &Classifier{state: st, meta: meta, buffer: buf}
}

// Absorb integrates one drained reading. Known VM-MAC → GlobalState
// delta math; unknown → buffer.
func (c *Classifier) Absorb(key bpf.FlowKey, raw bpf.FlowMetrics) {
	if _, known := c.meta.Lookup(metadata.VMMAC(key)); known {
		c.state.ApplyDelta(key, raw)
		return
	}
	c.buffer.Capture(key, raw)
}

// Sweep ages out buffered entries (force folds the whole buffer — the
// graceful-shutdown drain). Called once per scrape tick after the
// Absorb loop.
func (c *Classifier) Sweep(force bool) { c.buffer.Sweep(force) }
