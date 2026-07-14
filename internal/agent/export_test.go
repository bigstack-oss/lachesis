package agent

import (
	"runtime/debug"
	"time"

	"github.com/bigstack-oss/lachesis/internal/boot"
	"github.com/bigstack-oss/lachesis/internal/config"
	"github.com/bigstack-oss/lachesis/internal/gc"
	"github.com/bigstack-oss/lachesis/internal/metadata"
)

// CloseListenerForTest closes the agent's HTTP listener out from under
// the running server, forcing Serve to return a non-ErrServerClosed
// error. It exists only to exercise the server-failure exit path in
// Run; this file is compiled only by `go test`, so the method is not
// part of the production API.
func (a *Agent) CloseListenerForTest() error {
	return a.listener.Close()
}

// RestoreFromWALForTest exposes restoreFromWAL so the external test
// package can exercise the boot-time error classes (schema-newer is
// fatal; corruption quarantines the primary and starts empty) without
// a Linux Bootstrap.
func RestoreFromWALForTest(a *Agent, cfg config.WALConfig) error {
	return restoreFromWAL(a, cfg)
}

// BuildIDFromForTest exposes buildIDFrom so the extraction of the
// agent_build identity can be pinned against a synthetic BuildInfo.
func BuildIDFromForTest(bi *debug.BuildInfo) string {
	return buildIDFrom(bi)
}

// MetadataForTest exposes the agent's userspace metadata map so a test
// can seed and ghost entries that the wired sweeper then evicts.
func MetadataForTest(a *Agent) *metadata.ShardedMetadataMap {
	return a.meta
}

// WireGhostSweeperForTest wires a lingering-ghost sweeper into the agent
// — as the Linux Bootstrap's "wire GC" step does — over the agent's own
// metadata map, a caller-supplied evictor, and a short sweep interval,
// then advances the boot sequencer through to PhaseStateRestored so the
// sweeper's Await barrier unblocks once Run starts it. Off-Linux unit
// tests use it to exercise the enabled workers() row end to end.
func WireGhostSweeperForTest(a *Agent, ev gc.MacEvictor, interval time.Duration) {
	a.ghostSweeper = gc.New(gc.Options{
		Meta:     a.meta,
		Evictor:  ev,
		Seq:      a.seq,
		Metrics:  a.mx.gc,
		Interval: interval,
	})
	for p := boot.PhaseBPFLoaded; p <= boot.PhaseStateRestored; p++ {
		_ = a.seq.Advance(p)
	}
}
