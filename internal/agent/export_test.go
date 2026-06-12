package agent

import (
	"runtime/debug"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/config"
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
