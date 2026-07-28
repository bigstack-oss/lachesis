package scenariotest

import (
	"context"
	"io"
)

// VMExec runs one shell command on a VM. drive consumes it through
// this seam so flow execution is testable without live VMs; the
// production implementation is internal/scenariotest/remote.SSH.
type VMExec interface {
	Run(ctx context.Context, addr, command string) (string, error)
}

// StdinExec is the optional [VMExec] extension for commands fed from
// the harness's own stdin — how IngressFlowStep streams a byte
// budget INTO a VM from outside the cluster. Implemented by
// internal/scenariotest/remote.SSH; a transport without it fails that
// step with a clear error.
type StdinExec interface {
	RunWithStdin(ctx context.Context, addr, command string, stdin io.Reader) (string, error)
}
