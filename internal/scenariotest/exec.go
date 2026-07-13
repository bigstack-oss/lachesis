package scenariotest

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// VMExec runs one shell command on a VM. drive consumes it through
// this seam so flow execution is testable without live VMs; the
// production implementation is [SSHExec].
type VMExec interface {
	Run(ctx context.Context, addr, command string) (string, error)
}

// SSHExec runs commands over the system ssh binary — deliberately not
// an in-process SSH library: no new dependency, and the operator can
// reproduce any failing command verbatim from the logs.
type SSHExec struct {
	User    string
	KeyPath string
	// Timeout bounds each command. Zero means no per-command bound
	// beyond the caller's ctx.
	Timeout time.Duration
}

// NewSSHExec builds the driver's exec from the config's SSH block.
func NewSSHExec(cfg SSHConfig) *SSHExec {
	return &SSHExec{User: cfg.User, KeyPath: expandHome(cfg.KeyPath), Timeout: cfg.Timeout}
}

// sshBaseArgs are the non-negotiable transport options. The two
// +ssh-rsa entries are load-bearing on Cirros images: its dropbear
// only speaks SHA-1 ssh-rsa, which modern OpenSSH refuses by default
// ("no mutual signature supported"); enabling them is harmless on
// modern sshd. Host-key checking is off because scenario VMs are
// ephemeral and their FIPs get recycled across runs.
var sshBaseArgs = []string{
	"-o", "StrictHostKeyChecking=no",
	"-o", "UserKnownHostsFile=/dev/null",
	"-o", "PubkeyAcceptedKeyTypes=+ssh-rsa",
	"-o", "HostKeyAlgorithms=+ssh-rsa",
	"-o", "BatchMode=yes",
	"-o", "ConnectTimeout=8",
	"-o", "LogLevel=ERROR",
}

// Run executes command on addr as the configured user and returns
// the combined output.
func (s *SSHExec) Run(ctx context.Context, addr, command string) (string, error) {
	if s.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.Timeout)
		defer cancel()
	}
	args := append([]string{"-i", s.KeyPath}, sshBaseArgs...)
	args = append(args, fmt.Sprintf("%s@%s", s.User, addr), command)
	out, err := exec.CommandContext(ctx, "ssh", args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("ssh %s@%s %q: %w (output: %s)",
			s.User, addr, command, err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
