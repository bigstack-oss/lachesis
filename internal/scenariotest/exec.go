package scenariotest

import (
	"context"
	"fmt"
	"io"
	"log/slog"
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

// StdinExec is the optional [VMExec] extension for commands fed from
// the harness's own stdin — how [IngressFlowStep] streams a byte
// budget INTO a VM from outside the cluster. Implemented by [SSHExec];
// a transport without it fails that step with a clear error.
type StdinExec interface {
	RunWithStdin(ctx context.Context, addr, command string, stdin io.Reader) (string, error)
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
	// Log (nil = discard) receives one [LevelTrace] line per command.
	Log *slog.Logger
}

// NewSSHExec builds the driver's exec from the config's SSH block.
// log (nil = discard) receives one [LevelTrace] line per command.
func NewSSHExec(cfg SSHConfig, log *slog.Logger) *SSHExec {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &SSHExec{User: cfg.User, KeyPath: expandHome(cfg.KeyPath), Timeout: cfg.Timeout, Log: log}
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
	return s.run(ctx, addr, command, nil)
}

// RunWithStdin is [SSHExec.Run] with the command's stdin fed from the
// harness: the ssh client streams stdin over the session and the
// remote command sees EOF when it drains.
func (s *SSHExec) RunWithStdin(ctx context.Context, addr, command string, stdin io.Reader) (string, error) {
	return s.run(ctx, addr, command, stdin)
}

func (s *SSHExec) run(ctx context.Context, addr, command string, stdin io.Reader) (string, error) {
	if s.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.Timeout)
		defer cancel()
	}
	args := append([]string{"-i", s.KeyPath}, sshBaseArgs...)
	args = append(args, fmt.Sprintf("%s@%s", s.User, addr), command)
	start := time.Now()
	cmd := exec.CommandContext(ctx, "ssh", args...)
	cmd.Stdin = stdin
	out, err := cmd.CombinedOutput()
	dur := time.Since(start).Round(time.Millisecond)
	if err != nil {
		if s.Log != nil {
			s.Log.Log(ctx, LevelTrace, "ssh", "addr", addr, "cmd", command, "err", err, "dur", dur)
		}
		return string(out), fmt.Errorf("ssh %s@%s %q: %w (output: %s)",
			s.User, addr, command, err, strings.TrimSpace(string(out)))
	}
	if s.Log != nil {
		s.Log.Log(ctx, LevelTrace, "ssh", "addr", addr, "cmd", command, "dur", dur)
	}
	return string(out), nil
}
