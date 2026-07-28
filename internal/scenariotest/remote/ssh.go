// Package remote runs commands on hosts the harness does not own — the
// scenario VMs it drives traffic through, and the agent hosts it
// restarts. It is the live implementation of
// [scenariotest.VMExec] / [scenariotest.StdinExec].
//
// One of scenariotest's leaf driver packages: it depends on the core
// harness for the SSH config shape and the trace log level, and on
// nothing else in the tree.
package remote

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"strings"
	"time"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
)

// SSH runs commands over the system ssh binary — deliberately not
// an in-process SSH library: no new dependency, and the operator can
// reproduce any failing command verbatim from the logs.
type SSH struct {
	User    string
	KeyPath string
	// Timeout bounds each command. Zero means no per-command bound
	// beyond the caller's ctx.
	Timeout time.Duration
	// Log (nil = discard) receives one [scenariotest.LevelTrace] line
	// per command.
	Log *slog.Logger
}

// NewSSH builds the driver's exec from the config's SSH block.
// log (nil = discard) receives one [scenariotest.LevelTrace] line per
// command.
func NewSSH(cfg scenariotest.SSHConfig, log *slog.Logger) *SSH {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &SSH{User: cfg.User, KeyPath: cfg.KeyFile(), Timeout: cfg.Timeout, Log: log}
}

// baseArgs are the non-negotiable transport options. The two
// +ssh-rsa entries are load-bearing on Cirros images: its dropbear
// only speaks SHA-1 ssh-rsa, which modern OpenSSH refuses by default
// ("no mutual signature supported"); enabling them is harmless on
// modern sshd. Host-key checking is off because scenario VMs are
// ephemeral and their FIPs get recycled across runs.
var baseArgs = []string{
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
func (s *SSH) Run(ctx context.Context, addr, command string) (string, error) {
	return s.run(ctx, addr, command, nil)
}

// RunWithStdin is [SSH.Run] with the command's stdin fed from the
// harness: the ssh client streams stdin over the session and the
// remote command sees EOF when it drains.
func (s *SSH) RunWithStdin(ctx context.Context, addr, command string, stdin io.Reader) (string, error) {
	return s.run(ctx, addr, command, stdin)
}

func (s *SSH) run(ctx context.Context, addr, command string, stdin io.Reader) (string, error) {
	if s.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.Timeout)
		defer cancel()
	}
	args := append([]string{"-i", s.KeyPath}, baseArgs...)
	args = append(args, fmt.Sprintf("%s@%s", s.User, addr), command)
	start := time.Now()
	cmd := exec.CommandContext(ctx, "ssh", args...)
	cmd.Stdin = stdin
	out, err := cmd.CombinedOutput()
	dur := time.Since(start).Round(time.Millisecond)
	if err != nil {
		if s.Log != nil {
			s.Log.Log(ctx, scenariotest.LevelTrace, "ssh", "addr", addr, "cmd", command, "err", err, "dur", dur)
		}
		return string(out), fmt.Errorf("ssh %s@%s %q: %w (output: %s)",
			s.User, addr, command, err, strings.TrimSpace(string(out)))
	}
	if s.Log != nil {
		s.Log.Log(ctx, scenariotest.LevelTrace, "ssh", "addr", addr, "cmd", command, "dur", dur)
	}
	return string(out), nil
}
