//go:build linux

package loadtest

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/bigstack-oss/lachesis/internal/config"
)

// writeAgentConfig writes a YAML config that points the agent's netlink
// subscriber at the host-side veth (via the attach_interfaces allowlist)
// and asks for an ephemeral listener. It marshals the agent's own
// [config.Config] (starting from [config.Defaults]) rather than a hand-
// written template, so the harness can never drift from the real config
// schema. The veth already exists when the agent boots, so the
// subscriber's ListExisting replay attaches to it. Returns the path;
// caller is responsible for os.Remove.
func writeAgentConfig(iface, httpAddr string) (string, error) {
	cfg := config.Defaults()
	cfg.HTTP.Listen = httpAddr
	cfg.BPF.PinPath = "/sys/fs/bpf/lachesis-loadtest"
	// The harness measures steady-state resource budgets, not crash
	// recovery, and the builder image has no guaranteed bpffs mount at
	// pin_path — so opt out of strict pinning and let the agent boot
	// with unpinned maps rather than refuse.
	cfg.BPF.UnsafeAllowUnpinnedMaps = true
	cfg.BPF.AttachInterfaces = []string{iface}
	cfg.Scrape.Interval = time.Second
	cfg.Logging.Level = "warn"
	cfg.Logging.Format = "text"
	cfg.WAL.Enabled = false
	// The harness runs without Neutron, so no VM MAC ever resolves to a
	// tenant: every flow lands in the UnresolvedBuffer and only reaches
	// GlobalState (and thus the lachesis_bytes_total total family) once its TTL expires and
	// it folds to "unknown". The default 60s TTL outlives the load window,
	// so the liveness read would see zero bytes. Shorten it well under the
	// window so folds happen mid-run and the observed-bytes floor is real.
	cfg.Unresolved.TTL = 2 * time.Second

	body, err := yaml.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("marshal agent config: %w", err)
	}
	dir, err := os.MkdirTemp("", "lachesis-loadtest-")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "agent.yaml")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// startAgent forks the agent binary with -config pointing at path.
// Stdout / stderr go to the loadtest's own streams so failures are
// visible in CI logs.
func startAgent(bin, cfgPath string) (*exec.Cmd, error) {
	cmd := exec.Command(bin, "-config", cfgPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// New process group so we can deliver signals to the agent only,
	// not the loadtest's own children later.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

// stopAgent sends SIGTERM, waits up to [agentTermGrace] for clean
// shutdown, then SIGKILLs if the agent is unresponsive.
func stopAgent(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(agentTermGrace):
		_ = cmd.Process.Kill()
		<-done
	}
}

// waitForAgent polls /metrics until 200 OK or the deadline elapses.
func waitForAgent(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + addr + "/metrics")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(agentReadyPoll)
	}
	return fmt.Errorf("/metrics not ready at http://%s within %s", addr, timeout)
}
